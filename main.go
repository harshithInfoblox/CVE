package main

import (
	"bytes"
	"compress/gzip"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	_ "github.com/lib/pq"
	"github.com/robfig/cron/v3"
)

const (
	dbUser             = "hp"
	dbName             = "newcvedb2"
	dbSSLMode          = "disable"
	cveBaseURL         = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%d.json.gz"
	cveModifiedURL     = "https://nvd.nist.gov/feeds/json/cve/1.1-modified.json.gz"
	cveModifiedMetaURL = "https://nvd.nist.gov/feeds/json/cve/1.1-modified.json.gz.meta"
	initialDownload    = true
	lastModifiedFile   = "last_modified.txt" 
)

type CVEItem struct {
	CVE struct {
		CVEDataMeta struct {
			ID string `json:"ID"`
		} `json:"CVE_data_meta"`
		Description struct {
			DescriptionData []struct {
				Value string `json:"value"`
			} `json:"description_data"`
		} `json:"description"`
	} `json:"cve"`
	Configurations struct {
		Nodes []struct {
			CPEMatch []struct {
				CPE23URI     string `json:"cpe23Uri"`
				Vulnerable   bool   `json:"vulnerable"`
				VersionStart string `json:"versionStartIncluding"`
				VersionEnd   string `json:"versionEndExcluding"`
			} `json:"cpe_match"`
			Children []struct {
				CPEMatch []struct {
					CPE23URI     string `json:"cpe23Uri"`
					Vulnerable   bool   `json:"vulnerable"`
					VersionStart string `json:"versionStartIncluding"`
					VersionEnd   string `json:"versionEndExcluding"`
				} `json:"cpe_match"`
			} `json:"children"`
		} `json:"nodes"`
	} `json:"configurations"`
	Impact struct {
		BaseMetricV3 struct {
			CVSSV3 struct {
				Version      string  `json:"version"`
				VectorString string  `json:"vectorString"`
				BaseScore    float64 `json:"baseScore"`
				BaseSeverity string  `json:"baseSeverity"`
			} `json:"cvssV3"`
		} `json:"baseMetricV3"`
	} `json:"impact"`
	PublishedDate    string `json:"publishedDate"`
	LastModifiedDate string `json:"lastModifiedDate"`
}

type CVEResponse struct {
	CVEItems []CVEItem `json:"CVE_Items"`
}

func main() {
	logFile, err := os.OpenFile("cve_data.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("failed to open log file: %v", err)
	}
	defer logFile.Close()
	log.SetOutput(logFile)

	db, err := sql.Open("postgres", fmt.Sprintf("user=%s dbname=%s sslmode=%s", dbUser, dbName, dbSSLMode))
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	if initialDownload {
		for year := 2023; year <= 2025; year++ {
			log.Printf("Processing year: %d\n", year)
			err := downloadAndInsertData(fmt.Sprintf(cveBaseURL, year), db)
			if err != nil {
				log.Printf("Error processing year %d: %v\n", year, err)
			}
		}
		// Create or update last_modified.txt after initial download
		modifiedDate := time.Now().Format(time.RFC3339)
		if err := saveLastModified(modifiedDate); err != nil {
			log.Printf("Failed to save initial last modified date: %v", err)
		}
	}

	c := cron.New()
	c.AddFunc("*/2 * * * *", func() {
		log.Println("Checking for updates...")
		err := checkAndUpdateData(cveModifiedURL, cveModifiedMetaURL, db)
		if err != nil {
			log.Printf("Error checking for updates: %v\n", err)
		}
	})
	c.Start()

	select {}
}

func downloadAndInsertData(url string, db *sql.DB) error {
	response, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download data: %v", err)
	}
	defer response.Body.Close()

	tempFile, err := os.CreateTemp("", "cve_data_*.json.gz")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())

	if _, err = io.Copy(tempFile, response.Body); err != nil {
		return fmt.Errorf("failed to copy data to temp file: %v", err)
	}

	log.Printf("Data downloaded to: %s\n", tempFile.Name())

	tempFile.Seek(0, io.SeekStart)

	var buf bytes.Buffer
	gzipReader, err := gzip.NewReader(tempFile)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %v", err)
	}
	defer gzipReader.Close()

	if _, err = io.Copy(&buf, gzipReader); err != nil {
		return fmt.Errorf("failed to copy data from gzip reader: %v", err)
	}

	var cveData CVEResponse
	decoder := json.NewDecoder(bytes.NewReader(buf.Bytes()))
	if err = decoder.Decode(&cveData); err != nil {
		return fmt.Errorf("failed to decode JSON data: %v", err)
	}

	log.Printf("Decoded CVE Data: %+v\n", cveData)

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %v", err)
	}
	defer tx.Rollback()

	for i, item := range cveData.CVEItems {
		cveID := item.CVE.CVEDataMeta.ID
		description := ""
		if len(item.CVE.Description.DescriptionData) > 0 {
			description = item.CVE.Description.DescriptionData[0].Value
		}
		publishedDate := item.PublishedDate
		lastModifiedDate := item.LastModifiedDate
		log.Printf("============================starting new cve=======================================================================")
		log.Printf("Inserting CVE ID %d: %s, Description: %s\n", i+1, cveID, description)

		_, err := tx.Exec(`INSERT INTO cve_data1 (cve_id, description, published_date, last_modified_date)
						   VALUES ($1, $2, $3, $4)
						   ON CONFLICT (cve_id) DO UPDATE
						   SET description = EXCLUDED.description,
							   published_date = EXCLUDED.published_date,
							   last_modified_date = EXCLUDED.last_modified_date;`,
			cveID, description, publishedDate, lastModifiedDate)
		if err != nil {
			log.Printf("Error inserting data for CVE ID %s: %v\n", cveID, err)
			return err
		}
		log.Printf("Nodes length = %d", len(item.Configurations.Nodes))

		if len(item.Configurations.Nodes) > 0 {
			for configIndex, node := range item.Configurations.Nodes {
				configNumber := configIndex + 1 // Configuration starts from 1

				// Process CPE URIs in the CPEMatch array of the node
				for k, cpe := range node.CPEMatch {
					cpeURI := normalizeCPEURI(cpe.CPE23URI)
					versionStart := normalizeVersion(cpe.VersionStart)
					versionEnd := normalizeVersion(cpe.VersionEnd)
					log.Printf("Inserting cpeURI = %s in cpe_data table with configNumber = %d", cpeURI, configNumber)

					_, err := tx.Exec(`INSERT INTO cpe_data (cve_id, cpe_uri, vulnerable, version_start, version_end, config)
									   VALUES ($1, $2, $3, $4, $5, $6)
									   ON CONFLICT (cve_id, cpe_uri) DO UPDATE
									   SET vulnerable = EXCLUDED.vulnerable,
										   version_start = EXCLUDED.version_start,
										   version_end = EXCLUDED.version_end,
										   config = EXCLUDED.config;`,
						cveID, cpeURI, cpe.Vulnerable, versionStart, versionEnd, configNumber)
					if err != nil {
						log.Printf("Error inserting CPE data for CVE ID %s, Config %d, CPE %d: %v\n", cveID, configNumber, k+1, err)
						return err
					}
				}

				// Process CPE URIs in the Children array of the node
				for _, child := range node.Children {
					for l, cpe := range child.CPEMatch {
						cpeURI := normalizeCPEURI(cpe.CPE23URI)
						versionStart := normalizeVersion(cpe.VersionStart)
						versionEnd := normalizeVersion(cpe.VersionEnd)
						log.Printf("Inserting cpeURI = %s from child node in cpe_data table with configNumber = %d", cpeURI, configNumber)

						_, err := tx.Exec(`INSERT INTO cpe_data (cve_id, cpe_uri, vulnerable, version_start, version_end, config)
										   VALUES ($1, $2, $3, $4, $5, $6)
										   ON CONFLICT (cve_id, cpe_uri) DO UPDATE
										   SET vulnerable = EXCLUDED.vulnerable,
											   version_start = EXCLUDED.version_start,
											   version_end = EXCLUDED.version_end,
											   config = EXCLUDED.config;`,
							cveID, cpeURI, cpe.Vulnerable, versionStart, versionEnd, configNumber)
						if err != nil {
							log.Printf("Error inserting CPE data for CVE ID %s, Config %d, Child Node, CPE %d: %v\n", cveID, configNumber, l+1, err)
							return err
						}
					}
				}
			}

		}

		if item.Impact.BaseMetricV3.CVSSV3.Version != "" {
			_, err := tx.Exec(`INSERT INTO impact_data (cve_id, cvss_version, cvss_vector_string, cvss_base_score, cvss_base_severity)
							   VALUES ($1, $2, $3, $4, $5)
							   ON CONFLICT (cve_id) DO UPDATE
							   SET cvss_version = EXCLUDED.cvss_version,
								   cvss_vector_string = EXCLUDED.cvss_vector_string,
								   cvss_base_score = EXCLUDED.cvss_base_score,
								   cvss_base_severity = EXCLUDED.cvss_base_severity;`,
				cveID,
				item.Impact.BaseMetricV3.CVSSV3.Version,
				item.Impact.BaseMetricV3.CVSSV3.VectorString,
				item.Impact.BaseMetricV3.CVSSV3.BaseScore,
				item.Impact.BaseMetricV3.CVSSV3.BaseSeverity)
			if err != nil {
				log.Printf("Error inserting impact data for CVE ID %s: %v\n", cveID, err)
				return err
			}
		}
		log.Printf("========================================end===========================================================================")
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("transaction commit error: %v", err)
	}

	return nil
}

func normalizeCPEURI(cpeURI string) string {
	parts := strings.Split(cpeURI, ":")
	if len(parts) >= 5 {
		osAndVersion := parts[4]
		osVersionParts := strings.Split(osAndVersion, "_")
		if len(osVersionParts) == 2 {
			parts[4] = osVersionParts[0]
			parts = append(parts[:5], append([]string{osVersionParts[1]}, parts[5:]...)...)
		}
	}
	return strings.Join(parts, ":")
}

func normalizeVersion(version string) string {
	re := regexp.MustCompile(`^\d+(\.\d+)*`)
	return re.FindString(version)
}

func checkAndUpdateData(url, metaURL string, db *sql.DB) error {
	resp, err := http.Get(metaURL)
	if err != nil {
		return fmt.Errorf("failed to fetch metadata: %v", err)
	}
	defer resp.Body.Close()

	metaBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read metadata: %v", err)
	}

	metaContent := string(metaBytes)
	modifiedDate := parseLastModified(metaContent)

	lastModified, err := readLastModified()
	if err != nil {
		log.Printf("No last modified date found, assuming full update: %v\n", err)
	}

	if modifiedDate != lastModified {
		log.Println("New data available, downloading and updating...")
		if err := downloadAndInsertData(url, db); err != nil {
			return fmt.Errorf("failed to update data: %v", err)
		}

		if err := saveLastModified(modifiedDate); err != nil {
			return fmt.Errorf("failed to save last modified date: %v", err)
		}
	} else {
		log.Println("No new data available.")
	}

	return nil
}

func parseLastModified(metaContent string) string {
	re := regexp.MustCompile(`lastModifiedDate:(.*)`)
	matches := re.FindStringSubmatch(metaContent)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

func readLastModified() (string, error) {
	data, err := os.ReadFile(lastModifiedFile)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func saveLastModified(lastModified string) error {
	return os.WriteFile(lastModifiedFile, []byte(lastModified), 0644)
}
