CREATE TABLE cpe_data (
    cve_id VARCHAR(255) PRIMARY KEY,
    cpe_uri TEXT,
    vulnerable BOOLEAN,
    version_start VARCHAR(255),
    version_end VARCHAR(255),
    config INTEGER
);

CREATE TABLE cve_data1 (
    cve_id VARCHAR(255) PRIMARY KEY,
    description TEXT,
    published_date DATE,
    last_modified_date DATE
);

CREATE TABLE impact_data (
    cve_id VARCHAR(255) PRIMARY KEY,
    cvss_version VARCHAR(255),
    cvss_vector_string VARCHAR(255),
    cvss_base_score NUMERIC,
    cvss_base_severity VARCHAR(255)
);