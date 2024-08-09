//! ccadb-csv is a crate offering helpers for processing CSV data from [Common CA Database] (CCADB)
//! reports. These reports offer metadata about root and intermediate certificate authorities that
//! have been disclosed to participating root programs (e.g. Mozilla, Microsoft, and Google).
//!
//! The structs in this crate are very thin wrappers around the CSV content, preserving values
//! unprocessed and in String form, like the raw CSV data. Consumers that wish to process this data
//! will likely want to create newtype wrappers that further refine the data.
//!
//! Presently there is support for reading the "All Certificate Records" report in [`all_cert_records`],
//! and the "Mozilla Included CA Certificate Report" in [`mozilla_included_roots`]. See
//! [CCADB Resources] for more information.
//!
//! To download the CSV data required for use with this crate see the companion
//! ccadb-csv-fetch crate.
//!
//! [Common CA Database]: https://www.ccadb.org/
//! [CCADB Resources]: https://www.ccadb.org/resources
#![warn(clippy::pedantic)]

use std::error::Error;
use std::io::Read;
use std::{fmt, result};

use serde::Deserialize;

/// Convenience type for functions that return a `T` on success or a [`DataSourceError`] otherwise.
pub type Result<T> = result::Result<T, DataSourceError>;

#[derive(Debug)]
#[non_exhaustive]
/// An error that can occur while parsing a CCADB data source.
pub enum DataSourceError {
    #[non_exhaustive]
    /// An error that occurred while processing CCADB CSV data.
    Csv { source: Box<csv::Error> },
}

impl fmt::Display for DataSourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DataSourceError::Csv { source } => {
                write!(f, "failed to decode CCADB CSV: {source}")
            }
        }
    }
}

impl Error for DataSourceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            DataSourceError::Csv { source } => Some(source),
        }
    }
}

impl From<csv::Error> for DataSourceError {
    fn from(source: csv::Error) -> Self {
        DataSourceError::Csv {
            source: Box::new(source),
        }
    }
}

/// Module for processing the CCADB "all certificate records version 2" CSV report.
///
/// This report contains information on both root certificates and intermediates, in a variety
/// of inclusion and trust states. It does not include the PEM of the certificates themselves,
/// but does include helpful metadata like CPS and CRL URLs.
///
/// If you are interested strictly in root certificates that are included in the Mozilla root
/// program, prefer the [`mozilla_included_roots`] module.
pub mod all_cert_records {
    use std::io::Read;

    use serde::Deserialize;

    use super::{csv_metadata_iter, Result};

    /// URL for the CCADB all certificate records version 2 CSV report.
    pub const URL: &str =
        "https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv2";

    #[allow(dead_code)]
    #[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
    /// Metadata related to an issuing certificate from the "all certificate records" CCADB CSV
    /// report.
    pub struct CertificateMetadata {
        #[serde(rename = "CA Owner")]
        pub ca_owner: String,

        #[serde(rename = "Salesforce Record ID")]
        pub salesforce_record_id: String,

        #[serde(rename = "Certificate Name")]
        pub certificate_name: String,

        #[serde(rename = "Parent Salesforce Record ID")]
        pub parent_salesforce_record_id: String,

        #[serde(rename = "Parent Certificate Name")]
        pub parent_certificate_name: String,

        #[serde(rename = "Certificate Record Type")]
        pub certificate_record_type: String,

        #[serde(rename = "Revocation Status")]
        pub revocation_status: String,

        #[serde(rename = "SHA-256 Fingerprint")]
        pub sha256_fingerprint: String,

        #[serde(rename = "Parent SHA-256 Fingerprint")]
        pub parent_sha256_fingerprint: String,

        #[serde(rename = "Audits Same as Parent?")]
        pub audits_same_as_parent: String,

        #[serde(rename = "Auditor")]
        pub auditor: String,

        #[serde(rename = "Standard Audit URL")]
        pub standard_audit_url: String,

        #[serde(rename = "Standard Audit Type")]
        pub standard_audit_type: String,

        #[serde(rename = "Standard Audit Statement Date")]
        pub standard_audit_statement_date: String,

        #[serde(rename = "Standard Audit Period Start Date")]
        pub standard_audit_period_start_date: String,

        #[serde(rename = "Standard Audit Period End Date")]
        pub standard_audit_period_end_date: String,

        #[serde(rename = "NetSec Audit URL")]
        pub netsec_audit_url: String,

        #[serde(rename = "NetSec Audit Type")]
        pub netsec_audit_type: String,

        #[serde(rename = "NetSec Audit Statement Date")]
        pub netsec_audit_statement_date: String,

        #[serde(rename = "NetSec Audit Period Start Date")]
        pub netsec_audit_period_start_date: String,

        #[serde(rename = "NetSec Audit Period End Date")]
        pub netsec_audit_period_end_date: String,

        #[serde(rename = "TLS BR Audit URL")]
        pub tls_br_audit_url: String,

        #[serde(rename = "TLS BR Audit Type")]
        pub tls_br_audit_type: String,

        #[serde(rename = "TLS BR Audit Statement Date")]
        pub tls_br_audit_statement_date: String,

        #[serde(rename = "TLS BR Audit Period Start Date")]
        pub tls_br_audit_period_start_date: String,

        #[serde(rename = "TLS BR Audit Period End Date")]
        pub tls_br_audit_period_end_date: String,

        #[serde(rename = "TLS EVG Audit URL")]
        pub tls_evg_audit_url: String,

        #[serde(rename = "TLS EVG Audit Type")]
        pub tls_evg_audit_type: String,

        #[serde(rename = "TLS EVG Audit Statement Date")]
        pub tls_evg_audit_statement_date: String,

        #[serde(rename = "TLS EVG Audit Period Start Date")]
        pub tls_evg_audit_period_start_date: String,

        #[serde(rename = "TLS EVG Audit Period End Date")]
        pub tls_evg_audit_period_end_date: String,

        #[serde(rename = "Code Signing Audit URL")]
        pub code_signing_audit_url: String,

        #[serde(rename = "Code Signing Audit Type")]
        pub code_signing_audit_type: String,

        #[serde(rename = "Code Signing Audit Statement Date")]
        pub code_signing_audit_statement_date: String,

        #[serde(rename = "Code Signing Audit Period Start Date")]
        pub code_signing_audit_period_start_date: String,

        #[serde(rename = "Code Signing Audit Period End Date")]
        pub code_signing_audit_period_end_date: String,

        #[serde(rename = "CP/CPS Same as Parent?")]
        pub cp_cps_same_as_parent: String,

        #[serde(rename = "Certificate Policy (CP) URL")]
        pub certificate_policy_url: String,

        #[serde(rename = "Certificate Practice Statement (CPS) URL")]
        pub certificate_practice_statement_cps_url: String,

        #[serde(rename = "CP/CPS Last Updated Date")]
        pub cp_cps_last_updated_date: String,

        #[serde(rename = "Test Website URL - Valid")]
        pub test_website_url_valid: String,

        #[serde(rename = "Test Website URL - Expired")]
        pub test_website_url_expired: String,

        #[serde(rename = "Test Website URL - Revoked")]
        pub test_website_url_revoked: String,

        #[serde(rename = "Technically Constrained")]
        pub technically_constrained: String,

        #[serde(rename = "Subordinate CA Owner")]
        pub subordinate_ca_owner: String,

        #[serde(rename = "Full CRL Issued By This CA")]
        pub full_crl_issued_by_this_ca: String,

        #[serde(rename = "JSON Array of Partitioned CRLs")]
        pub json_array_of_partitioned_crls: String,

        #[serde(rename = "Valid From (GMT)")]
        pub valid_from_gmt: String,

        #[serde(rename = "Valid To (GMT)")]
        pub valid_to_gmt: String,

        #[serde(rename = "Derived Trust Bits")]
        pub derived_trust_bits: String,

        #[serde(rename = "Chrome Status")]
        pub chrome_status: String,

        #[serde(rename = "Microsoft Status")]
        pub microsoft_status: String,

        #[serde(rename = "Mozilla Status")]
        pub mozilla_status: String,

        #[serde(rename = "Status of Root Cert")]
        pub status_of_root_cert: String,

        #[serde(rename = "Authority Key Identifier")]
        pub authority_key_identifier: String,

        #[serde(rename = "Subject Key Identifier")]
        pub subject_key_identifier: String,

        #[serde(rename = "Country")]
        pub country: String,

        #[serde(rename = "TLS Capable")]
        pub tls_capable: String,

        #[serde(rename = "TLS EV Capable")]
        pub tls_ev_capable: String,

        #[serde(rename = "Code Signing Capable")]
        pub code_signing_capable: String,

        #[serde(rename = "S/MIME Capable")]
        pub smime_capable: String,
    }

    /// Read the provided CSV data, producing an iterator of [`CertificateMetadata`] parse results
    /// for each of the rows.
    pub fn read_csv<'csv>(
        data: impl Read + 'csv,
    ) -> impl Iterator<Item = Result<CertificateMetadata>> {
        csv_metadata_iter(data)
    }
}

/// Module for processing the CCADB "included CA certificate PEM" CSV report.
///
/// This report contains information about root CA certificates (not intermediates) that are
/// included in the Mozilla root program. PEM content for each root is available.
///
/// If you are interested in issuers included in other programs, for purposes other than TLS,
/// or for metadata such as CPS or CRL URLs, prefer the broader [`all_cert_records`] module.
pub mod mozilla_included_roots {
    use std::io::Read;

    use serde::Deserialize;

    use super::{csv_metadata_iter, Result};

    /// URL for the CCADB Mozilla included CA certificate PEM CSV report.
    pub const URL: &str =
        "https://ccadb-public.secure.force.com/mozilla/IncludedCACertificateReportPEMCSV";

    #[allow(dead_code)]
    #[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
    /// Metadata related to an included root CA certificate from the Mozilla
    /// "included CA certificate PEM" CCADB CSV report.
    pub struct CertificateMetadata {
        #[serde(rename = "Owner")]
        pub owner: String,

        #[serde(rename = "Certificate Issuer Organization")]
        pub certificate_issuer_organization: String,

        #[serde(rename = "Certificate Issuer Organizational Unit")]
        pub certificate_issuer_organizational_unit: String,

        #[serde(rename = "Common Name or Certificate Name")]
        pub common_name_or_certificate_name: String,

        #[serde(rename = "Certificate Serial Number")]
        pub certificate_serial_number: String,

        #[serde(rename = "SHA-256 Fingerprint")]
        pub sha256_fingerprint: String,

        #[serde(rename = "Subject + SPKI SHA256")]
        pub subject_spki_sha256: String,

        #[serde(rename = "Valid From [GMT]")]
        pub valid_from_gmt: String,

        #[serde(rename = "Valid To [GMT]")]
        pub valid_to_gmt: String,

        #[serde(rename = "Public Key Algorithm")]
        pub public_key_algorithm: String,

        #[serde(rename = "Signature Hash Algorithm")]
        pub signature_hash_algorithm: String,

        #[serde(rename = "Trust Bits")]
        pub trust_bits: String,

        #[serde(rename = "Distrust for TLS After Date")]
        pub distrust_for_tls_after_date: String,

        #[serde(rename = "Distrust for S/MIME After Date")]
        pub distrust_for_smime_after_date: String,

        #[serde(rename = "EV Policy OID(s)")]
        pub ev_policy_oids: String,

        #[serde(rename = "Approval Bug")]
        pub approval_bug: String,

        #[serde(rename = "NSS Release When First Included")]
        pub nss_release_when_first_included: String,

        #[serde(rename = "Firefox Release When First Included")]
        pub firefox_release_when_first_included: String,

        #[serde(rename = "Test Website - Valid")]
        pub test_website_valid: String,

        #[serde(rename = "Test Website - Expired")]
        pub test_website_expired: String,

        #[serde(rename = "Test Website - Revoked")]
        pub test_website_revoked: String,

        #[serde(rename = "Mozilla Applied Constraints")]
        pub mozilla_applied_constraints: String,

        #[serde(rename = "Company Website")]
        pub company_website: String,

        #[serde(rename = "Geographic Focus")]
        pub geographic_focus: String,

        #[serde(rename = "Certificate Policy (CP)")]
        pub certificate_policy_cp: String,

        #[serde(rename = "Certification Practice Statement (CPS)")]
        pub certificate_practice_statement_cps: String,

        #[serde(rename = "Standard Audit")]
        pub standard_audit: String,

        #[serde(rename = "BR Audit")]
        pub br_audit: String,

        #[serde(rename = "EV Audit")]
        pub ev_audit: String,

        #[serde(rename = "Auditor")]
        pub auditor: String,

        #[serde(rename = "Standard Audit Type")]
        pub standard_audit_type: String,

        #[serde(rename = "Standard Audit Statement Dt")]
        pub standard_audit_statement_dt: String,

        #[serde(rename = "PEM Info")]
        pub pem_info: String,
    }

    /// Read the provided CSV data, producing an iterator of [`CertificateMetadata`] parse results
    /// for each of the rows.
    pub fn read_csv(data: impl Read) -> impl Iterator<Item = Result<CertificateMetadata>> {
        csv_metadata_iter(data)
    }
}

#[cfg(test)]
// simple smoke tests against test data files with 1 record each.
mod tests {
    use std::fs::File;
    use std::path::{Path, PathBuf};

    use super::all_cert_records;
    use super::mozilla_included_roots;
    use super::Result;

    #[test]
    fn test_included_roots_read_csv() {
        let data_file = File::open(test_resource_path(
            "IncludedCACertificateReportPEMCSV.test.csv",
        ))
        .unwrap();

        let records = mozilla_included_roots::read_csv(data_file)
            .collect::<Result<Vec<_>>>()
            .expect("failed to parse included certificates records CSV");
        assert!(!records.is_empty());

        let expected = mozilla_included_roots::CertificateMetadata {
            owner: "Internet Security Research Group".to_owned(),
            certificate_issuer_organization: "Internet Security Research Group".to_string(),
            certificate_issuer_organizational_unit: "".to_string(),
            common_name_or_certificate_name: "ISRG Root X1".to_string(),
            certificate_serial_number: "008210CFB0D240E3594463E0BB63828B00".to_string(),
            sha256_fingerprint: "96BCEC06264976F37460779ACF28C5A7CFE8A3C0AAE11A8FFCEE05C0BDDF08C6"
                .to_string(),
            subject_spki_sha256: "DA43F86604EB9619893C744D6AFBC37A7A57A0FBA3841E8D95488F5C798B150A"
                .to_string(),
            valid_from_gmt: "2015.06.04".to_string(),
            valid_to_gmt: "2035.06.04".to_string(),
            public_key_algorithm: "RSA 4096 bits".to_string(),
            signature_hash_algorithm: "SHA256WithRSA".to_string(),
            trust_bits: "Websites".to_string(),
            distrust_for_tls_after_date: "".to_string(),
            distrust_for_smime_after_date: "".to_string(),
            ev_policy_oids: "Not EV".to_string(),
            approval_bug: "https://bugzilla.mozilla.org/show_bug.cgi?id=1204656".to_string(),
            nss_release_when_first_included: "NSS 3.26".to_string(),
            firefox_release_when_first_included: "Firefox 50".to_string(),
            test_website_valid: "https://valid-isrgrootx1.letsencrypt.org/".to_string(),
            test_website_expired: "https://expired-isrgrootx1.letsencrypt.org/".to_string(),
            test_website_revoked: "https://revoked-isrgrootx1.letsencrypt.org/".to_string(),
            mozilla_applied_constraints: "".to_string(),
            company_website: "https://letsencrypt.org/".to_string(),
            geographic_focus: "Global".to_string(),
            certificate_policy_cp: "https://letsencrypt.org/documents/isrg-cp-v3.4/; https://letsencrypt.org/documents/isrg-cp-v3.3/; https://letsencrypt.org/documents/isrg-cp-v3.1/; https://letsencrypt.org/documents/isrg-cp-v2.7/; https://letsencrypt.org/documents/isrg-cp-v2.6/; https://letsencrypt.org/documents/isrg-cp-v2.5/; https://letsencrypt.org/documents/isrg-cp-v2.4/".to_string(),
            certificate_practice_statement_cps: "https://letsencrypt.org/documents/isrg-cps-v4.5/; https://letsencrypt.org/documents/isrg-cps-v4.4/; https://letsencrypt.org/documents/isrg-cps-v4.3/; https://letsencrypt.org/documents/isrg-cps-v4.1/; https://letsencrypt.org/documents/isrg-cps-v3.3/; https://letsencrypt.org/documents/isrg-cps-v3.1/; https://letsencrypt.org/documents/isrg-cps-v3.0/; https://letsencrypt.org/documents/isrg-cps-v2.9/; https://letsencrypt.org/documents/isrg-cps-v2.7/".to_string(),
            standard_audit: "https://www.cpacanada.ca/generichandlers/CPACHandler.ashx?attachmentid=cd221a0a-aa3c-49a9-bd8a-ad336588075a".to_string(),
            br_audit: "https://www.cpacanada.ca/generichandlers/CPACHandler.ashx?attachmentid=7f5e9f87-ecfd-4120-ae6f-e136e8637a4b".to_string(),
            ev_audit: "".to_string(),
            auditor: "Schellman & Company, LLC.".to_string(),
            standard_audit_type: "WebTrust".to_string(),
            standard_audit_statement_dt: "2022.11.08".to_string(),
            pem_info: "'-----BEGIN CERTIFICATE-----\r\nMIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw\r\nTzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh\r\ncmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4\r\nWhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu\r\nZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY\r\nMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc\r\nh77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+\r\n0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U\r\nA5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW\r\nT8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH\r\nB5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC\r\nB5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv\r\nKBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn\r\nOlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn\r\njh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw\r\nqHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI\r\nrU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV\r\nHRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq\r\nhkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL\r\nubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ\r\n3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK\r\nNFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5\r\nORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur\r\nTkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC\r\njNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc\r\noyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq\r\n4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA\r\nmRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d\r\nemyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=\r\n-----END CERTIFICATE-----'".to_string(),
        };

        assert_eq!(records.first().unwrap(), &expected)
    }

    #[test]
    fn test_all_records_read_csv() {
        let data_file = File::open(test_resource_path(
            "AllCertificateRecordsCSVFormat.test.csv",
        ))
        .unwrap();

        let records = all_cert_records::read_csv(data_file)
            .collect::<Result<Vec<_>>>()
            .unwrap();
        assert!(!records.is_empty());

        let expected = all_cert_records::CertificateMetadata {
            ca_owner: "QuoVadis".to_string(),
            salesforce_record_id: "0018Z00002vyRdNQAU".to_string(),
            certificate_name: "DigiCert QuoVadis G3 Qualified BE itsme RSA4096 SHA256 2023 CA1"
                .to_string(),
            parent_salesforce_record_id: "001o000000HshFQAAZ".to_string(),
            parent_certificate_name: "QuoVadis Root CA 1 G3".to_string(),
            certificate_record_type: "Intermediate Certificate".to_string(),
            revocation_status: "Not Revoked".to_string(),
            sha256_fingerprint: "C0EE0CCED463096DF07D27257AF79C986FF92B678F669C109FFF570F32AB433F"
                .to_string(),
            parent_sha256_fingerprint:
            "8A866FD1B276B57E578E921C65828A2BED58E9F2F288054134B7F1F4BFC9CC74".to_string(),
            audits_same_as_parent: "true".to_string(),
            auditor: "".to_string(),
            standard_audit_url: "".to_string(),
            standard_audit_type: "".to_string(),
            standard_audit_statement_date: "".to_string(),
            standard_audit_period_start_date: "".to_string(),
            standard_audit_period_end_date: "".to_string(),
            netsec_audit_url: "".to_string(),
            netsec_audit_type: "".to_string(),
            netsec_audit_statement_date: "".to_string(),
            netsec_audit_period_start_date: "".to_string(),
            netsec_audit_period_end_date: "".to_string(),
            tls_br_audit_url: "".to_string(),
            tls_br_audit_type: "".to_string(),
            tls_br_audit_statement_date: "".to_string(),
            tls_br_audit_period_start_date: "".to_string(),
            tls_br_audit_period_end_date: "".to_string(),
            tls_evg_audit_url: "".to_string(),
            tls_evg_audit_type: "".to_string(),
            tls_evg_audit_statement_date: "".to_string(),
            tls_evg_audit_period_start_date: "".to_string(),
            tls_evg_audit_period_end_date: "".to_string(),
            code_signing_audit_url: "".to_string(),
            code_signing_audit_type: "".to_string(),
            code_signing_audit_statement_date: "".to_string(),
            code_signing_audit_period_start_date: "".to_string(),
            code_signing_audit_period_end_date: "".to_string(),
            cp_cps_same_as_parent: "true".to_string(),
            certificate_policy_url: "".to_string(),
            certificate_practice_statement_cps_url: "".to_string(),
            cp_cps_last_updated_date: "".to_string(),
            test_website_url_valid: "".to_string(),
            test_website_url_expired: "".to_string(),
            test_website_url_revoked: "".to_string(),
            technically_constrained: "false".to_string(),
            mozilla_status: "Provided by CA".to_string(),
            microsoft_status: "Not Included".to_string(),
            subordinate_ca_owner: "".to_string(),
            full_crl_issued_by_this_ca: "".to_string(),
            json_array_of_partitioned_crls: "[\"http://crl.digicert.eu/DigiCertQuoVadisG3QualifiedBEitsmeRSA4096SHA2562023CA1.crl\"]".to_string(),
            valid_from_gmt: "2023.03.14".to_string(),
            valid_to_gmt: "2032.03.11".to_string(),
            chrome_status: "Not Included".to_string(),
            derived_trust_bits: "Client Authentication;Secure Email;Document Signing".to_string(),
            status_of_root_cert: "Apple: Included; Google Chrome: Included; Microsoft: Included; Mozilla: Included".to_string(),
            authority_key_identifier: "o5fW816iEOGrRZ88F2Q87gFwnMw=".to_string(),
            subject_key_identifier: "7RAkwGs8hi1E+nylj8w5J87dR7c=".to_string(),
            country: "Bermuda".to_string(),
            tls_capable: "False".to_string(),
            tls_ev_capable: "False".to_string(),
            code_signing_capable: "False".to_string(),
            smime_capable: "True".to_string(),
        };

        assert_eq!(records.first().unwrap(), &expected);
    }

    fn test_resource_path(filename: impl AsRef<Path>) -> PathBuf {
        let mut resource_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        resource_path.push("testdata/");
        resource_path.push(filename);
        resource_path
    }
}

// read the provided data as CSV with a header line, producing an iterator over the
// deserialized records.
fn csv_metadata_iter<T: for<'a> Deserialize<'a>>(
    data: impl Read,
) -> impl Iterator<Item = Result<T>> {
    csv::ReaderBuilder::new()
        .has_headers(true)
        .from_reader(data)
        .into_deserialize::<T>()
        .map(|r| r.map_err(Into::into))
}
