use std::error::Error;
use std::fs::File;
use std::io::{Read, Take};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use std::{fmt, io, result};

/// Convenience type for functions that return a `T` on success or a [`FetchError`] otherwise.
pub type Result<T> = result::Result<T, FetchError>;

/// An error that can occur while fetching or parsing a CCADB data source.
#[derive(Debug)]
#[non_exhaustive]
pub enum FetchError {
    /// An HTTP level error fetching the CSV data from the CCADB API.
    #[non_exhaustive]
    Api { source: Box<ureq::Error> },

    /// An error that occurred while processing CCADB CSV data.
    #[non_exhaustive]
    DataSource {
        source: Box<ccadb_csv::DataSourceError>,
    },

    /// An error writing CCADB CSV to disk.
    #[non_exhaustive]
    File { source: io::Error },

    /// An unknown report type was requested.
    #[non_exhaustive]
    UnknownReport { name: String },
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FetchError::Api { source } => {
                write!(f, "failed to fetch CCADB CSV: {source}")
            }
            FetchError::DataSource { source } => {
                write!(f, "failed to decode fetched CCADB CSV: {source}")
            }
            FetchError::File { source } => {
                write!(f, "failed to write fetched CCADB CSV: {source}")
            }
            FetchError::UnknownReport { name } => {
                write!(f, "unknown report type: {name}")
            }
        }
    }
}

impl Error for FetchError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            FetchError::Api { source } => Some(source),
            FetchError::DataSource { source } => Some(source),
            FetchError::File { source } => Some(source),
            FetchError::UnknownReport { .. } => None,
        }
    }
}

impl From<ureq::Error> for FetchError {
    fn from(source: ureq::Error) -> Self {
        let source = Box::new(source);
        FetchError::Api { source }
    }
}

impl From<ccadb_csv::DataSourceError> for FetchError {
    fn from(source: ccadb_csv::DataSourceError) -> Self {
        let source = Box::new(source);
        FetchError::DataSource { source }
    }
}

impl From<io::Error> for FetchError {
    fn from(source: io::Error) -> Self {
        FetchError::File { source }
    }
}

/// Types of CCADB CSV reports that can be fetched.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ReportType {
    /// Metadata report for all certificates (roots and intermediates) in the CCADB.
    AllCertRecords,

    /// Metadata report for Mozilla included root certificates in the CCADB (with PEM).
    MozillaIncludedRoots,
}

impl ReportType {
    #[must_use]
    pub fn url(&self) -> &str {
        match self {
            ReportType::AllCertRecords => ccadb_csv::all_cert_records::URL,
            ReportType::MozillaIncludedRoots => ccadb_csv::mozilla_included_roots::URL,
        }
    }
}

impl fmt::Display for ReportType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReportType::AllCertRecords => write!(f, "all-cert-records"),
            ReportType::MozillaIncludedRoots => write!(f, "mozilla-included-roots"),
        }
    }
}

impl TryFrom<&str> for ReportType {
    type Error = FetchError;

    fn try_from(report_type: &str) -> result::Result<Self, Self::Error> {
        match report_type {
            "all-cert-records" => Ok(ReportType::AllCertRecords),
            "mozilla-included-roots" => Ok(ReportType::MozillaIncludedRoots),
            _ => Err(FetchError::UnknownReport {
                name: report_type.to_owned(),
            }),
        }
    }
}

/// Fetch the provided report type's CSV from CCADB, writing the result to output.
///
/// # Errors
///
/// Returns an error if the output file can't be created, if the report URL can't be downloaded,
/// or if the report CSV can't be parsed.
pub fn fetch_report(report_type: &ReportType, output: impl AsRef<Path>) -> Result<u64> {
    let mut output_file = File::create(output)?;
    let mut csv_reader = read_csv_url(report_type.url())?;
    Ok(io::copy(&mut csv_reader, &mut output_file)?)
}

fn read_csv_url(url: &str) -> Result<Take<Box<dyn Read + Send + Sync>>> {
    let agent = ureq::builder()
        .tls_config(Arc::new(tls_config()))
        .timeout_read(Duration::from_secs(60))
        .user_agent(format!("ccadb-csv-fetch/{VERSION}").as_ref())
        .build();

    Ok(agent.get(url).call()?.into_reader().take(READ_LIMIT))
}

// builds a TLS ClientConfig that has only one trust anchor, the vendored
// CCADB_API_ROOT.
fn tls_config() -> rustls::ClientConfig {
    let anchor_der = rustls::pki_types::CertificateDer::from(CCADB_API_ROOT);
    let anchor = webpki::anchor_from_trusted_cert(&anchor_der)
        .unwrap()
        .to_owned();
    let root_store = rustls::RootCertStore {
        roots: vec![anchor].into_iter().collect(),
    };
    rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// `READ_LIMIT` prevents the server from exhausting our memory with a huge response. It should
/// be larger than all of the CCADB CSV file sizes.
const READ_LIMIT: u64 = 25_000_000; // 25 MB (SI).

/// Root certificate used to anchor the certificate chain offered by the CCADB API endpoints.
/// This is hardcoded to a vendored copy of the DER encoding of the root certificate to allow
/// the ccadb-utils to be used to generate a webpki-roots compatible root store without
/// depending on a platform root store, or a webpki-roots dependency.
///
/// If the Salesforce API certificate chain changes we will have to update this root certificate.
///
/// Sourced out-of-band from <https://cacerts.digicert.com/DigiCertGlobalRootCA.crt>
const CCADB_API_ROOT: &[u8] = include_bytes!("DigiCertGlobalRootCA.crt");

#[cfg(test)]
mod tests {
    use crate::{read_csv_url, ReportType};
    use std::io::{BufRead, BufReader};

    /// Quick-n-dirty test to see if the upstream data has changed format.
    /// We do this in this crate instead of ccadb-csv because we already
    /// have the machinery to download the report CSV here.
    #[test]
    fn csv_header_check() {
        // Keep in-sync with ccadb-csv/src/lib.rs.
        let expected_headers = [
            (
                ReportType::AllCertRecords,
                r#""CA Owner","Salesforce Record ID","Certificate Name","Parent Salesforce Record ID","Parent Certificate Name","Certificate Record Type","Subordinate CA Owner","Apple Status","Chrome Status","Microsoft Status","Mozilla Status","Status of Root Cert","Revocation Status","SHA-256 Fingerprint","Parent SHA-256 Fingerprint","Valid From (GMT)","Valid To (GMT)","Authority Key Identifier","Subject Key Identifier","Technically Constrained","Derived Trust Bits","Full CRL Issued By This CA","JSON Array of Partitioned CRLs","Auditor","Audits Same as Parent?","Standard Audit URL","Standard Audit Type","Standard Audit Statement Date","Standard Audit Period Start Date","Standard Audit Period End Date","NetSec Audit URL","NetSec Audit Type","NetSec Audit Statement Date","NetSec Audit Period Start Date","NetSec Audit Period End Date","TLS BR Audit URL","TLS BR Audit Type","TLS BR Audit Statement Date","TLS BR Audit Period Start Date","TLS BR Audit Period End Date","TLS EVG Audit URL","TLS EVG Audit Type","TLS EVG Audit Statement Date","TLS EVG Audit Period Start Date","TLS EVG Audit Period End Date","Code Signing Audit URL","Code Signing Audit Type","Code Signing Audit Statement Date","Code Signing Audit Period Start Date","Code Signing Audit Period End Date","S/MIME BR Audit URL","S/MIME BR Audit Type","S/MIME BR Audit Statement Date","S/MIME BR Audit Period Start Date","S/MIME BR Audit Period End Date","VMC Audit URL","VMC Audit Type","VMC Audit Statement Date","VMC Audit Period Start Date","VMC Audit Period End Date","Policy Documentation","CA Document Repository","CP Same as Parent?","Certificate Policy (CP) URL","CP Last Update Date","CPS Same as Parent?","Certificate Practice Statement (CPS) URL","CPS Last Update Date","CP/CPS Same as Parent?","Certificate Practice & Policy Statement","CP/CPS Last Updated Date","Test Website URL - Valid","Test Website URL - Expired","Test Website URL - Revoked","TLS Capable","TLS EV Capable","Code Signing Capable","S/MIME Capable","Country""#,
            ),
            (
                ReportType::MozillaIncludedRoots,
                r#""Owner","Certificate Issuer Organization","Certificate Issuer Organizational Unit","Common Name or Certificate Name","Certificate Serial Number","SHA-256 Fingerprint","Subject + SPKI SHA256","Valid From [GMT]","Valid To [GMT]","Public Key Algorithm","Signature Hash Algorithm","Trust Bits","Distrust for TLS After Date","Distrust for S/MIME After Date","EV Policy OID(s)","Approval Bug","NSS Release When First Included","Firefox Release When First Included","Test Website - Valid","Test Website - Expired","Test Website - Revoked","Mozilla Applied Constraints","Company Website","Geographic Focus","Certificate Policy (CP)","Certification Practice Statement (CPS)","Certificate Practice & Policy Statement (CP/CPS)","Standard Audit","BR Audit","EV Audit","Auditor","Standard Audit Type","Standard Audit Statement Dt","PEM Info""#,
            ),
        ];

        for (report_type, expected_header) in expected_headers {
            let report_data = read_csv_url(report_type.url()).expect("CSV URL fetch failed");

            let mut buf_reader = BufReader::new(report_data);
            let mut first_line = String::new();
            buf_reader
                .read_line(&mut first_line)
                .expect("CSV missing header line");

            assert_eq!(
                first_line.trim(),
                expected_header,
                "report type {report_type:?}:\nexpected:\n{expected_header}\ngot:\n{}\n",
                first_line.trim()
            );
        }
    }
}
