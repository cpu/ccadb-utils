#![warn(clippy::pedantic)]
use std::error::Error;
use std::fs::File;
use std::io::{Read, Take};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use std::{fmt, io};

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

/// Convenience type for functions that return a `T` on success or a [`FetchError`] otherwise.
pub type Result<T> = core::result::Result<T, FetchError>;

#[derive(Debug)]
#[non_exhaustive]
/// An error that can occur while fetching or parsing a CCADB data source.
pub enum FetchError {
    #[non_exhaustive]
    /// A HTTP level error fetching the CSV data from the CCADB API.
    Api { source: Box<ureq::Error> },
    #[non_exhaustive]
    /// An error that occurred while processing CCADB CSV data.
    DataSource {
        source: Box<ccadb_csv::DataSourceError>,
    },
    /// An error writing CCADB CSV to disk.
    #[non_exhaustive]
    File { source: io::Error },
    /// An unknown report type was requested.
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

// Types of CCADB CSV reports that can be fetched.
pub enum ReportType {
    // Metadata report for all certificates (roots and intermediates) in the CCADB.
    AllCertRecords,
    // Metadata report for Mozilla included root certificates in the CCADB (with PEM).
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

    fn try_from(report_type: &str) -> std::result::Result<Self, Self::Error> {
        match report_type {
            "all-cert-records" => Ok(ReportType::AllCertRecords),
            "mozilla-included-roots" => Ok(ReportType::MozillaIncludedRoots),
            &_ => Err(FetchError::UnknownReport {
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

    let resp = agent.get(url).call()?;
    Ok(resp.into_reader().take(READ_LIMIT))
}

// builds a TLS ClientConfig that has only root trusted root certificate, the vendored
// CCADB_API_ROOT.
fn tls_config() -> rustls::ClientConfig {
    let mut root_store = rustls::RootCertStore::empty();
    let anchor = webpki::TrustAnchor::try_from_cert_der(CCADB_API_ROOT).unwrap();
    let anchors = vec![
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            anchor.subject,
            anchor.spki,
            anchor.name_constraints,
        ),
    ];
    root_store.add_server_trust_anchors(anchors.into_iter());

    rustls::ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth()
}
