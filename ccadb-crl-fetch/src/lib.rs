#![warn(clippy::pedantic)]
use ccadb_csv::all_cert_records::CertificateMetadata;
use reqwest::StatusCode;
use std::error::Error;
use std::path::Path;
use std::sync::Arc;
use std::{fmt, io};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;

const MOZILLA_STATUS_INCLUDED: &str = "Included";
const MOZILLA_STATUS_PROVIDED_BY_CA: &str = "Provided by CA";
const REVOCATION_STATUS_NOT_REVOKED: &str = "Not Revoked";

type Result<T> = core::result::Result<T, ProcessingError>;

#[derive(Debug)]
#[non_exhaustive]
pub enum ProcessingError {
    #[non_exhaustive]
    DataSource { source: ccadb_csv::DataSourceError },
    #[non_exhaustive]
    BadCrlUrl { source: url::ParseError },
    #[non_exhaustive]
    BadCrlPartitionsJson { source: serde_json::Error },
    #[non_exhaustive]
    CrlDownload { url: String, source: reqwest::Error },
    #[non_exhaustive]
    BadStatus { url: String, code: StatusCode },
    #[non_exhaustive]
    Io { source: io::Error },
}

impl fmt::Display for ProcessingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProcessingError::DataSource { source } => {
                write!(f, "fetching CCADB data source failed: {source}")
            }
            ProcessingError::BadCrlUrl { source } => {
                write!(f, "parsing CRL url: {source}")
            }
            ProcessingError::BadCrlPartitionsJson { source } => {
                write!(f, "parsing CRL partitions JSON array: {source}")
            }
            ProcessingError::CrlDownload { url, source } => {
                write!(f, "downloading CRL: {url}: {source}")
            }
            ProcessingError::BadStatus { url, code } => {
                write!(f, "downloading CRL: {url}: status not 200: {code}")
            }
            ProcessingError::Io { source } => {
                write!(f, "writing CRL: {source}")
            }
        }
    }
}

impl Error for ProcessingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ProcessingError::DataSource { source } => Some(source),
            ProcessingError::BadCrlUrl { source } => Some(source),
            ProcessingError::BadCrlPartitionsJson { source } => Some(source),
            ProcessingError::CrlDownload { source, .. } => Some(source),
            ProcessingError::BadStatus { .. } => None,
            ProcessingError::Io { source } => Some(source),
        }
    }
}

impl From<ccadb_csv::DataSourceError> for ProcessingError {
    fn from(source: ccadb_csv::DataSourceError) -> Self {
        ProcessingError::DataSource { source }
    }
}

impl From<url::ParseError> for ProcessingError {
    fn from(source: url::ParseError) -> Self {
        ProcessingError::BadCrlUrl { source }
    }
}

impl From<serde_json::Error> for ProcessingError {
    fn from(source: serde_json::Error) -> Self {
        ProcessingError::BadCrlPartitionsJson { source }
    }
}

impl From<io::Error> for ProcessingError {
    fn from(source: io::Error) -> Self {
        ProcessingError::Io { source }
    }
}

/// A new type wrapper offering helpers to process [`CertificateMetadata`].
pub struct CertificateRecord(pub CertificateMetadata);

impl CertificateRecord {
    /// Returns the full CRL URL for the record, if it exists.
    ///
    /// # Errors
    ///
    /// Returns an error if the "Full CRL Issued by this CA" column of the [`CertificateMetadata`]
    /// is non-empty and contains an invalid URL.
    pub fn full_crl_url(&self) -> Result<Option<reqwest::Url>> {
        match &self.0.full_crl_issued_by_this_ca.is_empty() {
            true => Ok(None),
            false => Ok(Some(reqwest::Url::parse(
                &self.0.full_crl_issued_by_this_ca,
            )?)),
        }
    }

    /// Returns a vector of the record's CRL partition URLs. It may be empty if the record
    /// has no CRL partitions.
    ///
    /// # Errors
    ///
    /// Returns an error if the "JSON Array of Partitioned CRLs" column of the [`CertificateMetadata`]
    /// is non-empty, and contains an invalid JSON array, or a JSON array that contains invalid URL
    /// values.
    pub fn crl_partition_urls(&self) -> Result<Vec<reqwest::Url>> {
        match &self.0.json_array_of_partitioned_crls.is_empty() {
            true => Ok(Vec::default()),
            false => {
                let raw_urls: Vec<&str> =
                    serde_json::from_str(&self.0.json_array_of_partitioned_crls)?;
                raw_urls
                    .into_iter()
                    .map(|url| reqwest::Url::parse(url).map_err(Into::into))
                    .collect::<Result<Vec<reqwest::Url>>>()
            }
        }
    }

    /// Returns a vector of all of the record's CRL URLs, both full and partitioned. It may be
    /// empty if the record has no full CRL URL and no CRL partitions. It is equivalent to
    /// combining the results of [`Self::full_crl_url`] and [`Self::crl_partition_urls`].
    ///
    /// # Errors
    ///
    /// Returns an error for the same conditions that [`Self::full_crl_url`] and [`Self::crl_partition_urls`]
    /// may return errors.
    pub fn all_crl_urls(&self) -> Result<Vec<reqwest::Url>> {
        let mut results = if let Some(full_crl) = self.full_crl_url()? {
            vec![full_crl]
        } else {
            Vec::default()
        };
        results.extend(self.crl_partition_urls()?);
        Ok(results)
    }
}

/// Return an iterator providing [`CertificateRecord`] items from the provided root reports
/// that are marked as currently included in the Mozilla root program, and that are not marked
/// as revoked. This will include both root and intermediate certificate records.
///
/// # Errors
///
/// Returns an error if any of the `root_reports` results are errors (indicating an invalid row in
/// the CSV data source).
pub fn mozilla_records(
    root_reports: impl Iterator<Item = ccadb_csv::Result<CertificateMetadata>>,
) -> Result<impl Iterator<Item = CertificateRecord>> {
    let root_reports = root_reports
        .into_iter()
        .map(|r| r.map_err(Into::into))
        .collect::<Result<Vec<CertificateMetadata>>>()?;

    Ok(root_reports.into_iter().filter_map(|metadata| {
        let root = CertificateRecord(metadata);
        let moz_status = root.0.mozilla_status.as_str();
        let rev_status = root.0.revocation_status.as_str();
        let moz_included =
            moz_status == MOZILLA_STATUS_INCLUDED || moz_status == MOZILLA_STATUS_PROVIDED_BY_CA;
        let not_revoked = rev_status == REVOCATION_STATUS_NOT_REVOKED || rev_status.is_empty();
        if moz_included && not_revoked {
            Some(root)
        } else {
            None
        }
    }))
}

fn download_err(url: &reqwest::Url, err: reqwest::Error) -> ProcessingError {
    ProcessingError::CrlDownload {
        url: url.to_string(),
        source: err,
    }
}

/// Download the provided CRL `url` using the `client`, writing the DER result to `out_path`.
///
/// # Errors
///
/// Returns an error if the GET request fails, if the response isn't status code 200, if reading
/// the response body fails, or if writing the response body to disk fails.
pub async fn download_crl(
    client: Arc<reqwest::Client>,
    out_path: impl AsRef<Path>,
    url: reqwest::Url,
) -> Result<()> {
    let resp = client
        .get(url.clone())
        .send()
        .await
        .map_err(|e| download_err(&url, e))?;

    if resp.status() != StatusCode::OK {
        return Err(ProcessingError::BadStatus {
            url: url.to_string(),
            code: resp.status(),
        });
    }

    let bytes = resp.bytes().await.map_err(|e| download_err(&url, e))?;
    File::create(&out_path).await?.write_all(&bytes).await?;
    Ok(())
}
