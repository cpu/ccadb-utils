mod error;
mod root;
mod template;

use std::collections::BTreeSet;
use std::io::Read;

use crate::error::ProcessingError;
use crate::root::RootCertificate;
use crate::template::WebpkiRoot;
use askama::Template;
use ccadb_csv::mozilla_included_roots::{self, CertificateMetadata};
use ccadb_csv::DataSourceError;
use chrono::Utc;

/// Render a Rust file containing webpki roots for all of the root certificates from the data_file
/// that are currently included in the Mozilla root program, have a Website trust bit, and do
/// not have a Distrust for TLS Date that has already passed.
///
/// If no metadata in the data_file is invalid, a String with the rendered content is returned.
/// Otherwise, a ProcessingError will be returned describing the issue encountered.
pub fn render_webpki_roots(data_file: impl Read) -> Result<String> {
    // An iterator pipeline to:
    // 1. Read the data_file CSV as a Vec of CertificateMetadata. Returning a ProcessingError
    //    immediately if any rows fail to parse.
    // 2. Wrapping the CertificateMetadata in the RootCertificate newtype so we can use its
    //    helpful methods for filtering.
    // 3. Filter out any roots that do not have the Website trust bit, or that have a distrust
    //    for TLS date that's in the past.
    // 4. Convert the trusted TLS roots into the WebpkiRoot we'll render in template form,
    //    returning a ProcessingError immediately if any trusted TLS root is missing information
    //    we need to template it.
    // 5. Collecting the set of WebpkiRoots into a BTreeSet, ordered by the root's SHA 256
    //    fingerprint to give predictable order.
    let trusted_roots = mozilla_included_roots::read_csv(data_file)
        .collect::<std::result::Result<Vec<CertificateMetadata>, DataSourceError>>()
        .map_err(ProcessingError::from)?
        .into_iter()
        .map(RootCertificate)
        .filter(|root| root.trusted_for_tls(&Utc::now().naive_utc().date()))
        .map(WebpkiRoot::try_from)
        .collect::<Result<BTreeSet<WebpkiRoot>>>()?;

    Ok(template::WebpkiRootsTemplate { trusted_roots }.render()?)
}

// type alias for convenience.
type Result<T> = core::result::Result<T, ProcessingError>;
