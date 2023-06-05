use ccadb_csv::DataSourceError;
use std::error::Error;
use std::{fmt, io};

// x509_parser's error type signature is too verbose to repeat often.
type X509ParserError = x509_parser::nom::Err<x509_parser::prelude::X509Error>;

#[derive(Debug)]
#[non_exhaustive]
/// An error that may occur when processing CSV metadata to render webpki trusted roots.
pub enum ProcessingError {
    #[non_exhaustive]
    /// Certificate metadata PEM doesn't contain a root certificate.
    NoCertInPem {
        sha256_fingerprint: String,
        name: String,
        pem: String,
    },
    #[non_exhaustive]
    /// Certificate metadata PEM content could not be read for processing.
    PemIo {
        sha256_fingerprint: String,
        name: String,
        source: io::Error,
    },
    #[non_exhaustive]
    /// Certificate metadata could not be processed.
    DataSource { source: DataSourceError },
    #[non_exhaustive]
    /// Certificate metadata contained a trust bit that was not recognized.
    UnknownTrustBit { bit: String },
    #[non_exhaustive]
    /// Certificate metadata contained a distrust for TLS after date that could not be parsed.
    InvalidDate {
        date: String,
        source: chrono::ParseError,
    },
    #[non_exhaustive]
    /// Certificate metadata contained a serial number that could not be recognized.
    InvalidSerial { source: InvalidSerialError },
    #[non_exhaustive]
    /// Certificate metadata contained a SHA256 fingerprint that could not be recognized.
    InvalidFP { fp: String },
    #[non_exhaustive]
    /// Certificate metadata PEM contained a root certificate that could not be parsed.
    InvalidRoot { source: CertParseError },
    #[non_exhaustive]
    /// Rendering the webpki trusted root template failed.
    Template { source: askama::Error },
}

impl fmt::Display for ProcessingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProcessingError::DataSource { source } => {
                write!(f, "loading CCADB CSV failed: {source}")
            }
            ProcessingError::PemIo {
                name,
                sha256_fingerprint,
                ..
            } => {
                write!(
                    f,
                    "IO error for CA: {name:?} SHA256: {sha256_fingerprint:?}"
                )
            }
            ProcessingError::NoCertInPem {
                name,
                sha256_fingerprint,
                ..
            } => {
                write!(
                    f,
                    "no certificate in PEM for CA: {name:?} SHA256: {sha256_fingerprint:?}"
                )
            }
            ProcessingError::UnknownTrustBit { bit } => {
                write!(f, "unknown trust bit: {bit:?}",)
            }
            ProcessingError::InvalidSerial { source } => {
                write!(f, "invalid serial: {source}")
            }
            ProcessingError::InvalidFP { fp } => {
                write!(f, "invalid SHA256 fingerprint: {fp:?}")
            }
            ProcessingError::InvalidDate { date, source } => {
                write!(f, "invalid date: {date:?}: {source}")
            }
            ProcessingError::InvalidRoot { source } => {
                write!(f, "invalid root: {source}")
            }
            ProcessingError::Template { source } => {
                write!(f, "rendering template: {source}")
            }
        }
    }
}

impl From<DataSourceError> for ProcessingError {
    fn from(source: DataSourceError) -> Self {
        ProcessingError::DataSource { source }
    }
}

impl From<CertParseError> for ProcessingError {
    fn from(source: CertParseError) -> Self {
        ProcessingError::InvalidRoot { source }
    }
}

impl From<webpki::Error> for ProcessingError {
    fn from(source: webpki::Error) -> Self {
        ProcessingError::InvalidRoot {
            source: source.into(),
        }
    }
}

impl From<X509ParserError> for ProcessingError {
    fn from(source: X509ParserError) -> Self {
        ProcessingError::InvalidRoot {
            source: source.into(),
        }
    }
}

impl From<askama::Error> for ProcessingError {
    fn from(source: askama::Error) -> Self {
        ProcessingError::Template { source }
    }
}

impl Error for ProcessingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ProcessingError::PemIo { source, .. } => Some(source),
            ProcessingError::DataSource { source } => Some(source),
            ProcessingError::InvalidSerial {
                source: InvalidSerialError::InvalidHex { source, .. },
            } => Some(source),
            ProcessingError::InvalidRoot { source } => match source {
                CertParseError::Webpki { source } => Some(source),
                CertParseError::X509Parser { source } => Some(source),
            },
            ProcessingError::Template { source } => Some(source),
            _ => None,
        }
    }
}

#[derive(Debug)]
#[non_exhaustive]
/// An error that can occur when processing certificate metadata serial numbers.
pub enum InvalidSerialError {
    #[non_exhaustive]
    /// Certificate metadata contained a serial number that was not a valid big integer.
    InvalidBigNum { serial: String },
    #[non_exhaustive]
    /// Certificate metadata contained a hex serial number that could not be decoded from hex.
    InvalidHex {
        serial: String,
        source: hex::FromHexError,
    },
}

impl fmt::Display for InvalidSerialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvalidSerialError::InvalidBigNum { serial } => {
                write!(f, "invalid serial number: {serial:?}")
            }
            InvalidSerialError::InvalidHex { serial, source } => {
                write!(
                    f,
                    "invalid serial number hex: {serial:?}: decode error: {source}"
                )
            }
        }
    }
}

#[derive(Debug)]
#[non_exhaustive]
/// An error that can occur when parsing a root certificate from the CCADB report PEM.
pub enum CertParseError {
    #[non_exhaustive]
    /// An error that occurred because the CCAD report PEM wasn't a valid webpki trust anchor.
    Webpki { source: webpki::Error },
    #[non_exhaustive]
    /// An error that occurred because the CCAD report PEM couldn't be parsed by x509_parser.
    X509Parser { source: X509ParserError },
}

impl From<webpki::Error> for CertParseError {
    fn from(source: webpki::Error) -> Self {
        CertParseError::Webpki { source }
    }
}

impl From<X509ParserError> for CertParseError {
    fn from(source: X509ParserError) -> Self {
        CertParseError::X509Parser { source }
    }
}

impl fmt::Display for CertParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CertParseError::Webpki { source } => {
                write!(f, "invalid webpki trust anchor: {source}")
            }
            CertParseError::X509Parser { source } => {
                write!(f, "invalid x509_parser certificate: {source}")
            }
        }
    }
}
