use ccadb_csv::mozilla_included_roots::CertificateMetadata;
use chrono::NaiveDate;
use num_bigint::BigUint;
use std::collections::HashSet;
use std::io::BufReader;

use super::Result;
use crate::error::{InvalidSerialError, ProcessingError};

/// RootCertificate is a new type wrapper around CertificateMetadata that allows
/// viewing the metadata in more useful representations.
pub struct RootCertificate(pub CertificateMetadata);

impl RootCertificate {
    #[must_use]
    /// Returns the PEM metadata for the root certificate.
    pub fn pem(&self) -> &str {
        self.0.pem_info.as_str().trim_matches('\'')
    }

    /// Returns the DER encoding of the root certificate contained in the metadata PEM, or
    /// an error if the PEM can not be decoded, or there is no root certificate in the PEM content.
    pub fn der(&self) -> Result<Vec<u8>> {
        let mut pem_reader = BufReader::new(self.pem().as_bytes());
        Ok(rustls_pemfile::certs(&mut pem_reader)
            .map_err(|e| ProcessingError::PemIo {
                sha256_fingerprint: self.0.sha256_fingerprint.clone(),
                name: self.0.common_name_or_certificate_name.clone(),
                source: e,
            })?
            .first()
            .ok_or(ProcessingError::NoCertInPem {
                sha256_fingerprint: self.0.sha256_fingerprint.clone(),
                name: self.0.common_name_or_certificate_name.clone(),
                pem: self.pem().to_string(),
            })?
            .clone())
    }

    /// Returns the metadata serial number for the root certificate, or an error if the certificate
    /// serial number from the metadata can not be parsed as a base 16 unsigned big integer.
    pub fn serial(&self) -> Result<BigUint> {
        BigUint::parse_bytes(self.0.certificate_serial_number.as_bytes(), 16).ok_or(
            ProcessingError::InvalidSerial {
                source: InvalidSerialError::InvalidBigNum {
                    serial: self.0.certificate_serial_number.clone(),
                },
            },
        )
    }

    /// Returns the colon separated string with the metadata SHA256 fingerprint for the root
    /// certificate, or an error if the sha256 fingerprint from the metadata can't be decoded.
    pub fn sha256_fp(&self) -> Result<String> {
        Ok(x509_parser::utils::format_serial(
            &hex::decode(&self.0.sha256_fingerprint).map_err(|e| {
                ProcessingError::InvalidSerial {
                    source: InvalidSerialError::InvalidHex {
                        serial: self.0.certificate_serial_number.clone(),
                        source: e,
                    },
                }
            })?,
        ))
    }

    /// Returns the set of trust bits expressed for this root certificate, or an error
    /// if the trust bits could not be parsed.
    pub fn trust_bits(&self) -> Result<HashSet<TrustBits>> {
        self.0
            .trust_bits
            .split(';')
            .map(TrustBits::try_from)
            .collect()
    }

    /// Return the NaiveDate after which this certificate should not be trusted for TLS (if any).
    /// Returns an error if there is a distrust for TLS after date value that can not be parsed.
    pub fn tls_distrust_after(&self) -> Result<Option<NaiveDate>> {
        match &self.0.distrust_for_tls_after_date {
            // No distrust for TLS after date
            date if date.is_empty() => Ok(None),
            date => Ok(Some(NaiveDate::parse_from_str(date, "%Y.%m.%d").map_err(
                |e| ProcessingError::InvalidDate {
                    date: date.to_string(),
                    source: e,
                },
            )?)),
        }
    }

    /// Returns true iff the RootCertificate has valid TrustBits that include TrustBits::Websites,
    /// and the RootCertificate has no distrust for TLS after date, or has a valid distrust
    /// for TLS after date that is in the future compared to `now`. In all other cases this function
    /// returns false.
    pub fn trusted_for_tls(&self, now: &NaiveDate) -> bool {
        // If we can't parse the trust bits, assume there are none. E.g. fail closed to
        // not including the root since an empty set of trust bits won't contain TrustBits::Website.
        let has_tls_trust_bit = self
            .trust_bits()
            .unwrap_or(HashSet::default())
            .contains(&TrustBits::Websites);

        // If we can't parse the tls_distrust_after date, assume it's epoch. E.g. fail closed
        // to not including the root since now will be after epoch.
        let tls_distrust_after = self
            .tls_distrust_after()
            .unwrap_or(Some(NaiveDate::default()));

        match (has_tls_trust_bit, tls_distrust_after) {
            // No website trust bit - not trusted for tls.
            (false, _) => false,
            // Has website trust bit, no distrust after - trusted for tls.
            (true, None) => true,
            // Trust bit, populated distrust after - need to check date to decide.
            (true, Some(tls_distrust_after)) => {
                match now.cmp(&tls_distrust_after).is_ge() {
                    // We're past the distrust date - skip.
                    true => false,
                    // We haven't yet reached the distrust date - include.
                    false => true,
                }
            }
        }
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Clone, Copy)]
#[non_exhaustive]
/// TrustBits describe the possible Mozilla root certificate trust bits.
pub enum TrustBits {
    /// certificate is trusted for Websites (e.g. TLS).
    Websites,
    /// certificate is trusted for Email (e.g. S/MIME).
    Email,
}

const MOZILLA_TRUST_BIT_WEBSITES: &str = "Websites";
const MOZILLA_TRUST_BIT_EMAIL: &str = "Email";

impl TryFrom<&str> for TrustBits {
    type Error = ProcessingError;

    /// Try to read the string as a Mozilla trust bit, returning an error if the
    /// string does not match a known trust bit label.
    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        match value {
            MOZILLA_TRUST_BIT_WEBSITES => Ok(TrustBits::Websites),
            MOZILLA_TRUST_BIT_EMAIL => Ok(TrustBits::Email),
            bit => Err(ProcessingError::UnknownTrustBit {
                bit: bit.to_owned(),
            }),
        }
    }
}
