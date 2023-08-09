use ccadb_csv::mozilla_included_roots::CertificateMetadata;
use chrono::NaiveDate;
use num_bigint::BigUint;
use std::collections::HashSet;
use std::io::BufReader;
use yasna::Tag;

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
            &hex::decode(&self.0.sha256_fingerprint).map_err(|_| ProcessingError::InvalidFP {
                fp: self.0.sha256_fingerprint.to_string(),
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
            .unwrap_or_default()
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

    pub fn mozilla_applied_constraints(&self) -> Option<Vec<u8>> {
        if self.0.mozilla_applied_constraints.is_empty() {
            return None;
        }

        // NOTE: To date there's only one CA with applied constraints, and it has only one constraint
        // imposed. It's not clear how multiple constraints would be expressed. This method takes a
        // best guess but will likely need to be revisited in the future.
        let included_subtrees = self.0.mozilla_applied_constraints.split(',');
        let der = yasna::construct_der(|writer| {
            // permittedSubtrees [0]
            writer.write_tagged_implicit(Tag::context(0), |writer| {
                // GeneralSubtrees
                writer.write_sequence(|writer| {
                    for included_subtree in included_subtrees {
                        // base GeneralName
                        writer.next().write_sequence(|writer| {
                            writer
                                .next()
                                // DnsName
                                .write_tagged_implicit(Tag::context(2), |writer| {
                                    writer
                                        .write_ia5_string(included_subtree.trim_start_matches('*'))
                                })
                        })
                        // minimum [0] (absent, 0 default)
                        // maximum [1] (must be omitted).
                    }
                })
            })
        });

        Some(der)
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

#[cfg(test)]
pub(crate) mod tests {
    use crate::error::ProcessingError;
    use crate::root::RootCertificate;
    use ccadb_csv::mozilla_included_roots::CertificateMetadata;

    pub(crate) fn test_metadata() -> CertificateMetadata {
        CertificateMetadata {
            owner: "Crazy CPU's Castle of Cheap Certificates".to_string(),
            certificate_issuer_organization: "CPU Inc LLC".to_string(),
            certificate_issuer_organizational_unit: "Crazy Certificates".to_string(),
            common_name_or_certificate_name: "Trustworthy Root CA".to_string(),
            certificate_serial_number: "C0FFEE".to_string(),
            sha256_fingerprint: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                .to_string(),
            subject_spki_sha256: "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"
                .to_string(),
            valid_from_gmt: "2023.06.05".to_string(),
            valid_to_gmt: "2033.10.06".to_string(),
            public_key_algorithm: "RSA 9999 bits".to_string(),
            signature_hash_algorithm: "SHA420WithRSA".to_string(),
            trust_bits: "Websites;Email".to_string(),
            distrust_for_tls_after_date: "".to_string(),
            distrust_for_smime_after_date: "".to_string(),
            ev_policy_oids: "1.2.3.4.5.6".to_string(),
            approval_bug: "https://bugzilla.mozilla.org/show_bug.cgi?id=9999999".to_string(),
            nss_release_when_first_included: "NSS 99.99.99".to_string(),
            firefox_release_when_first_included: "Firefox 999".to_string(),
            test_website_valid: "https://example.com/fake_valid".to_string(),
            test_website_expired: "https://example.com/fake_expired".to_string(),
            test_website_revoked: "https://example.com/fake_revoked".to_string(),
            mozilla_applied_constraints: "*.tr".to_string(),
            company_website: "https://binaryparadox.net".to_string(),
            geographic_focus: "Canada".to_string(),
            certificate_policy_cp: "https://example.com/pretend_cp".to_string(),
            certificate_practice_statement_cps: "https://example.com/pretend_cps".to_string(),
            standard_audit: "Super Secure 2000".to_string(),
            br_audit: "https://example.com/fake_br_audit".to_string(),
            ev_audit: "https://example.com/fake_ev_audit".to_string(),
            auditor: "Trustworthy Tom".to_string(),
            standard_audit_type: "Super Secure 3000".to_string(),
            standard_audit_statement_dt: "2023.06.01".to_string(),
            pem_info: "'".to_string() + include_str!("../tests/example.cert.pem") + "'",
        }
    }

    #[test]
    fn test_pem() {
        // the pem() method should strip the leading/trailing single quote character.
        let bare_pem = include_str!("../tests/example.cert.pem");
        let root = RootCertificate(test_metadata());
        let pem_result = root.pem();
        assert!(!pem_result.contains("\'"));
        assert_eq!(pem_result, bare_pem);
    }

    #[test]
    fn test_der() {
        let eg_metadata = test_metadata();
        let empty_pem_root = RootCertificate(CertificateMetadata {
            pem_info: "".to_string(),
            ..eg_metadata
        });
        assert!(matches!(
            empty_pem_root.der(),
            Err(ProcessingError::NoCertInPem { .. })
        ));

        let eg_metadata = test_metadata();
        let bad_pem_root = RootCertificate(CertificateMetadata {
            pem_info: "!!!!! wat !!!!!".to_string(),
            ..eg_metadata
        });
        assert!(matches!(
            bad_pem_root.der(),
            Err(ProcessingError::NoCertInPem { .. })
        ));
    }

    #[test]
    fn test_serial() {
        let eg_metadata = test_metadata();
        let empty_serial_root = RootCertificate(CertificateMetadata {
            certificate_serial_number: "".to_string(),
            ..eg_metadata
        });
        assert!(matches!(
            empty_serial_root.serial(),
            Err(ProcessingError::InvalidSerial { .. })
        ));

        let eg_metadata = test_metadata();
        let invalid_serial_root = RootCertificate(CertificateMetadata {
            certificate_serial_number: "(<'.')>~<('.'>)".to_string(),
            ..eg_metadata
        });
        assert!(matches!(
            invalid_serial_root.serial(),
            Err(ProcessingError::InvalidSerial { .. })
        ));
    }

    #[test]
    fn test_sha256_fp() {
        let eg_metadata = test_metadata();
        let invalid_fp_root = RootCertificate(CertificateMetadata {
            sha256_fingerprint: "*&$&$*".to_string(),
            ..eg_metadata
        });
        assert!(matches!(
            invalid_fp_root.sha256_fp(),
            Err(ProcessingError::InvalidFP { .. })
        ));

        let valid_root = RootCertificate(test_metadata());
        let fp = valid_root.sha256_fp().expect("unexpected sha256_fp err");
        assert_eq!(fp, "ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff");
    }

    #[test]
    fn test_trust_bits() {
        let eg_metadata = test_metadata();
        let empty_trust_bits_root = RootCertificate(CertificateMetadata {
            trust_bits: "".to_string(),
            ..eg_metadata
        });
        assert!(matches!(
            empty_trust_bits_root.trust_bits(),
            Err(ProcessingError::UnknownTrustBit { .. })
        ));

        let eg_metadata = test_metadata();
        let unknown_trust_bits_root = RootCertificate(CertificateMetadata {
            trust_bits: super::MOZILLA_TRUST_BIT_EMAIL.to_string() + "; TrustNoOne",
            ..eg_metadata
        });
        assert!(matches!(
            unknown_trust_bits_root.trust_bits(),
            Err(ProcessingError::UnknownTrustBit { .. })
        ));

        let eg_metadata = test_metadata();
        let tls_only_root = RootCertificate(CertificateMetadata {
            trust_bits: super::MOZILLA_TRUST_BIT_WEBSITES.to_string(),
            ..eg_metadata
        });
        let trust_bits = tls_only_root.trust_bits().unwrap();
        assert_eq!(trust_bits.len(), 1);
        assert!(trust_bits.contains(&super::TrustBits::Websites));

        let eg_metadata = test_metadata();
        let tls_and_email_root = RootCertificate(CertificateMetadata {
            trust_bits: super::MOZILLA_TRUST_BIT_WEBSITES.to_string()
                + ";"
                + super::MOZILLA_TRUST_BIT_EMAIL,
            ..eg_metadata
        });
        let trust_bits = tls_and_email_root.trust_bits().unwrap();
        assert_eq!(trust_bits.len(), 2);
        assert!(trust_bits.contains(&super::TrustBits::Websites));
        assert!(trust_bits.contains(&super::TrustBits::Email));
    }

    #[test]
    fn test_distrust_after() {
        let eg_metadata = test_metadata();
        let empty_distrust_after = RootCertificate(CertificateMetadata {
            distrust_for_tls_after_date: "".to_string(),
            ..eg_metadata
        });
        let distrust_after_result = empty_distrust_after
            .tls_distrust_after()
            .expect("unexpected err from tls_distrust_after");
        assert!(distrust_after_result.is_none());

        let eg_metadata = test_metadata();
        let invalid_distrust_after = RootCertificate(CertificateMetadata {
            distrust_for_tls_after_date: "2023".to_string(),
            ..eg_metadata
        });
        assert!(matches!(
            invalid_distrust_after.tls_distrust_after(),
            Err(ProcessingError::InvalidDate { .. })
        ));

        let eg_metadata = test_metadata();
        let valid_distrust_after = RootCertificate(CertificateMetadata {
            distrust_for_tls_after_date: "1987.10.06".to_string(),
            ..eg_metadata
        });
        let distrust_after = valid_distrust_after
            .tls_distrust_after()
            .expect("unexpected tls_distrust_after error");
        assert!(distrust_after.is_some());
        assert_eq!(distrust_after.unwrap().to_string(), "1987-10-06");
    }

    #[test]
    fn trusted_for_tls() {
        let now = chrono::Utc::now().naive_utc().date();
        let eg_metadata = test_metadata();
        let wrong_trust_bit = RootCertificate(CertificateMetadata {
            trust_bits: super::MOZILLA_TRUST_BIT_EMAIL.to_string(),
            ..eg_metadata
        });
        assert!(!wrong_trust_bit.trusted_for_tls(&now));

        let eg_metadata = test_metadata();
        let trusted_no_distrust_date = RootCertificate(CertificateMetadata {
            trust_bits: super::MOZILLA_TRUST_BIT_WEBSITES.to_string(),
            distrust_for_tls_after_date: "".to_string(),
            ..eg_metadata
        });
        assert!(trusted_no_distrust_date.trusted_for_tls(&now));

        let eg_metadata = test_metadata();
        let trusted_invalid_distrust_date = RootCertificate(CertificateMetadata {
            trust_bits: super::MOZILLA_TRUST_BIT_WEBSITES.to_string(),
            distrust_for_tls_after_date: "yeet".to_string(),
            ..eg_metadata
        });
        assert!(!trusted_invalid_distrust_date.trusted_for_tls(&now));

        let eg_metadata = test_metadata();
        let future_date = now
            .checked_add_months(chrono::Months::new(12))
            .unwrap()
            .format("%Y.%m.%d")
            .to_string();
        let trusted_not_yet_distrust_date = RootCertificate(CertificateMetadata {
            trust_bits: super::MOZILLA_TRUST_BIT_WEBSITES.to_string(),
            distrust_for_tls_after_date: future_date,
            ..eg_metadata
        });
        assert!(trusted_not_yet_distrust_date.trusted_for_tls(&now));

        let eg_metadata = test_metadata();
        let past_date = now
            .checked_sub_days(chrono::Days::new(1))
            .unwrap()
            .format("%Y.%m.%d")
            .to_string();
        let trusted_past_distrust_date = RootCertificate(CertificateMetadata {
            trust_bits: super::MOZILLA_TRUST_BIT_WEBSITES.to_string(),
            distrust_for_tls_after_date: past_date,
            ..eg_metadata
        });
        assert!(!trusted_past_distrust_date.trusted_for_tls(&now));
    }

    #[test]
    fn test_trust_bits_try_from() {
        use crate::root::{TrustBits, MOZILLA_TRUST_BIT_EMAIL, MOZILLA_TRUST_BIT_WEBSITES};

        let bitstr = "Unknown".to_string();
        assert!(matches!(
            TrustBits::try_from(bitstr.as_str()),
            Err(ProcessingError::UnknownTrustBit { .. })
        ));

        let bitstr = MOZILLA_TRUST_BIT_EMAIL;
        assert!(matches!(TrustBits::try_from(bitstr), Ok(TrustBits::Email)));

        let bitstr = MOZILLA_TRUST_BIT_WEBSITES;
        assert!(matches!(
            TrustBits::try_from(bitstr),
            Ok(TrustBits::Websites)
        ));
    }

    #[test]
    fn test_moz_applied_constraints() {
        let eg_root = RootCertificate(test_metadata());
        let expected = Some(vec![0xA0, 0x07, 0x30, 0x05, 0x82, 0x03, 0x2E, 0x74, 0x72]);
        assert_eq!(eg_root.mozilla_applied_constraints(), expected);
    }
}
