use crate::error::ProcessingError;
use crate::root::RootCertificate;
use askama::Template;
use std::cmp::Ordering;
use std::collections::BTreeSet;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

#[derive(Template)]
#[template(path = "webpki_roots.txt")]
/// A template for rendering trusted webpki roots as a Rust library.
pub(crate) struct WebpkiRootsTemplate {
    /// An ordered set of trusted webpki root certificates.
    pub(crate) trusted_roots: BTreeSet<WebpkiRoot>,
}

#[derive(Debug, Eq)]
/// Data representing a webpki trust anchor that can be templated.
pub(crate) struct WebpkiRoot {
    /// The decoded trust anchor issuer in human readable form.
    pub(crate) issuer: String,
    /// The decoded trust anchor subject in human readable form.
    pub(crate) subject: String,
    /// A short label to identify the trust anchor.
    pub(crate) label: String,
    /// The human readable certificate serial number.
    pub(crate) serial: String,
    /// A colon separated SHA256 certificate fingerprint in hex encoding.
    pub(crate) sha256_fp: String,
    /// The trust anchor's PEM encoding.
    pub(crate) pem: String,
    /// A string representing a [u8] slice of DER encoded trust anchor subject bytes.
    pub(crate) subject_der: String,
    /// A string representing a [u8] slice of DER encoded trust anchor subject public key
    /// information bytes.
    pub(crate) spki: String,
    // TODO(XXX): name_constraints,
}

impl PartialEq for WebpkiRoot {
    fn eq(&self, other: &Self) -> bool {
        self.sha256_fp == other.sha256_fp
    }
}

impl PartialOrd for WebpkiRoot {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.sha256_fp.partial_cmp(&other.sha256_fp)
    }
}

impl Ord for WebpkiRoot {
    fn cmp(&self, other: &Self) -> Ordering {
        self.sha256_fp.cmp(&other.sha256_fp)
    }
}

impl TryFrom<RootCertificate> for WebpkiRoot {
    type Error = ProcessingError;

    /// Try to convert a RootCertificate to a WebpkiRoot we can template. This involves
    /// converting several fields to string representations.
    fn try_from(root: RootCertificate) -> Result<Self, Self::Error> {
        let der = root.der()?;
        let trust_anchor = webpki::TrustAnchor::try_from_cert_der(&der)?;
        let cert = X509Certificate::from_der(&der)?.1;

        let issuer = cert.issuer.to_string();
        let subject = cert.subject.to_string();
        let label = root.0.common_name_or_certificate_name.clone();
        let serial = root.serial()?.to_string();
        let sha256_fp = root.sha256_fp()?;
        let pem = root.pem().to_string();
        // TODO(XXX): maybe set subject_der and spki as &[u8] and template as such?
        let subject_der = format!("{:?}", trust_anchor.subject);
        let spki = format!("{:?}", trust_anchor.spki);

        Ok(WebpkiRoot {
            issuer,
            subject,
            label,
            serial,
            sha256_fp,
            pem,
            subject_der,
            spki,
        })
    }
}

mod filters {
    /// prefix each line of `s` with `p`. This is helpful for rendering block comments
    /// where each line of the comment should have a prefix.
    pub fn prefix<T: std::fmt::Display>(s: T, p: &str) -> Result<String, askama::Error> {
        let s = s.to_string();
        let lines = s.lines().collect::<Vec<&str>>();
        let num_lines = lines.len();

        let mut indented = String::new();
        for (i, line) in lines.iter().enumerate() {
            indented.push_str(p);
            indented.push_str(line);
            if i != num_lines - 1 {
                indented.push('\n');
            }
        }

        Ok(indented)
    }
}
