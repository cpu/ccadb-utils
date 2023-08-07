use crate::error::ProcessingError;
use crate::root::RootCertificate;
use askama::Template;
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt::{Debug, Display, Formatter};
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

#[derive(Template)]
#[template(path = "webpki_roots.txt")]
/// A template for rendering trusted webpki roots as a Rust library.
pub(crate) struct WebpkiRootsTemplate {
    /// An ordered set of trusted webpki root certificates.
    pub(crate) trusted_roots: BTreeSet<WebpkiRoot>,
}

#[derive(Debug, Clone, Eq, PartialEq, PartialOrd)]
/// A wrapper around a Vec of DER bytes that is displayable with Debug formatting.
pub(crate) struct Der(Vec<u8>);

impl Display for Der {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // Defer to debug fmt.
        self.0.fmt(f)
    }
}

#[derive(Debug, Eq, Clone)]
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
    /// DER encoded trust anchor subject bytes.
    pub(crate) subject_der: Der,
    /// DER encoded trust anchor subject public key information bytes.
    pub(crate) spki: Der,
    /// DER encoded name constraints extension.
    pub(crate) name_constraints: Option<Der>,
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

    /// Try to convert a RootCertificate to a WebpkiRoot we can template.
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
        let subject_der = Der(trust_anchor.subject.to_vec());
        let spki = Der(trust_anchor.spki.to_vec());
        let name_constraints = root.mozilla_applied_constraints().map(|der| Der(der));

        Ok(WebpkiRoot {
            issuer,
            subject,
            label,
            serial,
            sha256_fp,
            pem,
            subject_der,
            spki,
            name_constraints,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Der, WebpkiRoot};
    use crate::root::{self, RootCertificate};

    use std::collections::BTreeSet;

    fn eg_root() -> WebpkiRoot {
        WebpkiRoot {
            issuer: "foo".to_owned(),
            subject: "bar".to_owned(),
            label: "baz".to_owned(),
            serial: "qux".to_owned(),
            sha256_fp: "quux".to_owned(),
            pem: "corge".to_owned(),
            subject_der: Der(vec![]),
            spki: Der(vec![]),
            name_constraints: None,
        }
    }

    #[test]
    fn webpki_root_partial_eq() {
        let root_a = eg_root();
        let mut root_b = eg_root();
        assert_eq!(root_a, root_b);

        root_b.issuer = "foo".into();
        assert_eq!(root_a, root_b);

        let mut root_c = eg_root();
        root_c.sha256_fp = "ffff".into();
        assert_ne!(root_a, root_c);
    }

    #[test]
    fn webpki_root_partial_ord() {
        let mut root_a = eg_root();
        root_a.sha256_fp = "ccccc".into();
        let mut root_b = eg_root();
        root_b.sha256_fp = "aaaa".into();
        let mut root_c = eg_root();
        root_c.sha256_fp = "bbbbb".into();

        let expected = vec![&root_b, &root_c, &root_a];
        let mut actual = BTreeSet::new();
        actual.insert(&root_a);
        actual.insert(&root_b);
        actual.insert(&root_c);
        assert_eq!(expected, actual.into_iter().collect::<Vec<_>>());
    }

    #[test]
    fn webpki_root_try_from() {
        let root = RootCertificate(root::tests::test_metadata());
        let pem = include_str!("../tests/example.cert.pem");

        let webpki_root =
            WebpkiRoot::try_from(root).expect("unexpected error parsing mock metadata");

        assert_eq!(
            webpki_root.issuer,
            "C=US, O=Let's Encrypt, CN=R3".to_string()
        );
        assert_eq!(webpki_root.subject, "CN=binaryparadox.net".to_string());
        assert_eq!(webpki_root.label, "Trustworthy Root CA".to_string());
        assert_eq!(webpki_root.serial, "12648430".to_string());
        assert_eq!(webpki_root.sha256_fp,
                   "ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff".to_string());
        assert_eq!(webpki_root.pem, pem.to_string());
        assert_eq!(
            webpki_root.subject_der,
            Der(vec![
                49, 26, 48, 24, 6, 3, 85, 4, 3, 19, 17, 98, 105, 110, 97, 114, 121, 112, 97, 114,
                97, 100, 111, 120, 46, 110, 101, 116
            ])
        );
        assert_eq!(
            webpki_root.spki,
            Der(vec!(
                48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7, 3,
                66, 0, 4, 40, 218, 22, 51, 224, 37, 148, 147, 55, 183, 38, 17, 196, 75, 250, 11,
                161, 7, 1, 149, 113, 141, 253, 33, 150, 151, 142, 84, 17, 16, 106, 106, 58, 102, 0,
                180, 62, 37, 46, 8, 222, 221, 86, 0, 33, 7, 254, 206, 249, 60, 123, 133, 234, 46,
                42, 121, 80, 165, 168, 205, 81, 167, 216, 77
            ))
        );
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

    #[cfg(test)]
    mod tests {
        use crate::template::filters::prefix;

        #[test]
        fn test_prefix() {
            let input = r#"Lorem ipsum dolor sit amet, consectetur adipiscing elit, 
sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. At augue eget arcu dictum 
varius duis at consectetur lorem. Quis risus sed vulputate odio ut. Velit scelerisque in dictum 
non consectetur a erat nam."#;
            let expected = r#" * Lorem ipsum dolor sit amet, consectetur adipiscing elit, 
 * sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. At augue eget arcu dictum 
 * varius duis at consectetur lorem. Quis risus sed vulputate odio ut. Velit scelerisque in dictum 
 * non consectetur a erat nam."#;

            assert_eq!(prefix(input, " * ").unwrap(), expected)
        }
    }
}
