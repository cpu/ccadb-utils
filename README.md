# Rust CCADB Utilities

**Status: Rough Prototype**

A collection of Rust crates useful for fetching and processing CSV data from [Common CA Database] (CCADB)
reports. These reports offer metadata about root and intermediate certificate authorities that have been disclosed
to participating root programs (e.g. Mozilla, Microsoft, and Google).

[Common CA Database]: https://www.ccadb.org/

## Getting started

```bash
cargo fetch-included-roots
cargo fetch-all-records     # May take a little while :)
```

## ccadb-csv

Offers thin wrappers around CCADB report content, preserving values unprocessed and in String form, like the raw CSV
data. Consumers that wish to process this data will likely want to create newtype wrappers that further refine the data.

## ccadb-csv-fetch

Utility for downloading CCADB CSV metadata reports for local processing. Hardcodes a vendored copy of the root
certificate required to access CCADB such that the tool can bootstrap a root store based on the CSV content without
itself needing a full root store.

## ccadb-crl-fetch

Utility for best-effort mass-downloading all Mozilla included, non-revoked, issuer CRLs (full and partitioned) 
present in the CCADB all certificate records CSV report. This report includes issuers that chain to expired roots
and CRL URLs that are broken, so some errors are to be expected. Mostly useful for building a test data corpus.

# Future Work

* Better handling of retries and HTTPS->HTTP protocol downgrade for CRL downloads.

# Previous Work

### ccadb-webpki-roots

Utility for converting the CCADB `IncludedCACertificateReportPEMCSV.csv` report into a Rust file holding the set of
Mozilla TLS trust anchors in `webpki` compatible format. This tool can be used to generate an updated `webpki-roots`
library.

This inspired [a simpler solution][codegen] built directly into the [webpki-roots] crate.

[codegen]: https://github.com/rustls/webpki-roots/blob/a63eec3f7ff565817bee11603f1a6e76fbee2fc0/tests/codegen.rs
[webpki-roots]: https://github.com/rustls/webpki-roots
