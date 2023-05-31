# Rust CCADB Utilities

**WORK IN PROGRESS**

A collection of Rust crates useful for fetching and processing CSV data from [Common CA Database] (CCADB)
reports. These reports offer metadata about root and intermediate certificate authorities that have been disclosed
to participating root programs (e.g. Mozilla, Microsoft, and Google).

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

### ccadb-webpki-roots

Utility for converting the CCADB `IncludedCACertificateReportPEMCSV.csv` report into a Rust file holding the set of
Mozilla TLS trust anchors in `webpki` compatible format. This tool can be used to generate an updated `webpki-roots`
library.

## ccadb-crl-fetch

Utility for best-effort mass-downloading all Mozilla included, non-revoked, issuer CRLs (full and partitioned) 
present in the CCADB all certificate records CSV report. This report includes issuers that chain to expired roots
and CRL URLs that are broken, so some errors are to be expected.

# Future Work

* GitHub actions, better unit test coverage.
* Better handling of retries and HTTPS->HTTP protocol downgrade for CRL downloads.