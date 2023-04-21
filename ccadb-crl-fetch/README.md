# ccadb-crl-fetch

Utility for mass-downloading all Mozilla included, non-revoked, issuer CRLs (full and partitioned) present in the
CCADB all certificate records CSV report.

This utility makes a best-effort attempt to download as many CRLs as it can. You can expect to find some URLs fail to
fetch. This may be because the issuer chains to an expired root, or because the CRL hosting is broken.

## Output files

CRLs will be downloaded to a `crls/` directory (which must not exist ahead of time). Files will be named for the
Salesforce record ID of the issuer associated with the CRL URL(s), and an incrementing counter for issuers with more 
than one CRL URL.

## Usage

```bash
cd ../
cargo fetch-all-records
cargo fetch-crls
ls -la crls/
```