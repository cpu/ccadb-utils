# ccadb-webpki-roots

Utility for converting the CCADB `IncludedCACertificateReportPEMCSV.csv` report into a Rust file holding the set of
Mozilla TLS trust anchors in `webpki` compatible format. This tool can be used to generate an updated `webpki-roots`
library.

You must provide the CCADB CSV content yourself, for example by using [`ccadb-csv-fetch`](../ccadb-csv-fetch).

## Output

Mozilla trust anchors that are trusted for websites (TLS) will be rendered to a Rust `.rs` file containing a public 
`TLS_SERVER_ROOTS` member that holds a `webpki::TrustAnchor` for each trust anchor. This can be used as the content
for the `webpki-roots` crate, or used by a `rustls`/`webpki` project directly.

## Usage

```bash
cd ../
cargo fetch-included-roots
cargo gen-roots
```