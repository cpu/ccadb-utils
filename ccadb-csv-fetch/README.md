# ccadb-csv-fetch

Utility for downloading CCADB CSV metadata reports for local processing. Hardcodes a vendored copy of the root
certificate required to access CCADB such that the tool can bootstrap a root store based on the CSV content without
itself needing a full root store.

## Usage

```bash
ccadb-csv-fetch ("mozilla-included-roots"|"all-cert-records") (csv-output-path)
```