use ccadb_crl_fetch::{download_crl, ProcessingError};
use futures_util::stream::StreamExt;
use indicatif::ProgressBar;
use std::error::Error;
use std::future::Future;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tokio_stream::iter;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_CSV_PATH: &str = "./testdata/AllCertificateRecordsCSVFormat.csv";
const DEFAULT_OUTPUT_DIR: &str = "./crls";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_init();

    let mut args = std::env::args();
    let (_, data_file, output_dir) = (
        args.next(), // Program name
        args.next().unwrap_or(DEFAULT_CSV_PATH.to_owned()),
        args.next().unwrap_or(DEFAULT_OUTPUT_DIR.to_owned()),
    );

    tracing::info!("loading root reports CSV from {data_file}...");
    let data_file = std::fs::File::open(data_file)?;

    fs::create_dir(&output_dir)
        .await
        .unwrap_or_else(|e| panic!("failed to create output dir {output_dir}: {e}"));

    let futures = download_futures(data_file, output_dir)?;
    let num_futures = futures.len();
    tracing::info!("Found {num_futures} CRL URLs to process");

    let stream_of_futures = iter(futures);
    let mut buffered = stream_of_futures.buffer_unordered(15); // TODO(XXX): parameter?

    tracing::info!("Downloading CRLs");
    let bar = ProgressBar::new(num_futures as u64);
    while let Some(res) = buffered.next().await {
        bar.inc(1);
        if let Err(err) = res {
            // TODO(XXX): Consider retries, particularly switching failed URLs from HTTPS to HTTP.
            bar.println(format!("{err}"));
        }
    }
    bar.finish();
    tracing::info!("Done!");
    Ok(())
}

fn tracing_init() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ccadb_crl_fetch=info".into()),
        )
        .init();
}

fn http_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::ClientBuilder::new()
        .timeout(Duration::from_secs(30)) // TODO(XXX): parameter?
        .user_agent(format!("ccadb_crl_fetch/{VERSION}"))
        .build()
}

fn download_futures(
    data_file: impl Read,
    output_dir: impl AsRef<Path>,
) -> Result<Vec<impl Future<Output = Result<(), ProcessingError>>>, Box<dyn Error>> {
    let root_reports: Vec<
        Result<ccadb_csv::all_cert_records::CertificateMetadata, ccadb_csv::DataSourceError>,
    > = ccadb_csv::all_cert_records::read_csv(data_file).collect();
    let moz_issuers = ccadb_crl_fetch::mozilla_records(root_reports.into_iter())?;
    let client = Arc::new(http_client()?);

    let mut futures = Vec::default();
    for issuer in moz_issuers {
        if let Ok(crl_urls) = issuer.all_crl_urls() {
            for (crl_idx, url) in crl_urls.into_iter().enumerate() {
                let id = &issuer.0.salesforce_record_id;
                let out_file_path = output_dir.as_ref().join(format!("{id}.{crl_idx}.crl"));
                futures.push(download_crl(client.clone(), out_file_path, url))
            }
        }
    }
    Ok(futures)
}
