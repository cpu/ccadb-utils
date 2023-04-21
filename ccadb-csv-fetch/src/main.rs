use ccadb_csv_fetch::{fetch_report, FetchError, ReportType};
use indicatif::{ProgressBar, ProgressStyle};
use std::path::Path;
use std::time;
use std::time::Duration;

const DEFAULT_REPORT_TYPE: ReportType = ReportType::MozillaIncludedRoots;

/// usage:
///   ccadb-csv-fetch ("mozilla-included-roots"|"all-cert-records") (csv-output-path)
fn main() -> Result<(), FetchError> {
    let mut args = std::env::args();
    let (_, report_type, output_path) = (
        args.next(), // program name.
        args.next().unwrap_or(DEFAULT_REPORT_TYPE.to_string()),
        args.next(),
    );

    let report_type = ReportType::try_from(report_type.as_str()).unwrap_or_else(|_| {
        panic!(
            "report type must be {} or {}",
            ReportType::MozillaIncludedRoots,
            ReportType::AllCertRecords,
        )
    });
    let output_path = output_path.unwrap_or(format!("{}.csv", report_type));

    download(report_type, output_path)
}

fn download(report_type: ReportType, output_path: impl AsRef<Path>) -> Result<(), FetchError> {
    // Unfortunately the CCADB APIs use chunked encoding so we can't easily provide a progress
    // bar based on the total size of the CSV to be downloaded. Since the CSV can be quite large we
    // do need to do _something_ to indicate the program hasn't hung.
    let pb = ProgressBar::new_spinner();
    pb.enable_steady_tick(Duration::from_millis(120));
    pb.set_style(
        ProgressStyle::with_template("{spinner:.blue} {msg}")
            .unwrap()
            // For more spinners check out the cli-spinners project:
            // https://github.com/sindresorhus/cli-spinners/blob/master/spinners.json
            .tick_strings(&["⢹", "⢺", "⢼", "⣸", "⣇", "⡧", "⡗", "⡏"]),
    );

    let start_time = time::Instant::now();
    pb.set_message(format!("Downloading {} ...", report_type.url()));
    fetch_report(&report_type, output_path).map(|_| ())?;
    let elapsed = start_time.elapsed().as_secs();
    pb.finish_with_message(format!("Downloaded {} in {elapsed}s", report_type.url()));

    Ok(())
}
