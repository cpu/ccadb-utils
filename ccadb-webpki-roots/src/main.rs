use ccadb_webpki_roots::render_webpki_roots;
use std::io;
use std::io::Write;

const DEFAULT_CSV_PATH: &str = "./testdata/IncludedCACertificateReportPEMCSV.csv";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args();

    let (_, data_file, output_file) = (
        args.next(), // Program name
        args.next().unwrap_or(DEFAULT_CSV_PATH.to_owned()),
        args.next(),
    );

    let input = std::fs::File::open(data_file)?;
    let mut output: Box<dyn Write> = match output_file {
        // No output file, print to stdout.
        None => Box::new(io::stdout().lock()),
        Some(path) => Box::new(std::fs::File::open(path)?) as Box<dyn Write>,
    };

    Ok(writeln!(output, "{}", render_webpki_roots(input)?)?)
}
