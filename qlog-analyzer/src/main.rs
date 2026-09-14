// Copyright (C) 2026, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

mod metrics;
mod output;
mod stats;

use std::fs;
use std::path::Path;
use std::path::PathBuf;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "qlog-analyzer",
    about = "Analyze a directory of sequential qlog traces"
)]
struct Args {
    /// Directory containing .sqlog, .sqlog.gz, or .sqlog.zst files.
    /// A single qlog file is accepted as well.
    input: PathBuf,

    /// Directory in which CSV files and report.md are written.
    #[arg(short, long, default_value = "qlog-analysis")]
    output: PathBuf,

    /// Robust z-score at which a connection is considered an outlier.
    #[arg(long, default_value_t = 3.5)]
    outlier_threshold: f64,
}

#[derive(Debug)]
pub(crate) struct ParseFailure {
    pub(crate) path: String,
    pub(crate) error: String,
}

fn main() {
    if let Err(error) = run(Args::parse()) {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn run(args: Args) -> Result<()> {
    if !args.outlier_threshold.is_finite() || args.outlier_threshold <= 0.0 {
        bail!("--outlier-threshold must be a finite number greater than zero");
    }

    let mut paths = discover_qlogs(&args.input)?;
    if paths.is_empty() {
        bail!(
            "no .sqlog, .sqlog.gz, or .sqlog.zst files found under {}",
            args.input.display()
        );
    }
    paths.sort();

    let display_root = if args.input.is_dir() {
        args.input.as_path()
    } else {
        args.input.parent().unwrap_or_else(|| Path::new(""))
    };

    let mut connections = Vec::with_capacity(paths.len());
    let mut failures = Vec::new();

    for path in paths {
        let display_path = path
            .strip_prefix(display_root)
            .unwrap_or(&path)
            .to_string_lossy()
            .into_owned();

        match metrics::parse_connection(&path, display_path.clone()) {
            Ok(connection) => connections.push(connection),

            Err(error) => failures.push(ParseFailure {
                path: display_path,
                error: format!("{error:#}"),
            }),
        }
    }

    connections.sort_by(|a, b| a.path.cmp(&b.path));

    let analysis = stats::analyze(connections, args.outlier_threshold);
    output::write_outputs(&args.output, &analysis, &failures)?;

    println!(
        "analyzed {} connection(s), {} failure(s); results written to {}",
        analysis.connections.len(),
        failures.len(),
        args.output.display()
    );

    Ok(())
}

fn discover_qlogs(input: &Path) -> Result<Vec<PathBuf>> {
    if input.is_file() {
        if is_qlog_path(input) {
            return Ok(vec![input.to_path_buf()]);
        }

        bail!("{} is not a supported qlog file", input.display());
    }

    if !input.is_dir() {
        bail!("input path {} does not exist", input.display());
    }

    let mut found = Vec::new();
    let mut pending = vec![input.to_path_buf()];

    while let Some(directory) = pending.pop() {
        let entries = fs::read_dir(&directory)
            .with_context(|| format!("failed to read {}", directory.display()))?;

        for entry in entries {
            let entry = entry.with_context(|| {
                format!("failed to read an entry in {}", directory.display())
            })?;
            let file_type = entry.file_type().with_context(|| {
                format!("failed to inspect {}", entry.path().display())
            })?;
            let path = entry.path();

            if file_type.is_dir() {
                pending.push(path);
            } else if (file_type.is_file() ||
                (file_type.is_symlink() && path.is_file())) &&
                is_qlog_path(&path)
            {
                found.push(path);
            }
        }
    }

    Ok(found)
}

fn is_qlog_path(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };

    name.ends_with(qlog::SQLOG_EXT) ||
        name.ends_with(qlog::SQLOG_GZ_EXT) ||
        name.ends_with(qlog::SQLOG_ZST_EXT)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn qlog_compound_extensions_are_recognized() {
        assert!(is_qlog_path(Path::new("connection.sqlog")));
        assert!(is_qlog_path(Path::new("connection.sqlog.gz")));
        assert!(is_qlog_path(Path::new("connection.sqlog.zst")));
        assert!(!is_qlog_path(Path::new("connection.qlog")));
        assert!(!is_qlog_path(Path::new("connection.gz")));
    }

    #[test]
    fn run_writes_all_output_files() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input");
        let output = directory.path().join("output");
        fs::create_dir(&input).unwrap();

        let mut qlog = fs::File::create(input.join("trace.sqlog")).unwrap();
        writeln!(
            qlog,
            "\u{1e}{}",
            serde_json::json!({
                "file_schema": "urn:ietf:params:qlog:file:sequential",
                "serialization_format": "JSON-SEQ",
                "trace": {
                    "vantage_point": {"type": "server"},
                    "event_schemas": []
                }
            })
        )
        .unwrap();
        writeln!(
            qlog,
            "\u{1e}{}",
            serde_json::json!({
                "time": 0.0,
                "name": "quic:packet_sent",
                "data": {
                    "header": {"packet_type": "1RTT"},
                    "raw": {"length": 1200}
                }
            })
        )
        .unwrap();
        drop(qlog);

        run(Args {
            input,
            output: output.clone(),
            outlier_threshold: 3.5,
        })
        .unwrap();

        for name in [
            "connections.csv",
            "distributions.csv",
            "outliers.csv",
            "failures.csv",
            "report.md",
        ] {
            assert!(output.join(name).is_file(), "missing {name}");
        }

        let connections =
            fs::read_to_string(output.join("connections.csv")).unwrap();
        assert!(connections.contains("trace.sqlog"));
        assert!(connections.contains("1200"));
    }
}
