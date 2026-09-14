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

use std::fs;
use std::fs::File;
use std::io::BufWriter;
use std::io::Write;
use std::path::Path;

use anyhow::Context;
use anyhow::Result;

use crate::stats::Analysis;
use crate::stats::AnalyzedConnection;
use crate::stats::Distribution;
use crate::stats::FEATURES;
use crate::ParseFailure;

pub(crate) fn write_outputs(
    output_dir: &Path, analysis: &Analysis, failures: &[ParseFailure],
) -> Result<()> {
    fs::create_dir_all(output_dir).with_context(|| {
        format!("failed to create output directory {}", output_dir.display())
    })?;

    write_connections(&output_dir.join("connections.csv"), analysis)?;
    write_distributions(&output_dir.join("distributions.csv"), analysis)?;
    write_outliers(&output_dir.join("outliers.csv"), analysis)?;
    write_failures(&output_dir.join("failures.csv"), failures)?;
    write_report(&output_dir.join("report.md"), analysis, failures)?;

    Ok(())
}

fn write_connections(path: &Path, analysis: &Analysis) -> Result<()> {
    let mut writer = csv::Writer::from_path(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    let mut header = base_connection_header();
    header.extend(FEATURES.iter().map(|feature| format!("z_{}", feature.name)));
    writer.write_record(&header)?;

    for connection in &analysis.connections {
        let mut record = base_connection_record(connection);
        record.extend(
            connection
                .feature_z_scores
                .iter()
                .map(|value| fmt_opt(*value)),
        );
        writer.write_record(&record)?;
    }

    writer.flush()?;
    Ok(())
}

fn base_connection_header() -> Vec<String> {
    [
        "path",
        "title",
        "vantage_point",
        "file_size_bytes",
        "event_count",
        "start_time_ms",
        "end_time_ms",
        "duration_ms",
        "packets_sent",
        "packets_received",
        "packets_lost",
        "loss_rate_pct",
        "bytes_sent",
        "bytes_received",
        "packet_size_missing_sent",
        "packet_size_missing_received",
        "unique_streams",
        "client_bidi_streams",
        "smoothed_rtt_sample_count",
        "smoothed_rtt_median_ms",
        "smoothed_rtt_p95_ms",
        "smoothed_rtt_final_ms",
        "rtt_variance_final_ms",
        "min_rtt_final_ms",
        "congestion_window_final_bytes",
        "congestion_window_max_bytes",
        "bytes_in_flight_max",
        "pto_count",
        "pto_max_consecutive",
        "pto_per_1000_packets",
        "blocked_events",
        "migration_events",
        "migrations_completed",
        "handshake_completed",
        "handshake_confirmed",
        "close_initiator",
        "close_trigger",
        "close_reason",
        "close_error",
        "workload_score",
        "network_score",
        "typicality_score",
        "max_abs_z",
        "strongest_feature",
        "outlier_kind",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn base_connection_record(connection: &AnalyzedConnection) -> Vec<String> {
    let metrics = &connection.metrics;
    vec![
        metrics.path.clone(),
        metrics.title.clone().unwrap_or_default(),
        metrics.vantage_point.clone(),
        metrics.file_size_bytes.to_string(),
        metrics.event_count.to_string(),
        fmt_opt(metrics.start_time_ms),
        fmt_opt(metrics.end_time_ms),
        fmt_opt(metrics.duration_ms()),
        metrics.packets_sent.to_string(),
        metrics.packets_received.to_string(),
        metrics.packets_lost().to_string(),
        fmt_opt(metrics.loss_rate_pct()),
        metrics.bytes_sent.to_string(),
        metrics.bytes_received.to_string(),
        metrics.packet_size_missing_sent.to_string(),
        metrics.packet_size_missing_received.to_string(),
        metrics.unique_streams().to_string(),
        metrics.client_bidi_streams().to_string(),
        metrics.smoothed_rtt_sample_count.to_string(),
        fmt_opt(metrics.smoothed_rtt_median_ms()),
        fmt_opt(metrics.smoothed_rtt_p95_ms()),
        fmt_opt(metrics.smoothed_rtt_final_ms),
        fmt_opt(metrics.rtt_variance_final_ms),
        fmt_opt(metrics.min_rtt_final_ms),
        fmt_opt_u64(metrics.congestion_window_final_bytes),
        fmt_opt_u64(metrics.congestion_window_max_bytes),
        fmt_opt_u64(metrics.bytes_in_flight_max),
        metrics.pto_count().to_string(),
        metrics.pto_max_consecutive.to_string(),
        fmt_opt(metrics.pto_per_1000_packets()),
        metrics.blocked_events.to_string(),
        metrics.migration_events.to_string(),
        metrics.migrations_completed.to_string(),
        metrics.handshake_completed.to_string(),
        metrics.handshake_confirmed.to_string(),
        metrics.close_initiator.clone().unwrap_or_default(),
        metrics.close_trigger.clone().unwrap_or_default(),
        metrics.close_reason.clone().unwrap_or_default(),
        metrics.close_error.clone().unwrap_or_default(),
        fmt_opt(connection.workload_score),
        fmt_opt(connection.network_score),
        fmt_opt(connection.typicality_score),
        fmt_opt(connection.max_abs_z),
        connection.strongest_feature.unwrap_or_default().to_string(),
        connection
            .outlier_kind
            .map(|kind| kind.to_string())
            .unwrap_or_default(),
    ]
}

fn write_distributions(path: &Path, analysis: &Analysis) -> Result<()> {
    let mut writer = csv::Writer::from_path(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    writer.write_record([
        "feature",
        "group",
        "transform",
        "count",
        "min",
        "p05",
        "p25",
        "median",
        "mean",
        "p75",
        "p95",
        "max",
        "mad",
        "model_median",
        "model_mad",
        "model_scale",
    ])?;

    for distribution in &analysis.distributions {
        writer.write_record(distribution_record(distribution))?;
    }

    writer.flush()?;
    Ok(())
}

fn distribution_record(distribution: &Distribution) -> Vec<String> {
    let raw = distribution.raw.as_ref();
    let model = distribution.model.as_ref();
    vec![
        distribution.feature.name.to_string(),
        distribution.feature.group.as_str().to_string(),
        distribution.feature.transform.as_str().to_string(),
        raw.map(|summary| summary.count.to_string())
            .unwrap_or_default(),
        raw.map(|summary| fmt(summary.min)).unwrap_or_default(),
        raw.map(|summary| fmt(summary.p05)).unwrap_or_default(),
        raw.map(|summary| fmt(summary.p25)).unwrap_or_default(),
        raw.map(|summary| fmt(summary.median)).unwrap_or_default(),
        raw.map(|summary| fmt(summary.mean)).unwrap_or_default(),
        raw.map(|summary| fmt(summary.p75)).unwrap_or_default(),
        raw.map(|summary| fmt(summary.p95)).unwrap_or_default(),
        raw.map(|summary| fmt(summary.max)).unwrap_or_default(),
        raw.map(|summary| fmt(summary.mad)).unwrap_or_default(),
        model.map(|summary| fmt(summary.median)).unwrap_or_default(),
        model.map(|summary| fmt(summary.mad)).unwrap_or_default(),
        fmt_opt(distribution.model_scale),
    ]
}

fn write_outliers(path: &Path, analysis: &Analysis) -> Result<()> {
    let mut writer = csv::Writer::from_path(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    writer.write_record([
        "path",
        "outlier_kind",
        "workload_score",
        "network_score",
        "typicality_score",
        "max_abs_z",
        "strongest_feature",
        "duration_ms",
        "total_bytes",
        "total_packets",
        "client_bidi_streams",
        "smoothed_rtt_median_ms",
        "loss_rate_pct",
        "pto_per_1000_packets",
        "blocked_events",
        "migrations_completed",
    ])?;

    for connection in sorted_outliers(analysis) {
        let metrics = &connection.metrics;
        writer.write_record([
            metrics.path.clone(),
            connection
                .outlier_kind
                .map(|kind| kind.to_string())
                .unwrap_or_default(),
            fmt_opt(connection.workload_score),
            fmt_opt(connection.network_score),
            fmt_opt(connection.typicality_score),
            fmt_opt(connection.max_abs_z),
            connection.strongest_feature.unwrap_or_default().to_string(),
            fmt_opt(metrics.duration_ms()),
            metrics.total_bytes().to_string(),
            metrics.total_packets().to_string(),
            metrics.client_bidi_streams().to_string(),
            fmt_opt(metrics.smoothed_rtt_median_ms()),
            fmt_opt(metrics.loss_rate_pct()),
            fmt_opt(metrics.pto_per_1000_packets()),
            metrics.blocked_events.to_string(),
            metrics.migrations_completed.to_string(),
        ])?;
    }

    writer.flush()?;
    Ok(())
}

fn write_failures(path: &Path, failures: &[ParseFailure]) -> Result<()> {
    let mut writer = csv::Writer::from_path(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    writer.write_record(["path", "error"])?;
    for failure in failures {
        writer.write_record([&failure.path, &failure.error])?;
    }
    writer.flush()?;

    Ok(())
}

fn write_report(
    path: &Path, analysis: &Analysis, failures: &[ParseFailure],
) -> Result<()> {
    let file = File::create(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    let mut writer = BufWriter::new(file);
    let outlier_count = analysis
        .connections
        .iter()
        .filter(|connection| connection.outlier_kind.is_some())
        .count();

    writeln!(writer, "# qlog analysis")?;
    writeln!(writer)?;
    writeln!(
        writer,
        "- Connections parsed: {}",
        analysis.connections.len()
    )?;
    writeln!(writer, "- Files that failed: {}", failures.len())?;
    writeln!(writer, "- Outliers: {outlier_count}")?;
    writeln!(writer, "- Outlier threshold: {}", fmt(analysis.threshold))?;

    writeln!(writer)?;
    writeln!(writer, "## Representative connection")?;
    writeln!(writer)?;
    if let Some(index) = analysis.representative {
        let connection = &analysis.connections[index];
        let metrics = &connection.metrics;
        writeln!(
            writer,
            "The existing connection closest to the robust workload center is **{}**.",
            markdown(&metrics.path)
        )?;
        writeln!(writer)?;
        writeln!(writer, "| Metric | Value |")?;
        writeln!(writer, "|---|---:|")?;
        writeln!(
            writer,
            "| Duration (ms) | {} |",
            fmt_opt(metrics.duration_ms())
        )?;
        writeln!(writer, "| Total bytes | {} |", metrics.total_bytes())?;
        writeln!(writer, "| Total packets | {} |", metrics.total_packets())?;
        writeln!(
            writer,
            "| Client bidi streams | {} |",
            metrics.client_bidi_streams()
        )?;
        writeln!(
            writer,
            "| Median smoothed RTT (ms) | {} |",
            fmt_opt(metrics.smoothed_rtt_median_ms())
        )?;
        writeln!(
            writer,
            "| Loss rate (%) | {} |",
            fmt_opt(metrics.loss_rate_pct())
        )?;
        writeln!(
            writer,
            "| Workload score | {} |",
            fmt_opt(connection.workload_score)
        )?;
        writeln!(
            writer,
            "| Network score | {} |",
            fmt_opt(connection.network_score)
        )?;
    } else {
        writeln!(writer, "No connection had enough workload data.")?;
    }

    writeln!(writer)?;
    writeln!(writer, "## Distributions")?;
    writeln!(writer)?;
    writeln!(
        writer,
        "Values below are in their original units; scoring uses the listed transform."
    )?;
    writeln!(writer)?;
    writeln!(
        writer,
        "| Feature | Group | Transform | Count | Median | P95 | MAD |"
    )?;
    writeln!(writer, "|---|---|---|---:|---:|---:|---:|")?;
    for distribution in &analysis.distributions {
        let raw = distribution.raw.as_ref();
        writeln!(
            writer,
            "| {} | {} | {} | {} | {} | {} | {} |",
            distribution.feature.name,
            distribution.feature.group.as_str(),
            distribution.feature.transform.as_str(),
            raw.map(|summary| summary.count.to_string())
                .unwrap_or_default(),
            raw.map(|summary| fmt(summary.median)).unwrap_or_default(),
            raw.map(|summary| fmt(summary.p95)).unwrap_or_default(),
            raw.map(|summary| fmt(summary.mad)).unwrap_or_default(),
        )?;
    }

    writeln!(writer)?;
    writeln!(writer, "## Strongest outliers")?;
    writeln!(writer)?;
    let outliers = sorted_outliers(analysis);
    if outliers.is_empty() {
        writeln!(writer, "No connection crossed the configured threshold.")?;
    } else {
        writeln!(
            writer,
            "| Connection | Kind | Strongest feature | |z| | Typicality |"
        )?;
        writeln!(writer, "|---|---|---|---:|---:|")?;
        for connection in outliers.into_iter().take(25) {
            writeln!(
                writer,
                "| {} | {} | {} | {} | {} |",
                markdown(&connection.metrics.path),
                connection
                    .outlier_kind
                    .map(|kind| kind.to_string())
                    .unwrap_or_default(),
                connection.strongest_feature.unwrap_or_default(),
                fmt_opt(connection.max_abs_z),
                fmt_opt(connection.typicality_score),
            )?;
        }
    }

    if !failures.is_empty() {
        writeln!(writer)?;
        writeln!(writer, "## Parse failures")?;
        writeln!(writer)?;
        writeln!(writer, "| File | Error |")?;
        writeln!(writer, "|---|---|")?;
        for failure in failures.iter().take(25) {
            writeln!(
                writer,
                "| {} | {} |",
                markdown(&failure.path),
                markdown(&failure.error)
            )?;
        }
    }

    writeln!(writer)?;
    writeln!(writer, "## Interpretation notes")?;
    writeln!(writer)?;
    writeln!(
        writer,
        "- An outlier is unusual, not necessarily unhealthy. Workload and network outliers are classified separately."
    )?;
    writeln!(
        writer,
        "- Scores use median/MAD robust z-scores. Duration, volume, packet count, stream count, PTO rate, and event counts use `log1p`."
    )?;
    writeln!(
        writer,
        "- A non-median value in a population with zero MAD has an infinite robust z-score and is therefore an outlier."
    )?;
    writeln!(
        writer,
        "- Empty cells mean the required qlog event or field was not present."
    )?;

    writer.flush()?;
    Ok(())
}

fn sorted_outliers(analysis: &Analysis) -> Vec<&AnalyzedConnection> {
    let mut outliers = analysis
        .connections
        .iter()
        .filter(|connection| connection.outlier_kind.is_some())
        .collect::<Vec<_>>();
    outliers.sort_by(|a, b| {
        b.max_abs_z
            .unwrap_or_default()
            .total_cmp(&a.max_abs_z.unwrap_or_default())
            .then_with(|| a.metrics.path.cmp(&b.metrics.path))
    });

    outliers
}

fn fmt_opt(value: Option<f64>) -> String {
    value.map(fmt).unwrap_or_default()
}

fn fmt_opt_u64(value: Option<u64>) -> String {
    value.map(|value| value.to_string()).unwrap_or_default()
}

fn fmt(value: f64) -> String {
    if value == f64::INFINITY {
        return "inf".to_string();
    }
    if value == f64::NEG_INFINITY {
        return "-inf".to_string();
    }

    let mut output = format!("{value:.6}");
    while output.contains('.') && output.ends_with('0') {
        output.pop();
    }
    if output.ends_with('.') {
        output.pop();
    }

    output
}

fn markdown(value: &str) -> String {
    value.replace('|', "\\|").replace(['\r', '\n'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_are_compact_and_infinity_is_explicit() {
        assert_eq!(fmt(12.5), "12.5");
        assert_eq!(fmt(12.0), "12");
        assert_eq!(fmt(f64::INFINITY), "inf");
    }

    #[test]
    fn markdown_table_cells_are_escaped() {
        assert_eq!(markdown("a|b\nc"), "a\\|b c");
    }
}
