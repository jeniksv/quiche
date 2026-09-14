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

use std::cmp::Ordering;
use std::fmt;

use crate::metrics::ConnectionMetrics;

const MAD_NORMAL_SCALE: f64 = 1.4826;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FeatureGroup {
    Workload,
    Network,
}

impl FeatureGroup {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Workload => "workload",
            Self::Network => "network",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Transform {
    Identity,
    Log1p,
}

impl Transform {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Log1p => "log1p",
        }
    }

    fn apply(self, value: f64) -> f64 {
        match self {
            Self::Identity => value,
            Self::Log1p => value.ln_1p(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Feature {
    pub(crate) name: &'static str,
    pub(crate) group: FeatureGroup,
    pub(crate) transform: Transform,
    getter: fn(&ConnectionMetrics) -> Option<f64>,
}

pub(crate) const FEATURES: [Feature; 9] = [
    Feature {
        name: "duration_ms",
        group: FeatureGroup::Workload,
        transform: Transform::Log1p,
        getter: ConnectionMetrics::duration_ms,
    },
    Feature {
        name: "total_bytes",
        group: FeatureGroup::Workload,
        transform: Transform::Log1p,
        getter: |connection| Some(connection.total_bytes() as f64),
    },
    Feature {
        name: "total_packets",
        group: FeatureGroup::Workload,
        transform: Transform::Log1p,
        getter: |connection| Some(connection.total_packets() as f64),
    },
    Feature {
        name: "client_bidi_streams",
        group: FeatureGroup::Workload,
        transform: Transform::Log1p,
        getter: |connection| Some(connection.client_bidi_streams() as f64),
    },
    Feature {
        name: "smoothed_rtt_median_ms",
        group: FeatureGroup::Network,
        transform: Transform::Identity,
        getter: ConnectionMetrics::smoothed_rtt_median_ms,
    },
    Feature {
        name: "loss_rate_pct",
        group: FeatureGroup::Network,
        transform: Transform::Identity,
        getter: ConnectionMetrics::loss_rate_pct,
    },
    Feature {
        name: "pto_per_1000_packets",
        group: FeatureGroup::Network,
        transform: Transform::Log1p,
        getter: ConnectionMetrics::pto_per_1000_packets,
    },
    Feature {
        name: "blocked_events",
        group: FeatureGroup::Network,
        transform: Transform::Log1p,
        getter: |connection| Some(connection.blocked_events as f64),
    },
    Feature {
        name: "migrations_completed",
        group: FeatureGroup::Network,
        transform: Transform::Log1p,
        getter: |connection| Some(connection.migrations_completed as f64),
    },
];

#[derive(Clone, Debug)]
pub(crate) struct Summary {
    pub(crate) count: usize,
    pub(crate) min: f64,
    pub(crate) p05: f64,
    pub(crate) p25: f64,
    pub(crate) median: f64,
    pub(crate) mean: f64,
    pub(crate) p75: f64,
    pub(crate) p95: f64,
    pub(crate) max: f64,
    pub(crate) mad: f64,
}

#[derive(Clone, Debug)]
pub(crate) struct Distribution {
    pub(crate) feature: Feature,
    pub(crate) raw: Option<Summary>,
    pub(crate) model: Option<Summary>,
    pub(crate) model_scale: Option<f64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OutlierKind {
    Workload,
    Network,
    Both,
}

impl fmt::Display for OutlierKind {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        let value = match self {
            Self::Workload => "workload",
            Self::Network => "network",
            Self::Both => "both",
        };

        formatter.write_str(value)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct AnalyzedConnection {
    pub(crate) metrics: ConnectionMetrics,
    pub(crate) feature_z_scores: Vec<Option<f64>>,
    pub(crate) workload_score: Option<f64>,
    pub(crate) network_score: Option<f64>,
    pub(crate) typicality_score: Option<f64>,
    pub(crate) max_abs_z: Option<f64>,
    pub(crate) strongest_feature: Option<&'static str>,
    pub(crate) outlier_kind: Option<OutlierKind>,
}

#[derive(Debug)]
pub(crate) struct Analysis {
    pub(crate) connections: Vec<AnalyzedConnection>,
    pub(crate) distributions: Vec<Distribution>,
    pub(crate) representative: Option<usize>,
    pub(crate) threshold: f64,
}

pub(crate) fn analyze(
    connections: Vec<ConnectionMetrics>, threshold: f64,
) -> Analysis {
    let distributions = FEATURES
        .iter()
        .copied()
        .map(|feature| distribution(feature, &connections))
        .collect::<Vec<_>>();

    let mut analyzed = connections
        .into_iter()
        .map(|metrics| {
            let feature_z_scores = FEATURES
                .iter()
                .zip(&distributions)
                .map(|(feature, distribution)| {
                    let value = (feature.getter)(&metrics)?;
                    let center = distribution.model.as_ref()?.median;
                    let scale = distribution.model_scale?;
                    Some(robust_z(feature.transform.apply(value), center, scale))
                })
                .collect::<Vec<_>>();

            let workload_score =
                group_score(&feature_z_scores, Some(FeatureGroup::Workload));
            let network_score =
                group_score(&feature_z_scores, Some(FeatureGroup::Network));
            let typicality_score = group_score(&feature_z_scores, None);
            let (strongest_feature, max_abs_z) = strongest(&feature_z_scores);

            let workload_outlier = group_is_outlier(
                &feature_z_scores,
                workload_score,
                FeatureGroup::Workload,
                threshold,
            );
            let network_outlier = group_is_outlier(
                &feature_z_scores,
                network_score,
                FeatureGroup::Network,
                threshold,
            );
            let outlier_kind = match (workload_outlier, network_outlier) {
                (true, true) => Some(OutlierKind::Both),
                (true, false) => Some(OutlierKind::Workload),
                (false, true) => Some(OutlierKind::Network),
                (false, false) => None,
            };

            AnalyzedConnection {
                metrics,
                feature_z_scores,
                workload_score,
                network_score,
                typicality_score,
                max_abs_z,
                strongest_feature,
                outlier_kind,
            }
        })
        .collect::<Vec<_>>();

    analyzed.sort_by(|a, b| a.metrics.path.cmp(&b.metrics.path));
    let representative = representative_index(&analyzed);

    Analysis {
        connections: analyzed,
        distributions,
        representative,
        threshold,
    }
}

fn distribution(
    feature: Feature, connections: &[ConnectionMetrics],
) -> Distribution {
    let raw_values = connections
        .iter()
        .filter_map(feature.getter)
        .filter(|value| value.is_finite())
        .collect::<Vec<_>>();
    let model_values = raw_values
        .iter()
        .copied()
        .map(|value| feature.transform.apply(value))
        .filter(|value| value.is_finite())
        .collect::<Vec<_>>();
    let raw = summarize(&raw_values);
    let model = summarize(&model_values);
    let model_scale =
        model.as_ref().map(|summary| summary.mad * MAD_NORMAL_SCALE);

    Distribution {
        feature,
        raw,
        model,
        model_scale,
    }
}

fn summarize(values: &[f64]) -> Option<Summary> {
    if values.is_empty() {
        return None;
    }

    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let median = percentile_sorted(&sorted, 0.5)?;
    let mut absolute_deviations = sorted
        .iter()
        .map(|value| (value - median).abs())
        .collect::<Vec<_>>();
    absolute_deviations.sort_by(f64::total_cmp);
    let mad = percentile_sorted(&absolute_deviations, 0.5)?;
    let mean = sorted.iter().sum::<f64>() / sorted.len() as f64;

    Some(Summary {
        count: sorted.len(),
        min: *sorted.first()?,
        p05: percentile_sorted(&sorted, 0.05)?,
        p25: percentile_sorted(&sorted, 0.25)?,
        median,
        mean,
        p75: percentile_sorted(&sorted, 0.75)?,
        p95: percentile_sorted(&sorted, 0.95)?,
        max: *sorted.last()?,
        mad,
    })
}

pub(crate) fn percentile_sorted(sorted: &[f64], percentile: f64) -> Option<f64> {
    if sorted.is_empty() || !(0.0..=1.0).contains(&percentile) {
        return None;
    }

    if sorted.len() == 1 {
        return Some(sorted[0]);
    }

    let rank = percentile * (sorted.len() - 1) as f64;
    let lower = rank.floor() as usize;
    let upper = rank.ceil() as usize;
    let fraction = rank - lower as f64;

    Some(sorted[lower] + (sorted[upper] - sorted[lower]) * fraction)
}

fn robust_z(value: f64, center: f64, scale: f64) -> f64 {
    if scale > f64::EPSILON {
        return (value - center) / scale;
    }

    let tolerance = f64::EPSILON * center.abs().max(value.abs()).max(1.0) * 4.0;
    let difference = value - center;
    if difference.abs() <= tolerance {
        0.0
    } else {
        difference.signum() * f64::INFINITY
    }
}

fn group_score(
    z_scores: &[Option<f64>], group: Option<FeatureGroup>,
) -> Option<f64> {
    let values = z_scores
        .iter()
        .enumerate()
        .filter(|(index, _)| {
            group.is_none_or(|group| FEATURES[*index].group == group)
        })
        .filter_map(|(_, value)| *value)
        .collect::<Vec<_>>();

    if values.is_empty() {
        return None;
    }

    if values.iter().any(|value| value.is_infinite()) {
        return Some(f64::INFINITY);
    }

    Some(
        (values.iter().map(|value| value * value).sum::<f64>() /
            values.len() as f64)
            .sqrt(),
    )
}

fn strongest(z_scores: &[Option<f64>]) -> (Option<&'static str>, Option<f64>) {
    z_scores
        .iter()
        .enumerate()
        .filter_map(|(index, value)| value.map(|value| (index, value.abs())))
        .max_by(|a, b| a.1.total_cmp(&b.1))
        .map_or((None, None), |(index, value)| {
            (Some(FEATURES[index].name), Some(value))
        })
}

fn group_is_outlier(
    z_scores: &[Option<f64>], score: Option<f64>, group: FeatureGroup,
    threshold: f64,
) -> bool {
    score.is_some_and(|score| score >= threshold) ||
        z_scores.iter().enumerate().any(|(index, value)| {
            FEATURES[index].group == group &&
                value.is_some_and(|value| value.abs() >= threshold)
        })
}

fn representative_index(connections: &[AnalyzedConnection]) -> Option<usize> {
    connections
        .iter()
        .enumerate()
        .filter(|(_, connection)| connection.workload_score.is_some())
        .min_by(|(_, a), (_, b)| representative_cmp(a, b))
        .map(|(index, _)| index)
}

fn representative_cmp(
    a: &AnalyzedConnection, b: &AnalyzedConnection,
) -> Ordering {
    let workload = a
        .workload_score
        .unwrap_or(f64::INFINITY)
        .total_cmp(&b.workload_score.unwrap_or(f64::INFINITY));
    if workload != Ordering::Equal {
        return workload;
    }

    let typicality = a
        .typicality_score
        .unwrap_or(f64::INFINITY)
        .total_cmp(&b.typicality_score.unwrap_or(f64::INFINITY));
    if typicality != Ordering::Equal {
        return typicality;
    }

    a.metrics.path.cmp(&b.metrics.path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connection(path: &str, bytes: u64, rtt: f64) -> ConnectionMetrics {
        ConnectionMetrics {
            path: path.into(),
            title: None,
            vantage_point: "server".into(),
            file_size_bytes: 0,
            event_count: 2,
            start_time_ms: Some(0.0),
            end_time_ms: Some(100.0),
            packets_sent: 10,
            packets_received: 10,
            packet_lost_events: 0,
            cf_lost_packets: Some(0),
            bytes_sent: bytes,
            bytes_received: 0,
            packet_size_missing_sent: 0,
            packet_size_missing_received: 0,
            unique_streams: 1,
            client_bidi_streams: 1,
            smoothed_rtt_sample_count: 1,
            smoothed_rtt_median_ms: Some(rtt),
            smoothed_rtt_p95_ms: Some(rtt),
            smoothed_rtt_final_ms: Some(rtt),
            rtt_variance_final_ms: Some(1.0),
            min_rtt_final_ms: Some(rtt),
            congestion_window_final_bytes: Some(12_000),
            congestion_window_max_bytes: Some(12_000),
            bytes_in_flight_max: Some(1_200),
            pto_inferred_count: 0,
            pto_timer_expirations: 0,
            pto_max_consecutive: 0,
            blocked_events: 0,
            migration_events: 0,
            migrations_completed: 0,
            handshake_completed: true,
            handshake_confirmed: true,
            close_initiator: None,
            close_trigger: Some("clean".into()),
            close_reason: None,
            close_error: None,
        }
    }

    #[test]
    fn percentile_uses_linear_interpolation() {
        assert_eq!(percentile_sorted(&[0.0, 10.0], 0.5), Some(5.0));
        assert_eq!(percentile_sorted(&[3.0], 0.95), Some(3.0));
        assert_eq!(percentile_sorted(&[], 0.5), None);
    }

    #[test]
    fn large_download_is_a_workload_outlier() {
        let mut connections = (0..9)
            .map(|index| connection(&format!("normal-{index}"), 10_000, 20.0))
            .collect::<Vec<_>>();
        connections.push(connection("download", 8_000_000_000, 20.0));

        let analysis = analyze(connections, 3.5);
        let download = analysis
            .connections
            .iter()
            .find(|connection| connection.metrics.path == "download")
            .unwrap();

        assert_eq!(download.outlier_kind, Some(OutlierKind::Workload));
    }

    #[test]
    fn zero_mad_marks_a_different_value_as_an_outlier() {
        assert_eq!(robust_z(1.0, 1.0, 0.0), 0.0);
        assert_eq!(robust_z(2.0, 1.0, 0.0), f64::INFINITY);
    }
}
