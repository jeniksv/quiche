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

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use anyhow::Context;
use anyhow::Result;
use qlog::events::http3::Http3Frame;
use qlog::events::quic::BlockedState;
use qlog::events::quic::ConnectionState;
use qlog::events::quic::MigrationState;
use qlog::events::quic::QuicFrame;
use qlog::events::quic::TimerEventType;
use qlog::events::quic::TimerType;
use qlog::events::EventData;
use qlog::reader::Event as ReaderEvent;
use qlog::reader::QlogSeqReader;
use qlog::TimeFormat;
use qlog::VantagePointType;
use serde::Serialize;
use serde_json::Value;

use crate::stats::percentile_sorted;

#[derive(Clone, Debug)]
pub(crate) struct ConnectionMetrics {
    pub(crate) path: String,
    pub(crate) title: Option<String>,
    pub(crate) vantage_point: String,
    pub(crate) file_size_bytes: u64,
    pub(crate) event_count: u64,
    pub(crate) start_time_ms: Option<f64>,
    pub(crate) end_time_ms: Option<f64>,
    pub(crate) packets_sent: u64,
    pub(crate) packets_received: u64,
    pub(crate) packet_lost_events: u64,
    pub(crate) cf_lost_packets: Option<u64>,
    pub(crate) bytes_sent: u64,
    pub(crate) bytes_received: u64,
    pub(crate) packet_size_missing_sent: u64,
    pub(crate) packet_size_missing_received: u64,
    pub(crate) unique_streams: usize,
    pub(crate) client_bidi_streams: usize,
    pub(crate) smoothed_rtt_sample_count: usize,
    pub(crate) smoothed_rtt_median_ms: Option<f64>,
    pub(crate) smoothed_rtt_p95_ms: Option<f64>,
    pub(crate) smoothed_rtt_final_ms: Option<f64>,
    pub(crate) rtt_variance_final_ms: Option<f64>,
    pub(crate) min_rtt_final_ms: Option<f64>,
    pub(crate) congestion_window_final_bytes: Option<u64>,
    pub(crate) congestion_window_max_bytes: Option<u64>,
    pub(crate) bytes_in_flight_max: Option<u64>,
    pub(crate) pto_inferred_count: u64,
    pub(crate) pto_timer_expirations: u64,
    pub(crate) pto_max_consecutive: u64,
    pub(crate) blocked_events: u64,
    pub(crate) migration_events: u64,
    pub(crate) migrations_completed: u64,
    pub(crate) handshake_completed: bool,
    pub(crate) handshake_confirmed: bool,
    pub(crate) close_initiator: Option<String>,
    pub(crate) close_trigger: Option<String>,
    pub(crate) close_reason: Option<String>,
    pub(crate) close_error: Option<String>,
}

impl ConnectionMetrics {
    pub(crate) fn duration_ms(&self) -> Option<f64> {
        Some((self.end_time_ms? - self.start_time_ms?).max(0.0))
    }

    pub(crate) fn packets_lost(&self) -> u64 {
        self.cf_lost_packets
            .unwrap_or_default()
            .max(self.packet_lost_events)
    }

    pub(crate) fn loss_rate_pct(&self) -> Option<f64> {
        if self.packets_sent == 0 {
            return None;
        }

        Some(self.packets_lost() as f64 * 100.0 / self.packets_sent as f64)
    }

    pub(crate) fn total_packets(&self) -> u64 {
        self.packets_sent.saturating_add(self.packets_received)
    }

    pub(crate) fn total_bytes(&self) -> u64 {
        self.bytes_sent.saturating_add(self.bytes_received)
    }

    pub(crate) fn unique_streams(&self) -> usize {
        self.unique_streams
    }

    pub(crate) fn client_bidi_streams(&self) -> usize {
        self.client_bidi_streams
    }

    pub(crate) fn smoothed_rtt_median_ms(&self) -> Option<f64> {
        self.smoothed_rtt_median_ms
    }

    pub(crate) fn smoothed_rtt_p95_ms(&self) -> Option<f64> {
        self.smoothed_rtt_p95_ms
    }

    pub(crate) fn pto_count(&self) -> u64 {
        if self.pto_timer_expirations > 0 {
            self.pto_timer_expirations
        } else {
            self.pto_inferred_count
        }
    }

    pub(crate) fn pto_per_1000_packets(&self) -> Option<f64> {
        if self.packets_sent == 0 {
            return None;
        }

        Some(self.pto_count() as f64 * 1000.0 / self.packets_sent as f64)
    }
}

struct Accumulator {
    connection: ConnectionMetrics,
    previous_event_time_ms: f64,
    previous_pto_level: u64,
    stream_ids: BTreeSet<u64>,
    smoothed_rtt_samples_ms: Vec<f64>,
}

impl Accumulator {
    fn new(
        path: String, title: Option<String>, vantage_point: String,
        file_size_bytes: u64,
    ) -> Self {
        Self {
            connection: ConnectionMetrics {
                path,
                title,
                vantage_point,
                file_size_bytes,
                event_count: 0,
                start_time_ms: None,
                end_time_ms: None,
                packets_sent: 0,
                packets_received: 0,
                packet_lost_events: 0,
                cf_lost_packets: None,
                bytes_sent: 0,
                bytes_received: 0,
                packet_size_missing_sent: 0,
                packet_size_missing_received: 0,
                unique_streams: 0,
                client_bidi_streams: 0,
                smoothed_rtt_sample_count: 0,
                smoothed_rtt_median_ms: None,
                smoothed_rtt_p95_ms: None,
                smoothed_rtt_final_ms: None,
                rtt_variance_final_ms: None,
                min_rtt_final_ms: None,
                congestion_window_final_bytes: None,
                congestion_window_max_bytes: None,
                bytes_in_flight_max: None,
                pto_inferred_count: 0,
                pto_timer_expirations: 0,
                pto_max_consecutive: 0,
                blocked_events: 0,
                migration_events: 0,
                migrations_completed: 0,
                handshake_completed: false,
                handshake_confirmed: false,
                close_initiator: None,
                close_trigger: None,
                close_reason: None,
                close_error: None,
            },
            previous_event_time_ms: 0.0,
            previous_pto_level: 0,
            stream_ids: BTreeSet::new(),
            smoothed_rtt_samples_ms: Vec::new(),
        }
    }

    fn finish(mut self) -> ConnectionMetrics {
        self.connection.unique_streams = self.stream_ids.len();
        self.connection.client_bidi_streams =
            self.stream_ids.iter().filter(|id| *id % 4 == 0).count();

        self.smoothed_rtt_samples_ms.sort_by(f64::total_cmp);
        self.connection.smoothed_rtt_sample_count =
            self.smoothed_rtt_samples_ms.len();
        self.connection.smoothed_rtt_median_ms =
            percentile_sorted(&self.smoothed_rtt_samples_ms, 0.5);
        self.connection.smoothed_rtt_p95_ms =
            percentile_sorted(&self.smoothed_rtt_samples_ms, 0.95);

        self.connection
    }

    fn begin_event(&mut self, time_ms: f64, time_format: &TimeFormat) {
        let absolute_time_ms = match time_format {
            TimeFormat::RelativeToEpoch => time_ms,
            TimeFormat::RelativeToPreviousEvent =>
                self.previous_event_time_ms + time_ms,
        };

        self.previous_event_time_ms = absolute_time_ms;
        self.connection.event_count += 1;
        self.connection.start_time_ms = Some(
            self.connection
                .start_time_ms
                .map_or(absolute_time_ms, |start| start.min(absolute_time_ms)),
        );
        self.connection.end_time_ms = Some(
            self.connection
                .end_time_ms
                .map_or(absolute_time_ms, |end| end.max(absolute_time_ms)),
        );
    }

    fn observe_event_data(&mut self, data: &EventData) {
        match data {
            EventData::QuicPacketSent(packet) => {
                self.connection.packets_sent += 1;
                if let Some(length) =
                    packet.raw.as_ref().and_then(|raw| raw.length)
                {
                    self.connection.bytes_sent =
                        self.connection.bytes_sent.saturating_add(length);
                } else {
                    self.connection.packet_size_missing_sent += 1;
                }
                self.observe_quic_frames(packet.frames.as_deref());
            },

            EventData::QuicPacketReceived(packet) => {
                self.connection.packets_received += 1;
                if let Some(length) =
                    packet.raw.as_ref().and_then(|raw| raw.length)
                {
                    self.connection.bytes_received =
                        self.connection.bytes_received.saturating_add(length);
                } else {
                    self.connection.packet_size_missing_received += 1;
                }
                self.observe_quic_frames(packet.frames.as_deref());
            },

            EventData::QuicPacketLost(packet) => {
                self.connection.packet_lost_events += 1;
                self.observe_quic_frames(packet.frames.as_deref());
            },

            EventData::QuicMarkedForRetransmit(event) =>
                self.observe_quic_frames(Some(&event.frames)),

            EventData::QuicFramesProcessed(event) =>
                self.observe_quic_frames(Some(&event.frames)),

            EventData::QuicStreamStateUpdated(event) => {
                self.stream_ids.insert(event.stream_id);
            },

            EventData::QuicStreamDataMoved(event) => {
                if let Some(stream_id) = event.stream_id {
                    self.stream_ids.insert(stream_id);
                }
            },

            EventData::QuicStreamDataBlockedUpdated(event) => {
                self.stream_ids.insert(event.stream_id);
                if is_newly_blocked(&event.old, &event.new) {
                    self.connection.blocked_events += 1;
                }
            },

            EventData::QuicConnectionDataBlockedUpdated(event) =>
                if is_newly_blocked(&event.old, &event.new) {
                    self.connection.blocked_events += 1;
                },

            EventData::QuicDatagramDataBlockedUpdated(event) =>
                if is_newly_blocked(&event.old, &event.new) {
                    self.connection.blocked_events += 1;
                },

            EventData::QuicMigrationStateUpdated(event) => {
                self.connection.migration_events += 1;
                if matches!(&event.new, MigrationState::MigrationComplete) {
                    self.connection.migrations_completed += 1;
                }
            },

            EventData::QuicConnectionStateUpdated(event) => match &event.new {
                ConnectionState::HandshakeCompleted =>
                    self.connection.handshake_completed = true,

                ConnectionState::HandshakeConfirmed => {
                    self.connection.handshake_completed = true;
                    self.connection.handshake_confirmed = true;
                },

                _ => {},
            },

            EventData::QuicConnectionClosed(event) => {
                self.connection.close_initiator =
                    event.initiator.as_ref().and_then(serialized_text);
                self.connection.close_trigger =
                    event.trigger.as_ref().and_then(serialized_text);
                self.connection.close_reason.clone_from(&event.reason);

                let mut errors = Vec::new();
                if let Some(error) =
                    event.connection_error.as_ref().and_then(serialized_text)
                {
                    errors.push(error);
                }
                if let Some(error) =
                    event.application_error.as_ref().and_then(serialized_text)
                {
                    errors.push(error);
                }
                if let Some(code) = event.error_code {
                    errors.push(format!("error_code={code}"));
                }
                if let Some(code) = event.internal_code {
                    errors.push(format!("internal_code={code}"));
                }
                self.connection.close_error =
                    (!errors.is_empty()).then(|| errors.join("; "));
            },

            EventData::QuicMetricsUpdated(event) => {
                if let Some(value) = event.smoothed_rtt {
                    self.observe_smoothed_rtt(value as f64);
                }
                if let Some(value) = event.rtt_variance {
                    self.connection.rtt_variance_final_ms = Some(value as f64);
                }
                if let Some(value) = event.min_rtt {
                    self.connection.min_rtt_final_ms = Some(value as f64);
                }
                if let Some(value) = event.congestion_window {
                    self.connection.congestion_window_final_bytes = Some(value);
                    update_max(
                        &mut self.connection.congestion_window_max_bytes,
                        value,
                    );
                }
                if let Some(value) = event.bytes_in_flight {
                    update_max(&mut self.connection.bytes_in_flight_max, value);
                }
                if let Some(value) = event.pto_count {
                    self.observe_pto_level(value as u64);
                }
                if let Some(value) =
                    event.ex_data.get("cf_lost_packets").and_then(total_counter)
                {
                    update_max(&mut self.connection.cf_lost_packets, value);
                }
            },

            EventData::QuicTimerUpdated(event) => {
                if matches!(event.timer_type.as_ref(), Some(TimerType::Pto)) &&
                    matches!(&event.event_type, TimerEventType::Expired)
                {
                    self.connection.pto_timer_expirations += 1;
                }
            },

            EventData::Http3StreamTypeSet(event) => {
                self.stream_ids.insert(event.stream_id);
            },

            EventData::Http3PriorityUpdated(event) => {
                if let Some(stream_id) = event.stream_id {
                    self.stream_ids.insert(stream_id);
                }
            },

            EventData::Http3FrameCreated(event) => {
                self.stream_ids.insert(event.stream_id);
                self.observe_h3_frame(&event.frame);
            },

            EventData::Http3FrameParsed(event) => {
                self.stream_ids.insert(event.stream_id);
                self.observe_h3_frame(&event.frame);
            },

            EventData::Http3DatagramCreated(event) =>
                self.observe_quarter_stream_id(event.quarter_stream_id),

            EventData::Http3DatagramParsed(event) =>
                self.observe_quarter_stream_id(event.quarter_stream_id),

            EventData::Http3PushResolved(event) => {
                if let Some(stream_id) = event.stream_id {
                    self.stream_ids.insert(stream_id);
                }
            },

            _ => {},
        }
    }

    fn observe_quic_frames(&mut self, frames: Option<&[QuicFrame]>) {
        let Some(frames) = frames else {
            return;
        };

        for frame in frames {
            match frame {
                QuicFrame::ResetStream { stream_id, .. } |
                QuicFrame::StopSending { stream_id, .. } |
                QuicFrame::Stream { stream_id, .. } |
                QuicFrame::MaxStreamData { stream_id, .. } |
                QuicFrame::StreamDataBlocked { stream_id, .. } => {
                    self.stream_ids.insert(*stream_id);
                },

                QuicFrame::HandshakeDone { .. } => {
                    self.connection.handshake_completed = true;
                    self.connection.handshake_confirmed = true;
                },

                _ => {},
            }
        }
    }

    fn observe_h3_frame(&mut self, frame: &Http3Frame) {
        if let Http3Frame::PriorityUpdate {
            stream_id: Some(stream_id),
            ..
        } = frame
        {
            self.stream_ids.insert(*stream_id);
        }
    }

    fn observe_quarter_stream_id(&mut self, quarter_stream_id: u64) {
        if let Some(stream_id) = quarter_stream_id.checked_mul(4) {
            self.stream_ids.insert(stream_id);
        }
    }

    fn observe_smoothed_rtt(&mut self, value: f64) {
        if value.is_finite() && value >= 0.0 {
            self.smoothed_rtt_samples_ms.push(value);
            self.connection.smoothed_rtt_final_ms = Some(value);
        }
    }

    fn observe_pto_level(&mut self, value: u64) {
        if value > self.previous_pto_level {
            self.connection.pto_inferred_count = self
                .connection
                .pto_inferred_count
                .saturating_add(value - self.previous_pto_level);
        }
        self.previous_pto_level = value;
        self.connection.pto_max_consecutive =
            self.connection.pto_max_consecutive.max(value);
    }

    fn observe_json_event(&mut self, name: &str, data: &Value) {
        collect_json_stream_ids(data, &mut self.stream_ids);
        if contains_frame_type(data, "handshake_done") {
            self.connection.handshake_completed = true;
            self.connection.handshake_confirmed = true;
        }

        match name.rsplit(':').next().unwrap_or(name) {
            "packet_sent" => {
                self.connection.packets_sent += 1;
                if let Some(length) = json_u64(data.get("raw"), "length") {
                    self.connection.bytes_sent =
                        self.connection.bytes_sent.saturating_add(length);
                } else {
                    self.connection.packet_size_missing_sent += 1;
                }
            },

            "packet_received" => {
                self.connection.packets_received += 1;
                if let Some(length) = json_u64(data.get("raw"), "length") {
                    self.connection.bytes_received =
                        self.connection.bytes_received.saturating_add(length);
                } else {
                    self.connection.packet_size_missing_received += 1;
                }
            },

            "packet_lost" => self.connection.packet_lost_events += 1,

            "metrics_updated" | "recovery_metrics_updated" => {
                if let Some(value) = json_f64(data.get("smoothed_rtt")) {
                    self.observe_smoothed_rtt(value);
                }
                if let Some(value) = json_f64(data.get("rtt_variance")) {
                    self.connection.rtt_variance_final_ms = Some(value);
                }
                if let Some(value) = json_f64(data.get("min_rtt")) {
                    self.connection.min_rtt_final_ms = Some(value);
                }
                if let Some(value) = json_u64(Some(data), "congestion_window") {
                    self.connection.congestion_window_final_bytes = Some(value);
                    update_max(
                        &mut self.connection.congestion_window_max_bytes,
                        value,
                    );
                }
                if let Some(value) = json_u64(Some(data), "bytes_in_flight") {
                    update_max(&mut self.connection.bytes_in_flight_max, value);
                }
                if let Some(value) = json_u64(Some(data), "pto_count") {
                    self.observe_pto_level(value);
                }
                if let Some(value) =
                    data.get("cf_lost_packets").and_then(total_counter)
                {
                    update_max(&mut self.connection.cf_lost_packets, value);
                }
            },

            "timer_updated" => {
                if data.get("timer_type").and_then(Value::as_str) == Some("pto") &&
                    data.get("event_type").and_then(Value::as_str) ==
                        Some("expired")
                {
                    self.connection.pto_timer_expirations += 1;
                }
            },

            "connection_data_blocked_updated" |
            "stream_data_blocked_updated" |
            "datagram_data_blocked_updated" => {
                let old = data.get("old").and_then(Value::as_str);
                let new = data.get("new").and_then(Value::as_str);
                if new == Some("blocked") && old != Some("blocked") {
                    self.connection.blocked_events += 1;
                }
            },

            "migration_state_updated" => {
                self.connection.migration_events += 1;
                if data.get("new").and_then(Value::as_str) ==
                    Some("migration_complete")
                {
                    self.connection.migrations_completed += 1;
                }
            },

            "connection_state_updated" => {
                match data.get("new").and_then(Value::as_str) {
                    Some("handshake_completed") =>
                        self.connection.handshake_completed = true,

                    Some("handshake_confirmed") => {
                        self.connection.handshake_completed = true;
                        self.connection.handshake_confirmed = true;
                    },

                    _ => {},
                }
            },

            "connection_closed" => {
                self.connection.close_initiator =
                    data.get("initiator").and_then(json_text);
                self.connection.close_trigger =
                    data.get("trigger").and_then(json_text);
                self.connection.close_reason =
                    data.get("reason").and_then(json_text);

                let mut errors = Vec::new();
                for field in ["connection_error", "application_error"] {
                    if let Some(error) = data.get(field).and_then(json_text) {
                        errors.push(error);
                    }
                }
                for field in ["error_code", "internal_code"] {
                    if let Some(code) = data.get(field).and_then(json_text) {
                        errors.push(format!("{field}={code}"));
                    }
                }
                self.connection.close_error =
                    (!errors.is_empty()).then(|| errors.join("; "));
            },

            _ => {},
        }
    }
}

pub(crate) fn parse_connection(
    path: &Path, display_path: String,
) -> Result<ConnectionMetrics> {
    let file_size_bytes = fs::metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?
        .len();
    let mut reader = QlogSeqReader::with_file(path).map_err(|error| {
        anyhow::anyhow!("failed to open {}: {error}", path.display())
    })?;

    let title = reader
        .qlog
        .trace
        .title
        .clone()
        .or_else(|| reader.qlog.title.clone());
    let vantage_point = reader
        .qlog
        .trace
        .vantage_point
        .as_ref()
        .map(|vantage| vantage_name(&vantage.ty))
        .unwrap_or_else(|| "unknown".to_string());
    let common_time_format = reader
        .qlog
        .trace
        .common_fields
        .as_ref()
        .and_then(|fields| fields.time_format.clone())
        .unwrap_or_default();

    let mut accumulator =
        Accumulator::new(display_path, title, vantage_point, file_size_bytes);

    for event in &mut reader {
        match event {
            ReaderEvent::Qlog(event) => {
                accumulator.begin_event(
                    event.time,
                    event.time_format.as_ref().unwrap_or(&common_time_format),
                );
                accumulator.observe_event_data(&event.data);
            },

            ReaderEvent::Json(event) => {
                accumulator.begin_event(event.time, &common_time_format);
                accumulator.observe_json_event(&event.name, &event.data);
            },
        }
    }

    Ok(accumulator.finish())
}

fn is_newly_blocked(old: &Option<BlockedState>, new: &BlockedState) -> bool {
    matches!(new, BlockedState::Blocked) &&
        !matches!(old, Some(BlockedState::Blocked))
}

fn update_max(slot: &mut Option<u64>, value: u64) {
    *slot = Some(slot.map_or(value, |current| current.max(value)));
}

fn total_counter(value: &Value) -> Option<u64> {
    value
        .get("total")
        .and_then(json_u64_value)
        .or_else(|| json_u64_value(value))
}

fn json_u64(object: Option<&Value>, field: &str) -> Option<u64> {
    object?.get(field).and_then(json_u64_value)
}

fn json_u64_value(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
}

fn json_f64(value: Option<&Value>) -> Option<f64> {
    let value = value?;
    let value = value
        .as_f64()
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))?;

    value.is_finite().then_some(value)
}

fn json_text(value: &Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::String(value) => Some(value.clone()),
        _ => Some(value.to_string()),
    }
}

fn serialized_text<T: Serialize>(value: &T) -> Option<String> {
    serde_json::to_value(value)
        .ok()
        .as_ref()
        .and_then(json_text)
}

fn vantage_name(vantage_point: &VantagePointType) -> String {
    match vantage_point {
        VantagePointType::Client => "client",
        VantagePointType::Server => "server",
        VantagePointType::Network => "network",
        VantagePointType::Unknown => "unknown",
    }
    .to_string()
}

fn collect_json_stream_ids(value: &Value, stream_ids: &mut BTreeSet<u64>) {
    match value {
        Value::Array(values) =>
            for value in values {
                collect_json_stream_ids(value, stream_ids);
            },

        Value::Object(values) =>
            for (key, value) in values {
                if key == "stream_id" {
                    if let Some(stream_id) = json_u64_value(value) {
                        stream_ids.insert(stream_id);
                    }
                } else if key == "quarter_stream_id" {
                    if let Some(stream_id) = json_u64_value(value)
                        .and_then(|value| value.checked_mul(4))
                    {
                        stream_ids.insert(stream_id);
                    }
                }

                collect_json_stream_ids(value, stream_ids);
            },

        _ => {},
    }
}

fn contains_frame_type(value: &Value, expected: &str) -> bool {
    match value {
        Value::Array(values) => values
            .iter()
            .any(|value| contains_frame_type(value, expected)),

        Value::Object(values) => {
            if values.get("frame_type").and_then(Value::as_str) == Some(expected)
            {
                return true;
            }

            values
                .values()
                .any(|value| contains_frame_type(value, expected))
        },

        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn parses_connection_metrics_from_sqlog() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("connection.sqlog");
        let mut file = fs::File::create(&path).unwrap();

        let records = [
            serde_json::json!({
                "file_schema": "urn:ietf:params:qlog:file:sequential",
                "serialization_format": "JSON-SEQ",
                "trace": {
                    "title": "test connection",
                    "vantage_point": {"type": "server"},
                    "event_schemas": []
                }
            }),
            serde_json::json!({
                "time": 10.0,
                "name": "quic:packet_sent",
                "data": {
                    "header": {"packet_type": "1RTT"},
                    "raw": {"length": 1200},
                    "frames": [
                        {"frame_type": "stream", "stream_id": 0},
                        {"frame_type": "stream", "stream_id": 4}
                    ]
                }
            }),
            serde_json::json!({
                "time": 20.0,
                "name": "quic:packet_received",
                "data": {
                    "header": {"packet_type": "1RTT"},
                    "raw": {"length": 800},
                    "frames": [{"frame_type": "handshake_done"}]
                }
            }),
            serde_json::json!({
                "time": 30.0,
                "name": "quic:recovery_metrics_updated",
                "data": {
                    "smoothed_rtt": 12.5,
                    "rtt_variance": 2.5,
                    "congestion_window": 24000,
                    "bytes_in_flight": 12000,
                    "pto_count": 2,
                    "cf_lost_packets": {"total": 3, "delta": 3}
                }
            }),
            serde_json::json!({
                "time": 40.0,
                "name": "quic:connection_closed",
                "data": {
                    "initiator": "remote",
                    "trigger": "clean",
                    "reason": "done"
                }
            }),
        ];

        for record in records {
            writeln!(file, "\u{1e}{record}").unwrap();
        }
        drop(file);

        let metrics =
            parse_connection(&path, "connection.sqlog".to_string()).unwrap();

        assert_eq!(metrics.title.as_deref(), Some("test connection"));
        assert_eq!(metrics.vantage_point, "server");
        assert_eq!(metrics.event_count, 4);
        assert_eq!(metrics.duration_ms(), Some(30.0));
        assert_eq!(metrics.packets_sent, 1);
        assert_eq!(metrics.packets_received, 1);
        assert_eq!(metrics.bytes_sent, 1200);
        assert_eq!(metrics.bytes_received, 800);
        assert_eq!(metrics.client_bidi_streams(), 2);
        assert_eq!(metrics.packets_lost(), 3);
        assert_eq!(metrics.pto_count(), 2);
        assert_eq!(metrics.smoothed_rtt_final_ms, Some(12.5));
        assert_eq!(metrics.congestion_window_max_bytes, Some(24000));
        assert!(metrics.handshake_confirmed);
        assert_eq!(metrics.close_trigger.as_deref(), Some("clean"));
    }

    #[test]
    fn relative_event_times_are_accumulated() {
        let mut accumulator =
            Accumulator::new("test".into(), None, "unknown".into(), 0);
        accumulator.begin_event(5.0, &TimeFormat::RelativeToPreviousEvent);
        accumulator.begin_event(7.0, &TimeFormat::RelativeToPreviousEvent);

        assert_eq!(accumulator.connection.start_time_ms, Some(5.0));
        assert_eq!(accumulator.connection.end_time_ms, Some(12.0));
        assert_eq!(accumulator.connection.duration_ms(), Some(7.0));
    }

    #[test]
    fn pto_inference_counts_positive_level_changes() {
        let mut accumulator =
            Accumulator::new("test".into(), None, "unknown".into(), 0);

        for level in [0, 1, 2, 0, 1, 0] {
            accumulator.observe_pto_level(level);
        }

        assert_eq!(accumulator.connection.pto_inferred_count, 3);
        assert_eq!(accumulator.connection.pto_max_consecutive, 2);
    }
}
