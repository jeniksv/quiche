# qlog-analyzer

`qlog-analyzer` performs batch analysis of sequential qlog traces. It scans an
input directory recursively, treats every qlog trace as one QUIC connection,
and writes connection-level metrics, population distributions, and robust
outlier classifications.

The analyzer uses the workspace `qlog` crate and its streaming
`QlogSeqReader`; an entire trace is therefore never loaded into memory. Raw
`.sqlog`, gzip-compressed `.sqlog.gz`, and zstd-compressed `.sqlog.zst` files
are supported.

## Build and run

```shell
cargo build --release -p qlog-analyzer

target/release/qlog-analyzer /path/to/qlogs
```

By default, results are written to `qlog-analysis` in the current directory.
Choose another directory or outlier threshold with:

```shell
target/release/qlog-analyzer /path/to/qlogs \
  --output /tmp/qlog-analysis \
  --outlier-threshold 3.5
```

A single supported qlog file can be passed instead of a directory.

## Output

The output directory contains:

| File | Contents |
|---|---|
| `connections.csv` | One row per successfully parsed connection, including all raw metrics, scores, and per-feature robust z-scores. |
| `distributions.csv` | Population summary for every feature: percentiles, mean, median, MAD, and the transformed model center/scale. |
| `outliers.csv` | Only connections that cross the configured threshold, sorted by their strongest deviation. |
| `failures.csv` | Files whose qlog header could not be parsed or opened. |
| `report.md` | Human-readable summary, representative connection, distributions, and the 25 strongest outliers. |

Missing qlog fields are emitted as empty CSV cells rather than being treated as
zero. Output ordering is deterministic.

## Connection metrics

Workload/shape metrics include connection duration, bytes, packets, unique
stream IDs, and unique client-initiated bidirectional streams. For server-side
HTTP/3 traces, a client-initiated bidirectional stream (`stream_id % 4 == 0`)
is a useful request-count proxy. It is still only a proxy: a non-HTTP/3 QUIC
application can use the same stream class for other purposes.

Network/recovery metrics include:

- median, p95, and final observed smoothed RTT;
- final RTT variance and minimum RTT;
- final/max congestion window and maximum bytes in flight;
- lost packets and loss rate;
- PTO count, maximum consecutive PTO level, and PTOs per 1000 sent packets;
- blocked transitions and completed migrations;
- handshake and connection-close information.

Byte totals sum `raw.length` on `packet_sent` and `packet_received` events.
Separate counters show packets for which this field was absent. Lost packets
use the larger of the number of `packet_lost` events and quiche's final
`cf_lost_packets.total` recovery counter, because either source can be absent at
a selected qlog importance level.

The qlog `pto_count` field is the current consecutive PTO level, not a lifetime
counter. When explicit expired PTO timer events are unavailable, the analyzer
estimates the lifetime count by summing positive changes of that level. RTT
percentiles describe values present in `recovery_metrics_updated` events; they
are not time-weighted samples.

## Typical connection and outliers

Production traffic is usually heavy-tailed, so an arithmetic mean often does
not resemble a real connection. `qlog-analyzer` computes a median and median
absolute deviation (MAD) for each feature. Heavy-tailed count/volume features
are transformed with `log1p` first. The robust z-score is:

```text
z = (transformed_value - median) / (1.4826 * MAD)
```

The workload, network, and combined typicality scores are the root mean square
of the available per-feature robust z-scores. A connection is an outlier if a
group score or any feature in that group reaches the configured threshold.
Workload and network outliers are labeled independently, so a large but healthy
download is not presented as a network failure.

The representative connection in `report.md` is an existing trace with the
smallest workload score, with combined typicality used as a tie-breaker. This
is medoid-like selection around the robust population center, not a synthetic
connection made from averages.

If MAD is zero, values equal to the median receive a z-score of zero and any
different value receives an infinite z-score. This deliberately detects a rare
non-zero event in a population dominated by exact zeros. Results are most
meaningful for reasonably sized, comparable cohorts; future grouping or
feature selection can be layered on top of `connections.csv` without parsing
the qlogs again.
