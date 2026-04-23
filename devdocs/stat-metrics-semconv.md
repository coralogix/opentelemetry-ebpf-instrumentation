# OTel Semantic Conventions Proposal

## Context

The `statso11y` subsystem is where we capture **stat metrics**: numeric observations read directly from the kernel via eBPF. It is one of 3 pipelines the agent runs: statso11y, appo11y, neto11y.

Today, statso11y emits exactly 2 user-facing stat metrics:

| Current name | Instrument | Unit | Source |
|---|---|---|---|
| `obi.stat.tcp.rtt` | Histogram | `s` | `kprobe/tcp_close` reading `tcp_sock.srtt_us` |
| `obi.stat.tcp.failed.connections` | Counter | `connection` | `sock/inet_sock_set_state` |

There is no entry in OTel semantic conventions for these metrics, nor for any other TCP- or UDP-specific stat metric. The existing `system.network.*` namespace covers transport-agnostic NIC-level counters (`system.network.io`, `system.network.connection.count`, `system.network.errors` and so on) but does not descend into protocol-specific detail.

We plan to expand statsolly's TCP and UDP coverage substantially. Before shipping those with new `obi.*` names we want to:

- retire the vendor prefix where possible
- align with existing OTel semantic conventions
- propose new semconv entries for what is not yet covered.

## Proposal

Add new TCP/UDP stat metrics to semconv by placing them under `system.network.*`, as sub-namespaces `system.network.tcp.*` and `system.network.udp.*`, alongside the existing transport-agnostic network metrics.

## Stat metrics vs OTel system metrics

What this project calls **stat metrics** and what OTel's semconv calls `system.*` metrics are the same kind of signal: kernel/OS-observed telemetry, typically counters of events or histograms of observed quantities (RTTs, byte counts, drops, error categories). In other words, OBI's "stat metrics" slot naturally into OTel's `system.*` namespace.

This proposal therefore positions statsolly's network-focused stat metrics as extensions to the existing `system.network.*` namespace, not as a parallel vendor space.

## Scope

- TCP stat metrics: TCP RTT, connection lifecycle, retransmits, resets and so on.
- UDP stat metrics (errors, queue drops, message payload size). Datagram *counts* reuse `system.network.packet.count{network.transport=udp}`.
- New attributes required to describe the above.

## Naming principles applied

From the semconv general metrics spec and existing precedent:

1. **Nest under `system.network.*`.** Existing stable semconv places network telemetry there; TCP/UDP sub-namespacing inside (`system.network.tcp.*`, `system.network.udp.*`) mirrors the `jvm.gc.*` / `jvm.memory.*` pattern of sub-namespacing within a stable root.
2. **No `.total` suffix** in OTel names (Prometheus exporter adds it).
3. **Units via UCUM**, not in the name: `By`, `s`, and grammatically-singular `{segment}`, `{connection}`, `{event}`, `{error}`, `{datagram}` for counts.
4. **Attributes over separate metrics** when aggregation across the attribute values is still a meaningful number. Separate metrics when events are semantically distinct.
5. **Reuse stable attributes** (`error.type`, `network.io.direction`, `network.transport`, `network.connection.state`) before inventing new ones.

## Namespace layout

```
system.network.*                              — existing stable root
  system.network.io                           — existing
  system.network.packet.count                 — existing
  system.network.packet.dropped               — existing
  system.network.errors                       — existing
  system.network.connection.count             — existing

  system.network.tcp.*                        — TCP metrics (NEW)
    system.network.tcp.connection.successes   
    system.network.tcp.connection.failures   (now called obi.stat.tcp.failed.connections)
    system.network.tcp.connection.duration
    system.network.tcp.handshake.duration
    system.network.tcp.rtt.duration          (now called obi.stat.tcp.rtt)
    system.network.tcp.retransmits
    system.network.tcp.resets

  system.network.udp.*                        — UDP metrics (NEW)
    system.network.udp.errors
    system.network.udp.queue.drops
    system.network.udp.message.size

network.*                                     — attribute root (unchanged)
  network.transport                           — existing
  network.io.direction                        — existing
  network.connection.state                    — existing
  network.tcp.handshake.role                  — NEW (client|server)
  network.tcp.retransmit.type                 — NEW (fast|tail_loss_probe|timeout|spurious)
  network.tcp.reset.cause                     — NEW, optional (application|timeout|unreachable|refused)
```

Note that metric names sit under `system.network.*` while attribute names sit under `network.*` — matching the existing semconv layout (e.g., metric `system.network.connection.count` carries attribute `network.connection.state`).

## Proposed new metrics — TCP (implemented)

### `system.network.tcp.rtt.duration`

- **Instrument**: Histogram
- **Unit**: `s`
- **Description**: Smoothed round-trip time (`srtt_us`) sampled at `tcp_close`. This supersedes `obi.stat.tcp.rtt`.
- **Attributes**: none required beyond resource attributes; may carry peer attributes where useful.

### `system.network.tcp.connection.failures`

- **Instrument**: Counter
- **Unit**: `{connection}`
- **Description**: TCP connection establishment attempts that did not reach `ESTABLISHED`.
- **Attributes**:
  - `error.type` — enum `unknown | refused | reset | timed-out | host-unreachable | net-unreachable | other` (reusing the stable `error.type` attribute used elsewhere in semconv). Now called `reason`.
  - (NEW) `network.tcp.handshake.role` (`client|server`)

## Proposed new metrics — TCP (in progress)

### `system.network.tcp.connection.successes`

- **Instrument**: Counter
- **Unit**: `{connection}`
- **Description**: TCP connections that completed handshake and reached `ESTABLISHED`.
- **Attributes**: `network.tcp.handshake.role` (`client|server`).

### `system.network.tcp.connection.duration`

- **Instrument**: Histogram
- **Unit**: `s`
- **Description**: Time from connection establishment to close, recorded at `tcp_close`.
- **Attributes**: `network.tcp.handshake.role`.

### `system.network.tcp.handshake.duration`

- **Instrument**: Histogram
- **Unit**: `s`
- **Description**: Time from `SYN` sent (active open) or `SYN` received (passive open) to handshake completion (`ESTABLISHED`).
- **Attributes**: `network.tcp.handshake.role`.

### `system.network.tcp.retransmits`

- **Instrument**: Counter
- **Unit**: `{segment}`
- **Description**: TCP segments retransmitted.
- **Attributes**: `network.tcp.retransmit.type` — enum `fast | tail_loss_probe | timeout | spurious`, aligned with kernel counters (`TCPFastRetrans`, `TCPLossProbes`, `TCPTimeouts`, `TCPSpuriousRetransmits`). Note: `network.io.direction` is not included; retransmits are a sender-side phenomenon.

### `system.network.tcp.resets`

- **Instrument**: Counter
- **Unit**: `{segment}`
- **Description**: RST segments observed.
- **Attributes**: `network.io.direction` (`receive|transmit`); optional `network.tcp.reset.cause` when inferable cheaply.

### `system.network.tcp.accept_queue.overflows`

- **Instrument**: Counter
- **Unit**: `{event}`
- **Description**: Listen-socket accept-queue overflow events (`sk_ack_backlog > sk_max_ack_backlog`). Named `accept_queue` rather than the Linux colloquial "listen overflow" to keep the semantic portable.
- **Attributes**: none required.

### `system.network.tcp.flow_control.events`

- **Instrument**: Counter
- **Unit**: `{event}`
- **Description**: TCP flow-control notifications (zero-window, window-full). Folded into one metric because both are "receiver told sender to wait" signals and users typically want them together.
- **Attributes**: `network.tcp.flow_control.event` (`zero_window|window_full`), `network.io.direction`.

## Proposed new metrics — UDP

UDP is stateless: no connections, no retransmits, no handshake. Signals of interest are error categories and payload sizing.

### `system.network.udp.errors`

- **Instrument**: Counter
- **Unit**: `{error}`
- **Description**: UDP-level error events.
- **Attributes**: `error.type` — enum `checksum | port_unreachable | send_buffer | receive_buffer` (reusing stable `error.type`; `port_unreachable` chosen to match ICMP terminology users already know, rather than the Linux-specific `NoPort`). Note: `network.io.direction` where applicable.

### `system.network.udp.queue.drops`

- **Instrument**: Counter
- **Unit**: `{datagram}`
- **Description**: Datagrams dropped due to socket queue exhaustion (distinct from interface-level drops covered by `system.network.packet.dropped`).
- **Attributes**: `network.io.direction`.

### `system.network.udp.message.size`

- **Instrument**: Histogram
- **Unit**: `By`
- **Description**: Size distribution of UDP message payload.
- **Attributes**: `network.io.direction`.

## Proposed new attributes

| Attribute | Values | Applies to |
|---|---|---|
| `network.tcp.handshake.role` | `client`, `server` | `system.network.tcp.connection.successes`, `system.network.tcp.connection.failures`, `system.network.tcp.connection.duration`, `system.network.tcp.handshake.duration` |
| `network.tcp.retransmit.type` | `fast`, `tail_loss_probe`, `timeout`, `spurious` | `system.network.tcp.retransmits` |
| `network.tcp.reset.cause` | `application`, `timeout`, `unreachable`, `refused` (optional) | `system.network.tcp.resets` |
| `network.tcp.flow_control.event` | `zero_window`, `window_full` | `system.network.tcp.flow_control.events` |

## OBI rollout (repo-internal, not part of the semconv proposal)

### Before -> after mapping for this repo

| Current name | Proposed name | Disposition |
|---|---|---|
| `obi.stat.tcp.rtt` | `system.network.tcp.rtt.duration` | Direct rename once accepted. Existing `Float64Histogram` instrument keeps working; only the name string changes. |
| `obi.stat.tcp.failed.connections` | `system.network.tcp.connection.failures` | Direct rename. The existing `reason` attribute is replaced by the stable `error.type` attribute; value set is preserved (`unknown \| refused \| reset \| timed-out \| host-unreachable \| net-unreachable \| other`). `Int64Counter` instrument is unchanged. Addition of `network.tcp.handshake.role` is deferred (see "in progress" section). |

All other TCP/UDP stat metrics proposed above are greenfield for this repo. Mapping against the earlier PR roadmap:

- retransmits -> `system.network.tcp.retransmits`
- active connections -> reuse existing `system.network.connection.count`
- success rate -> `rate(system.network.tcp.connection.failures) / (rate(system.network.tcp.connection.successes) + rate(system.network.tcp.connection.failures))`
- handshake latency -> `system.network.tcp.handshake.duration`

### Migration strategy (to be decided)

The two existing metrics (`obi.stat.tcp.rtt`, `obi.stat.tcp.failed.connections`) have downstream consumers, so the rename is a breaking change. Options, in rough order of user friction:

- **Hard cut**. Remove `obi.stat.*` and emit `system.network.*` in the same release. Simple; relies on pre-1.0 stability signal and a CHANGELOG note to carry the load.
- **Dual-emit for a deprecation window**. Emit both old and new names for N releases, then drop the old. No user action needed mid-window, at the cost of double cardinality on the two metrics while the window is open.
- **Opt-in flag (semconv pattern)**. Mirror upstream `OTEL_SEMCONV_STABILITY_OPT_IN`: old names by default, stat/dup emits both, stat emits new-only; flip the default in a later release and eventually remove the old. Three stages, but it's the pattern OTel users already recognise. (Described here <https://opentelemetry.io/blog/2023/http-conventions-declared-stable/#migration-plan>).

Note: `metrics.features` config values (`stats_tcp_failed_connections`, `stats_tcp_rtt`) are unchanged in all three options. They're internal toggles, not part of the user-facing metric surface.
