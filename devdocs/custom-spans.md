# Custom Spans

Custom spans let you declare additional OpenTelemetry spans in OBI's
configuration, without modifying the application's source code or its
existing OpenTelemetry instrumentation. You name a span, point it at a
probe location (a USDT marker or a function symbol), and OBI attaches an
eBPF probe and emits matching OTLP spans from then on.

The feature is designed to surface application-defined events that
aren't captured by OBI's built-in protocol instrumentation — business
milestones, internal pipeline stages, vendored library calls, anything
you can identify by a probe point in the binary.

## When to use it

Reach for a custom span when you want to:

- **Surface a business event** the application already emits as a USDT
  probe (or could be patched to emit). Examples: an order moving to
  "paid", a feature flag flipping, a queue draining below a threshold.
- **Time an internal function** without touching the application code.
  Give OBI an ELF symbol; it emits a span around each call.
- **Filter a high-frequency probe down to one event of interest**. For
  example, Python's built-in `python:function__entry` fires for every
  function call. A custom span with a `match:` filter narrows it to a
  single function name in BPF, so userspace only ever sees the events
  you care about.

A custom span behaves like any other OpenTelemetry span: it carries a
name, a trace context (when one is available on the firing thread), and
a `map[string]string` of attributes pulled from the probe's arguments.

## Configuration at a glance

The feature activates automatically when at least one span is configured.

```yaml
ebpf:
  custom_spans:
    ttl: 1m        # how long to wait for an end event after a start
    spans:
      - name: order.process
        on:
          usdt_span: myapp:order
        attrs:
          order_id:
            arg: 0
          customer:
            arg: 1
            type: string

      - name: cache.hit
        on:
          usdt_noret: myapp:cache_hit
        attrs:
          key:
            arg: 0
            type: string

      - name: billing.charge
        on:
          function_span: billing::Service::charge
        attrs:
          tenant:
            arg: 0
            type: string
          request_id:
            arg: 2
            type: u64

      - name: py.process_paid_order
        on:
          usdt_noret: python:function__entry
          match:
            arg: 1
            value: process_paid_order
```

Each span needs a `name` and exactly one **target** under `on:`. There
are four target shapes:

| Target            | Meaning                                                     | Example                              |
| ----------------- | ----------------------------------------------------------- | ------------------------------------ |
| `usdt_noret`      | A one-off USDT marker. Emits a zero-duration span per fire. | A cache hit, a feature flag flip.    |
| `usdt_span`       | A pair of USDT markers `<base>_start` + `<base>_end`. Emits a span whose duration is the time between them. | The order lifecycle, a transaction. |
| `function_noret`  | An ELF symbol; one entry uprobe.                            | `init_complete` (never returns).     |
| `function_span`   | An ELF symbol; entry uprobe + uretprobe. Span = entry-to-return. | `billing::Service::charge`.      |

Optional modifiers:

- **`match:`** (any USDT shape) — drops events in BPF whose argument at
  `match.arg` doesn't equal `match.value` byte-for-byte. Useful for
  filtering broad probes like `python:function__entry` or
  `ruby:method__entry`.

### `attrs`

`attrs` is a map from the attribute name (as it will appear on the OTLP
span) to the probe argument and how to read it.

```yaml
attrs:
  order_id: # integer, sign+width auto-derived from ELF (USDT only)
    arg: 0
  customer: # always specify `type: string` for strings
    arg: 1
    type: string
  status: # explicit integer type (required for function-mode)
    arg: 2
    type: i32
```

String attributes are read up to 128 bytes per fire.

### Automatic argument extraction (Go function-mode)

For `function_span:` and `function_noret:` targets on Go binaries, OBI
automatically discovers and extracts every primitive scalar and string
argument of the target method — no `attrs:` block needed. Works on
stripped binaries (`-ldflags="-s -w"`, no DWARF, no `.symtab`) by walking
the runtime type tables (`.typelink` → `_type` → `funcType`) the Go
linker keeps for the runtime's own reflect support.

```yaml
- name: order.place
  on:
    function_span: "main.(*Order).Place"
```

That's it. No `attrs:` block needed for the common case.

At attach time OBI resolves the receiver type, decodes the method's
signature, and emits one BPF spec entry per primitive argument. The
emitted span carries:

- `arg0`, `arg1`, … for top-level scalar and string args
- `argN.<FieldName>` for primitive fields reachable through a struct-
  pointer arg (Go's idiomatic `*Request` handler pattern)

#### Covered

- Scalars in registers: `bool`, signed/unsigned ints ≤ 8 bytes, `uintptr`,
  `unsafe.Pointer`
- Go strings in registers (`{ptr, len}`)
- Primitive **scalar** fields of a `*struct` argument
- Primitive **string** fields of a `*struct` argument

#### Skipped silently

- Floats — Go regabi passes them in float registers (XMM/V), which are
  not in the standard `pt_regs` snapshot a uprobe receives
- Slices, maps, channels, interfaces, func values — consume register
  slots for ordering, no attr emitted
- Nested struct pointers — only one level of indirection is followed
- Arrays-by-value and stack-spilled args (after 9 int regs amd64 / 16
  arm64)
- Unexported struct fields — most are codegen-internal (protoc-gen-go
  `state`, `sizeCache`, `unknownFields`) and would be noise
- Value-receiver methods, plain top-level functions — only the
  `pkg.(*Type).Method` symbol form is supported
- Methods on types not reached via `reflect.TypeOf` — the linker dead-
  codes the funcType. The probe attaches and the span fires; only the
  auto attrs are missing. A warning is logged once per span.

#### Enriching with a manual `attrs:` block

A manual `attrs:` block layers on top. On argument-index collision
(`attrs.<name>.arg == K` where auto already produced a slot for function
arg K), the manual declaration **replaces** the auto slot — user-supplied
name + type win. On non-colliding indices, manual extends auto. Both
lists appear on the emitted span.

Use this to:
- rename a noisy `arg1.UserId` to `user_id`
- override an inferred type (`u64` instead of auto-derived `i64`)
- extract an extra value auto missed (e.g. a register-level scalar not
  reachable via the funcType walk)

On non-Go binaries (no `.typelink`), auto extraction is a no-op; only
the manual `attrs:` block runs and the probe still attaches for timing.

### `ttl`

`ttl` controls how long the pairer holds a start event while waiting for
its matching end. If the end never arrives, the start is dropped after
`ttl` and no span is emitted.

Pick a value comfortably above your longest expected span duration. The
default is 5 minutes.

## Language support

Custom spans don't care which language emitted the probe — they only
care about probe identity in the target binary. The matrix below shows
which OBI features each language can drive in practice, and the
instrumentation library or technique that gets you there.

| Language | `usdt_noret` / `usdt_span` | `function_noret` / `function_span` | `match:` modifier | How to emit USDT from this language                                                                       |
| -------- | -------------------------- | ---------------------------------- | ----------------- | --------------------------------------------------------------------------------------------------------- |
| C / C++  | ✅                          | ✅                                  | ✅                 | `<sys/sdt.h>` `DTRACE_PROBE*`, or facebook/folly `FOLLY_SDT` (always-fires) / `FOLLY_SDT_WITH_SEMAPHORE`. |
| Rust     | ✅                          | ✅                                  | ✅                 | `libstapsdt-rs` / `sdt-rs`.                                                                               |
| Go       | ✅                          | ✅ (function_span attaches per-RET uprobes; kernel uretprobe is unsafe on Go because the trampoline rewrites the on-stack return address) | ✅                 | [`mmcshane/salp`](https://github.com/mmcshane/salp) registers probes at runtime. |
| Python   | ✅                          | ❌ (no static symbols)              | ✅                 | `python-stapsdt`; builtin `python:function__entry` is present in distro CPython 3.11 but does not fire on the specialized-interpreter hot path. |
| Ruby     | ✅                          | ❌                                  | ✅                 | `ruby-stapsdt`.                                                                                           |
| Java     | ✅                          | ❌                                  | ✅                 | Small JNI bridge over libstapsdt (the integration test ships one). HotSpot's built-in `hotspot:method__entry` requires a JDK built with full DTrace support — distro and Temurin builds don't qualify. |
| Node.js  | ✅                          | ❌                                  | ✅                 | Node-API addon over libstapsdt (the integration test ships one). The upstream `dtrace-provider` works on x86_64 but not on arm64. |

For function-mode spans, OBI auto-detects whether the binary is Go (via
`.gopclntab` and friends) or C/C++ and reads string arguments with the
matching calling convention. The Go-string read uses the regabi-emitted
`{ptr, len}` pair from non-consecutive registers on amd64 (AX/BX/CX/DI/SI/R8/…),
not a `reg_off+8` adjacency assumption.

Go binaries stripped with `-ldflags="-s -w"` keep `.gopclntab`. OBI
resolves `function_span: "main.Foo"` against it when `.symtab` is empty,
so production-built Go services work zero-code.

The `match:` modifier needs `bpf_get_attach_cookie()` (kernel ≥5.15) to
disambiguate two `custom_spans` that share a probe IP. On older kernels
OBI silently skips the `match:`-filtered span and keeps the unfiltered
base attached.

### Quick recipes per language

Each block below shows the application-side probe declaration paired
with the matching `custom_spans:` entry. For languages that support both
USDT and function-mode probes, both variants are shown.

#### C / C++

USDT paired (via `<sys/sdt.h>`):

```c
#include <sys/sdt.h>

void process_order(uint64_t order_id, const char *customer) {
    DTRACE_PROBE2(checkout, order_start, order_id, customer);
    do_work();
    int32_t status = 0;
    DTRACE_PROBE2(checkout, order_end, order_id, status);
}
```

```yaml
- name: order.process
  on:
    usdt_span: checkout:order
  attrs:
    order_id:
      arg: 0
    customer:
      arg: 1
      type: string
```

USDT paired with folly (semaphore-gated; skipped when no eBPF consumer):

```cpp
#include <folly/tracing/StaticTracepoint.h>

FOLLY_SDT_DEFINE_SEMAPHORE(checkout, order_start)
FOLLY_SDT_DEFINE_SEMAPHORE(checkout, order_end)

void process_order(uint64_t order_id, const char *customer) {
    FOLLY_SDT_WITH_SEMAPHORE(checkout, order_start, order_id, customer);
    do_work();
    int32_t status = 0;
    FOLLY_SDT_WITH_SEMAPHORE(checkout, order_end, order_id, status);
}
```

Function-mode paired (no source change needed; `__attribute__((noinline))`
keeps the symbol alive under `-O2`):

```c
__attribute__((noinline)) void process_order(uint64_t order_id,
                                             const char *customer) {
    // existing implementation
}
```

```yaml
- name: order.func
  on:
    function_span: process_order
  attrs:
    order_id:
      arg: 0
      type: u64
    customer: # C ABI: arg 1 = RSI / x1
      arg: 1
      type: string
```

#### Rust — via the [`usdt`](https://crates.io/crates/usdt) crate

USDT paired:

```rust
#[usdt::provider(provider = "checkout")]
mod probes {
    fn order_start(_id: u64, _customer: &str) {}
    fn order_end(_id: u64, _status: i32) {}
}

fn process_order(id: u64, customer: &str) {
    probes::order_start!(|| (id, customer));
    do_work();
    probes::order_end!(|| (id, 0_i32));
}
```

```yaml
- name: order.process
  on:
    usdt_span: checkout:order
  attrs:
    order_id:
      arg: 0
    customer:
      arg: 1
      type: string
```

Function-mode paired (Rust auto-detected from ELF; uses Go-style
`{ptr,len}` because Rust `&str` shares that representation):

```rust
#[no_mangle]
#[inline(never)]
pub fn process_order(id: u64, customer: &str) {
    // `no_mangle` keeps the symbol queryable as plain `process_order`;
    // `inline(never)` keeps a callable body addressable.
}
```

```yaml
- name: order.func
  on:
    function_span: process_order
  attrs:
    order_id:
      arg: 0
      type: u64
    customer:
      arg: 1
      type: string
```

#### Go — via [`mmcshane/salp`](https://github.com/mmcshane/salp)

USDT paired:

```go
provider := salp.NewProvider("checkout")
orderStart := salp.MustAddProbe(provider, "order_start", salp.Uint64, salp.String)
orderEnd   := salp.MustAddProbe(provider, "order_end",   salp.Uint64, salp.Int32)
_ = provider.Load()

func processOrder(id uint64, customer string) {
    orderStart.Fire(id, customer)
    time.Sleep(20 * time.Millisecond)
    orderEnd.Fire(id, int32(0))
}
```

```yaml
- name: order.process
  on:
    usdt_span: checkout:order
  attrs:
    order_id:
      arg: 0
    customer:
      arg: 1
      type: string
```

Function-mode paired (note the `//go:noinline` directive so the symbol
survives the inliner):

```go
//go:noinline
func processOrder(id uint64, customer string) {
    // ...
}
```

```yaml
- name: order.func
  on:
    function_span: main.processOrder
  attrs:
    order_id: # Go regabi: x0 / AX
      arg: 0
      type: u64
    customer: # {ptr, len} in x1+x2 / BX+CX
      arg: 1
      type: string
```

#### Python — via [`python-stapsdt`](https://pypi.org/project/stapsdt/)

USDT paired:

```python
import stapsdt

provider = stapsdt.Provider("checkout")
order_start = provider.add_probe("order_start", stapsdt.ArgTypes.uint64, stapsdt.ArgTypes.uint64)
order_end   = provider.add_probe("order_end",   stapsdt.ArgTypes.uint64, stapsdt.ArgTypes.int32)
provider.load()

def process_order(order_id, customer):
    buf = ctypes.create_string_buffer(customer.encode("ascii"))
    order_start.fire(order_id, ctypes.c_void_p(ctypes.addressof(buf)))
    do_work()
    order_end.fire(order_id, 0)
```

```yaml
- name: order.process
  on:
    usdt_span: checkout:order
  attrs:
    order_id:
      arg: 0
    customer:
      arg: 1
      type: string
```

`match:` on the builtin `python:function__entry` — no extra
instrumentation needed in the application; CPython itself fires the
probe on every interpreted function call, and OBI drops every event in
BPF except the one whose function name matches:

```python
# requires CPython built with --enable-pydtrace
def process_paid_order(order_id: int, customer: str) -> None:
    settle_payment(order_id)
    notify(customer)
```

```yaml
- name: py.process_paid_order
  on:
    usdt_noret: python:function__entry
    match:
      arg: 1
      value: process_paid_order
```

#### Ruby — via [`ruby-stapsdt`](https://github.com/rock-core/ruby-stapsdt)

USDT paired:

```ruby
require "stapsdt"

provider = Stapsdt::Provider.new("checkout")
order_start = provider.add_probe("order_start", :uint64, :uint64)
order_end   = provider.add_probe("order_end",   :uint64, :int32)
provider.load

def process_order(order_id, customer)
  order_start.fire(order_id, customer)
  sleep 0.020
  order_end.fire(order_id, 0)
end
```

```yaml
- name: order.process
  on:
    usdt_span: checkout:order
  attrs:
    order_id:
      arg: 0
    customer:
      arg: 1
      type: string
```

#### Java — JNI bridge over libstapsdt

The integration test ships a minimal `Stapsdt.java` + `jstapsdt.c` you
can vendor; the public API matches the python/ruby pattern:

```java
long provider    = Stapsdt.providerInit("checkout");
long orderStart  = Stapsdt.addProbeU64U64(provider, "order_start");
long orderEnd    = Stapsdt.addProbeU64I32(provider, "order_end");
Stapsdt.providerLoad(provider);

void processOrder(long orderId, String customer) {
    Stapsdt.fireU64Str(orderStart, orderId, customer.getBytes(UTF_8));
    Thread.sleep(20);
    Stapsdt.fireU64I32(orderEnd, orderId, 0);
}
```

```yaml
- name: order.process
  on:
    usdt_span: checkout:order
  attrs:
    order_id:
      arg: 0
    customer:
      arg: 1
      type: string
```

#### Node.js — Node-API addon over libstapsdt

Mirrors the integration test's `binding.cc` + `binding.gyp`:

```javascript
const stapsdt   = require('./build/Release/node_stapsdt.node');
const provider  = stapsdt.providerInit('checkout');
const orderStart = stapsdt.addProbeU64U64(provider, 'order_start');
const orderEnd   = stapsdt.addProbeU64I32(provider, 'order_end');
stapsdt.providerLoad(provider);

function processOrder(orderId, customer) {
    stapsdt.fireU64Str(orderStart, orderId, customer);
    // ... do work ...
    stapsdt.fireU64I32(orderEnd, orderId, 0);
}
```

```yaml
- name: order.process
  on:
    usdt_span: checkout:order
  attrs:
    order_id:
      arg: 0
    customer:
      arg: 1
      type: string
```

### Attribute and matching cheat sheet

- **Integer attribute (USDT)** — `arg: N` is enough; OBI derives sign +
  width from the `.note.stapsdt` record.
- **Integer attribute (function-mode)** — explicit `type:` is required
  (`u8` / `u16` / `u32` / `u64` / `i8` / `i16` / `i32` / `i64`); OBI
  reads the register at the given index.
- **String attribute** — `type: string` always required; OBI reads up to
  128 bytes per fire.
- **`match:` filter** — drop events whose arg at `match.arg` doesn't
  byte-equal `match.value` (max 63 bytes). Valid on any USDT shape;
  not allowed on function-mode (use a more specific symbol instead).

## Examples

### Order-processing pipeline (paired + single + match)

A C service emits stapsdt probes for the order lifecycle plus a higher-
frequency `cache_hit` event. We also surface Redis `GET` calls without
attaching to every command:

```yaml
ebpf:
  custom_spans:
    ttl: 1m
    spans:
      - name: order.process
        on:
          usdt_span: checkout:order
        attrs:
          order_id:
            arg: 0
          customer:
            arg: 1
            type: string

      - name: cache.hit
        on:
          usdt_noret: checkout:cache_hit
        attrs:
          key:
            arg: 0
            type: string

      - name: redis.get
        on:
          usdt_noret: checkout:redis_cmd
          match:
            arg: 0
            value: GET
        attrs:
          key:
            arg: 1
            type: string
```

### Time a Go function without source changes

```yaml
- name: billing.charge
  on:
    function_span: billing.(*Service).Charge
  attrs:
    tenant:
      arg: 0
      type: string
    request_id:
      arg: 2
      type: u64
```

OBI detects Go from the binary's ELF, reads `tenant` as a Go `{ptr, len}`
string, and emits a span whose duration is the entry-to-return time.

The same target without a manual `attrs:` block:

```yaml
- name: billing.charge
  on:
    function_span: billing.(*Service).Charge
```

attaches the same probe, emits the same span shape, and additionally
populates `arg0`, `arg1`, … (plus `arg2.Field` for any `*Request`-style
argument) from the receiver type's runtime metadata at attach time. No
DWARF required; works on stripped binaries.

### Surface a specific Python function

```yaml
- name: py.process_paid_order
  on:
    usdt_noret: python:function__entry
    match:
      arg: 1
      value: process_paid_order
```

One uprobe attached to the high-frequency `python:function__entry`
probe, but events are discarded in BPF unless the function name matches
exactly. Requires Python built with `--enable-pydtrace`.

## Known limitations

- **`function_span` correlates entry and return on the firing thread.**
  A recursive call on the same thread overwrites the pending start, so
  only the innermost iteration of a recursion is captured.
- **`match:` on `usdt_span`.** Both the start and end probes share the
  same filter spec. If your start and end carry different values at the
  match index, one side will be dropped and the span won't pair.
- **`hotspot:method__entry`.** OpenJDK's built-in method-entry USDT
  requires a JDK built with full DTrace USDT support. Stock Temurin /
  distro OpenJDK doesn't ship that — use the JNI-via-libstapsdt
  pattern instead (see the integration test sample).
- **Verifier-rejected configurations.** Match values longer than 63
  bytes are rejected at validation. The same applies to spans that
  reference more than 12 probe arguments.

## Internals

- **Configuration** lives in `pkg/config/custom_span.go`. The validator
  rejects mixed shapes, duplicate names, duplicate probes, and bad
  argument indexes.
- **Compilation** (`pkg/ebpf/custom_span.go`) takes the user-declared
  attrs and the binary's ELF-parsed argument layout and produces a
  `obiUSDTSpec` that BPF reads at probe fire time. Strings get coerced
  to a NUL-terminated read; integers keep the ELF-declared
  sign/width. The match modifier installs `MatchName` + `MatchArgIdx`
  + the `match_enabled` flag.
- **Auto-attribute extraction** (`pkg/ebpf/auto_attrs.go` +
  `pkg/internal/gometa/`). On a Go function-mode target, OBI
  parses `.typelink`, resolves the receiver of `pkg.(*Type).Method`,
  walks `uncommonType.methods[]` for the method name, and decodes its
  `funcType.In[]`. A regabi-1.17+ register allocator (amd64 + arm64)
  maps each input to a `pt_regs` slot; the per-recipe encoding
  (`reg-scalar`, `reg-gostring`, `ptr-field-scalar`,
  `ptr-field-gostring`) becomes one `obi_usdt_arg_spec` entry. The
  `k_obi_usdt_arg_ptr_field_go_string` BPF arg type reads a Go string
  header at `*(struct_ptr + field_off)`. The userspace span reader
  pairs the same recipe (as `[]AutoAttrSlot`) with each event and
  labels attributes `arg0`, `arg1`, …, `argN.FieldName` at decode time.
- **Attach** is handled in `pkg/ebpf/instrumenter.go`. Each uprobe
  attach carries a cookie that BPF reads via
  `bpf_get_attach_cookie()` (kernel ≥5.15). On older kernels we fall
  back to a `(pid, ns, ip)` map. The cookie path matters because two
  unrelated probes can land at the same instruction address — a
  function-mode probe and an inline USDT inside that function — and
  the cookie disambiguates them.
- **BPF emit** lives in `bpf/generictracer/custom_span.c`. Four
  programs (`obi_custom_span_start`, `_end`, `_event`,
  `_func_ret`) share a single `custom_span_emit` body that fills a
  ringbuf record with the resolved spec's args, applies the match
  filter, and submits.
- **Cross-tracer dispatch.** `generictracer` owns the registry and
  pairer; `gotracer` reuses the same shared ringbuf and routes
  `EVENT_CUSTOM_SPAN` records back to generictracer via
  `EBPFEventContext.CustomSpanHandler`. This is why Go binaries can
  emit custom spans even though they route through the gotracer
  attachment path.
- **Reader** (`pkg/internal/ebpf/generictracer/custom_span_reader.go`)
  pairs events. Paired USDT spans key on `arg_int[0]`, paired function
  spans key on the firing thread's TID.
- **Kernel requirements**: stapsdt + uprobe attach work on 5.8+.
  The cookie-based spec lookup needs `bpf_get_attach_cookie()`
  (≥5.15). Pre-5.15 kernels — including RHEL 8 / 4.18 backports — use
  an `(pid, ns, ip)` map fallback. Two `custom_spans` that target the
  same USDT probe (a base span plus a `match:`-filtered variant) share
  an IP and cannot be disambiguated by the IP-map fallback, so OBI
  **skips the `match:`-filtered span on pre-5.15 kernels** and lets the
  unfiltered base probe attach cleanly. The 5.15+ cookie path attaches
  both variants normally.
- **Semaphore-gated probes**: `FOLLY_SDT_WITH_SEMAPHORE` and the Rust
  `usdt` crate emit probe bodies whose inline asm checks a `u16`
  counter before firing. The kernel only bumps that counter when the
  uprobe attaches with the `ref_ctr_offset` PMU attr (kernel ≥4.20).
  Pre-4.20 kernels accept the attach with `RefCtrOffset=0`, but the
  inline body short-circuits and **no events emit**. Plain
  `DTRACE_PROBE*` / `FOLLY_SDT` (without the `_WITH_SEMAPHORE`
  variant) and libstapsdt-backed runtime probes are unaffected.

## TODO

Not-yet-implemented work and known gaps

- **Demangled-name lookup for function-mode probes.** Today
  `function_span: "process_order"` matches the ELF symbol table
  exactly. Rust callers have to opt into `#[no_mangle]`; C++ callers
  must paste the Itanium-mangled name. Hooking
  [`github.com/ianlancetaylor/demangle`](https://pkg.go.dev/github.com/ianlancetaylor/demangle)
  into `lookupFunctionTarget` would let users write
  `function_span: "billing::Service::charge"` or
  `function_span: "process_order"` regardless of language.
- **HotSpot `hotspot:method__entry` end-to-end test.** The probe note
  ships in libjvm.so but the call site is stripped from release
  builds (`DTraceMethodProbes` is a `develop` flag). The integration
  test uses a JNI-over-libstapsdt bridge instead. Real end-to-end
  coverage of the builtin probe requires a fastdebug JDK build or a
  JDK published with full DTrace USDT support.
- **Builtin `python:function__entry` end-to-end test.** Distro
  CPython 3.11 (debian:bookworm-slim) reports
  `sysconfig.get_config_var("WITH_DTRACE") == 1` and ships the
  `.note.stapsdt` entries, but the probe call sites in
  `libpython3.11.so.1.0` don't fire in practice — `bpftrace -p $PID
  -e 'usdt:libpython:python:function__entry { @c = count(); }'`
  yields zero over a constant Python-call loop. Likely cause is the
  3.11+ specialized adaptive interpreter bypassing the probe site
  on the hot path; full coverage would need a CPython build that
  exercises the slow path or a custom build with the probe call
  preserved across optimizations. Today the integration test
  exercises the `match:` path via the application-emitted
  `custom_span_py:cache_hit` probe rather than the builtin.
- **Recursive `function_span`.** The pairer keys on TID, so a
  recursive call on the same thread overwrites the pending start. A
  bounded per-TID stack of pending starts would let us recover the
  outer span at the cost of more memory.
- **Cross-tracer custom_span attach.** Today
  `finder.newGoTracersGroup` piggy-backs a `generictracer` on Go
  processes when `custom_spans` is configured. That attaches the
  full generictracer kprobe set (HTTP / gRPC / etc.) too. Lifting
  custom_span attach into a tiny shared sub-tracer would avoid the
  overlap.
