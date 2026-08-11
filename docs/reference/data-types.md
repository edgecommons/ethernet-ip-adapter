# Reference — Data Types

EtherNet/IP carries typed CIP values. This adapter decodes the **CIP elementary types** into JSON, both
for scheduled poll reads (explicit messaging) and for class-1 implicit-I/O (push) assembly fields. Every
signal declares its `type`; for push fields it also declares a byte `offset` (and, for a boolean, a
`bit`). The conversion is the same pure codec in both directions and both modes.

## Supported CIP types

| `type` | CIP type | On-wire JSON (read) | Write input |
|--------|----------|---------------------|-------------|
| `bool` | BOOL | boolean | boolean |
| `sint` | SINT (int8) | number | number (int) |
| `usint` | USINT (uint8) | number | number (int) |
| `int` | INT (int16) | number | number (int) |
| `uint` | UINT (uint16) | number | number (int) |
| `dint` | DINT (int32) | number | number (int) |
| `udint` | UDINT (uint32) | number | number (int) |
| `lint` | LINT (int64) | number | number (int) |
| `ulint` | ULINT (uint64) | number | number (int) |
| `real` | REAL (float32) | number | number |
| `lreal` | LREAL (float64) | number | number |

These are all the value types the adapter handles. `string`/`SSTRING`, structures and UDTs (including
Logix `STRING`, which is a UDT), and multi-dimensional arrays are **not supported** — they are rejected
at config-parse time, and `sb/browse` marks such tags `supported: false`.

## Arrays

`arrayCount: N` reads (or writes) a **1-D array** of `N` elements of the signal's `type`; the value is a
JSON array. `N` is an integer from **1 to 65535** (the CIP Read Tag element count is a 16-bit field); a
value outside that range is a configuration error, and in an `sb/read`/`sb/write` explicit signal ref it
is a `BAD_ARGS` refusal. A write must supply exactly `N` elements — a wrong length is rejected. A read
must come back with exactly `N` elements: a reply carrying a different number is a `BAD` sample whose
`qualityRaw` names the expected and received counts, never a shorter array published as `GOOD`.
Multi-dimensional arrays are not supported.

**BOOL array signals are experimental.** The adapter encodes them byte-per-element; Logix controllers
implement BOOL arrays as packed `DWORD`s, so BOOL-array reads from ControlLogix/CompactLogix report
`BAD`, with the reason in `qualityRaw`. Each such signal logs a warning at startup. Scalar `bool` signals
and `bool` array **fields of a push assembly** are not affected — a push layout is a byte map you
declare, not Logix tag storage.

## Scale & offset

For numeric types (not `bool`), a linear transform maps device units to engineering units:

- **Read:** `published = raw × scale + offset` (poll `offset`; push `valueOffset`). Applied element-wise
  for arrays. With no scale/offset, an integer type keeps native integer precision on the wire; with a
  scale it becomes a float.
- **Write:** the inverse, `device = (value − offset) / scale`, then **range-checked against the CIP
  type** — an out-of-range value is a typed error, **never a silent clamp**. An unscaled fractional value
  written to an integer type is rejected; a scaled result is rounded, then range-checked.

## Push field addressing (bit, offset)

A push field decodes out of the assembly byte buffer at its `offset`:

- **`bit` (0–7)** — extract one bit of the byte at `offset` as a boolean (`bool` only, single element).
  Fields may overlap, so a status byte and its individual bits can all read the same `offset`.
- A field's bytes must fit inside the assembly `sizeBytes`; this is validated at startup.

## Quality normalization

Every sample carries a normalized `quality` plus `qualityRaw` (the native detail):

| `quality` | When |
|-----------|------|
| `GOOD` | A successful read/decode. |
| `BAD` | A read failure, a wire type that does not match the configured `type` (`qualityRaw` = `DECODE type mismatch …`), or a reply carrying a different number of elements than the read asked for (`qualityRaw` = `DECODE element count mismatch (expected N, got M)`). Poll: also `NO_DATA`/`UNRESOLVED_REF` on `sb/read`; push: `NO_FRAME` when no frame has arrived. |
| `UNCERTAIN` | A value that goes non-finite (`NaN`/`inf`) after `scale`/`offset` — `qualityRaw` = `NON_FINITE_AFTER_SCALE`, value `null`. For an array, any non-finite element makes the whole reading UNCERTAIN. |

A non-GOOD sample always publishes (a failure is information); it is never suppressed by the deadband.

## Published identity

Each `SouthboundSignalUpdate` / read result carries:

- **`signal.name`** — the configured name (also the sanitized `data`-class channel token).
- **`signal.id`** — the stable canonical id: **poll** = the CIP tag path verbatim (`LINE_SPEED`);
  **push** = `a<assembly>/<offset>/<type>[.<bit>]` (`a100/4/real`, `a100/0/bool.1`).
- **`signal.address`** — the protocol-native handle: **poll** `{ tagPath, type, arrayCount?, slot? }`;
  **push** `{ assembly, offset, type, bit?, arrayCount?, slot? }`.

## Value typing notes

- Integers use the full 64-bit range; a consumer whose JSON parser uses IEEE-754 doubles (e.g.
  JavaScript) may lose precision above 2^53.
- `bool` is a JSON boolean; everything else is a JSON number (or an array of numbers).
- EtherNet/IP carries no device-side timestamp, so `sourceTs` is never emitted; `serverTs` is the
  adapter's read/receive time.

## Protocol scope

- **Poll** uses CIP **explicit messaging** — one request per signal per cycle (there is no
  multiple-service-packet batching, so large tag counts favor fewer, larger poll groups at longer
  intervals). The connection is unconnected explicit messaging by default, or CIP connected messaging
  with `connection.connected: true`.
- **Push** uses CIP **class-1 implicit I/O** — the device produces its input assembly cyclically at the
  RPI; the adapter maps configured byte-offset fields to signals. There is no wire-discoverable field
  map; the layout is configuration.
- **Security** — poll instances support TLS (CIP Security) on the explicit-messaging path via
  `connection.security` (mutual X.509, TCP `2221`; AEAD suites only — TLS 1.3, and TLS 1.2 ECDHE with
  AES-GCM or ChaCha20-Poly1305). Plaintext TCP `44818` is the default; class-1 implicit I/O is plaintext
  UDP `2222` (a push instance configured with TLS is rejected at startup). Secure the network segment
  for plaintext deployments.
