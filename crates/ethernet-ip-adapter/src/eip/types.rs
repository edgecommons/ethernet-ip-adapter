//! # The CIP ⇄ JSON value codec (§5.1, §5.4)
//!
//! Pure, fully unit-tested conversions between the protocol crate's [`enip::CipValue`] and the JSON
//! the UNS carries — one path per §5.1 row (bool, the eight integer widths, real, lreal), arrays, and
//! the scale/offset value transform in both directions. No I/O, no `enip` client, no UNS: just the
//! byte-value ↔ JSON-value math the `device.rs` seam applies.
//!
//! * **Read** ([`decode_value`]): `published = raw * scale + offset` (f64), with a wire-type check
//!   (`DECODE type mismatch` ⇒ BAD) and the non-finite rule (`NaN`/`inf` after scaling ⇒ UNCERTAIN,
//!   §5.4). Integer types with no transform keep native JSON-integer precision.
//! * **Write** ([`encode_write`]): the inverse `device = (value − offset) / scale`, then a
//!   **range-check against the CIP type — out-of-range is a typed error, never a clamp** (§5.1), and
//!   the value coerced to the elementary type. Arrays are element-wise with an exact-length check.
//!   Integer targets with no value transform keep native integer precision, the mirror of the read
//!   path: a JSON integer literal becomes the CIP integer through `i64`/`u64`, never through an
//!   `f64`, so a `lint`/`ulint` past 2⁵³ (an epoch-nanosecond stamp, a 64-bit counter) reaches the
//!   device bit-for-bit. Where a real transform makes `f64` arithmetic unavoidable, an integer input
//!   the arithmetic cannot carry exactly is a typed error naming it, never a silent rounding.

use serde_json::{json, Value};

use crate::config::EipType;

// ===================================================================================
// Read: CipValue → JSON
// ===================================================================================

/// A value decoded for reading: the JSON value and whether scaling produced a non-finite number
/// (which the seam surfaces as UNCERTAIN / `NON_FINITE_AFTER_SCALE`, §5.4). A non-finite result
/// carries a JSON `null` value (a JSON number cannot represent `NaN`/`inf`).
#[derive(Debug, Clone, PartialEq)]
pub struct Decoded {
    /// The published JSON value.
    pub value: Value,
    /// `true` ⇒ the decode is UNCERTAIN because a scaled result went non-finite (§5.4).
    pub non_finite: bool,
}

/// Why a decode failed as a per-signal BAD sample (§5.4) — the wire type did not match the configured
/// type. The seam renders [`DecodeError::quality_raw`] into `qualityRaw`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// The reply's declared wire type is not the configured [`EipType`].
    TypeMismatch {
        /// The configured type.
        expected: EipType,
        /// The type the device declared.
        got: enip::CipType,
    },
}

impl DecodeError {
    /// The `qualityRaw` string for a BAD sample from this decode failure (§5.4).
    #[must_use]
    pub fn quality_raw(&self) -> String {
        match self {
            Self::TypeMismatch { expected, got } => {
                format!(
                    "DECODE type mismatch (expected {}, got {:?})",
                    expected.wire(),
                    got
                )
            }
        }
    }
}

/// Convert a decoded [`enip::CipValue`] to its JSON value for the configured [`EipType`], applying
/// `scale`/`offset` (numeric only, §5.1). A scalar yields a scalar; an [`enip::CipValue::Array`]
/// yields a JSON array (element-wise). A wire-type mismatch is [`DecodeError::TypeMismatch`] (⇒ BAD);
/// a scaled result that goes non-finite is `Decoded { non_finite: true, value: null }` (⇒ UNCERTAIN).
///
/// # Errors
///
/// [`DecodeError::TypeMismatch`] when the value's wire type is not `ty`'s CIP type.
pub fn decode_value(
    v: &enip::CipValue,
    ty: EipType,
    scale: Option<f64>,
    offset: Option<f64>,
) -> Result<Decoded, DecodeError> {
    let want = ty.cip_type();
    match v {
        enip::CipValue::Array(el_ty, elems) => {
            if *el_ty != want {
                return Err(DecodeError::TypeMismatch {
                    expected: ty,
                    got: *el_ty,
                });
            }
            let mut out = Vec::with_capacity(elems.len());
            let mut non_finite = false;
            for e in elems {
                let d = decode_scalar(e, ty, scale, offset)?;
                if d.non_finite {
                    non_finite = true;
                }
                out.push(d.value);
            }
            // If any element scaled to a non-finite number the whole array reading is UNCERTAIN
            // (a JSON array cannot hold NaN/inf), value null.
            if non_finite {
                Ok(Decoded {
                    value: Value::Null,
                    non_finite: true,
                })
            } else {
                Ok(Decoded {
                    value: Value::Array(out),
                    non_finite: false,
                })
            }
        }
        scalar => {
            if scalar.wire_type() != want {
                return Err(DecodeError::TypeMismatch {
                    expected: ty,
                    got: scalar.wire_type(),
                });
            }
            decode_scalar(scalar, ty, scale, offset)
        }
    }
}

/// Decode one scalar element. `bool` ignores scale/offset; numeric types apply the transform and the
/// finite check.
fn decode_scalar(
    v: &enip::CipValue,
    ty: EipType,
    scale: Option<f64>,
    offset: Option<f64>,
) -> Result<Decoded, DecodeError> {
    if ty == EipType::Bool {
        let enip::CipValue::Bool(b) = v else {
            return Err(DecodeError::TypeMismatch {
                expected: ty,
                got: v.wire_type(),
            });
        };
        return Ok(Decoded {
            value: json!(b),
            non_finite: false,
        });
    }

    let raw = numeric_to_f64(v).ok_or(DecodeError::TypeMismatch {
        expected: ty,
        got: v.wire_type(),
    })?;

    if scale.is_some() || offset.is_some() {
        let published = raw * scale.unwrap_or(1.0) + offset.unwrap_or(0.0);
        if !published.is_finite() {
            return Ok(Decoded {
                value: Value::Null,
                non_finite: true,
            });
        }
        return Ok(Decoded {
            value: float_json(published),
            non_finite: false,
        });
    }

    // No transform: preserve native precision (integers stay JSON integers), but a raw non-finite
    // float is likewise not representable ⇒ UNCERTAIN.
    match v {
        enip::CipValue::Real(f) => {
            if f.is_finite() {
                Ok(Decoded {
                    value: float_json(f64::from(*f)),
                    non_finite: false,
                })
            } else {
                Ok(Decoded {
                    value: Value::Null,
                    non_finite: true,
                })
            }
        }
        enip::CipValue::Lreal(f) => {
            if f.is_finite() {
                Ok(Decoded {
                    value: float_json(*f),
                    non_finite: false,
                })
            } else {
                Ok(Decoded {
                    value: Value::Null,
                    non_finite: true,
                })
            }
        }
        other => Ok(Decoded {
            value: native_int_json(other),
            non_finite: false,
        }),
    }
}

/// The f64 magnitude of any numeric [`enip::CipValue`]; `None` for non-numeric variants.
fn numeric_to_f64(v: &enip::CipValue) -> Option<f64> {
    Some(match v {
        enip::CipValue::Sint(x) => f64::from(*x),
        enip::CipValue::Int(x) => f64::from(*x),
        enip::CipValue::Dint(x) => f64::from(*x),
        #[allow(clippy::cast_precision_loss)]
        enip::CipValue::Lint(x) => *x as f64,
        enip::CipValue::Usint(x) => f64::from(*x),
        enip::CipValue::Uint(x) => f64::from(*x),
        enip::CipValue::Udint(x) => f64::from(*x),
        #[allow(clippy::cast_precision_loss)]
        enip::CipValue::Ulint(x) => *x as f64,
        enip::CipValue::Real(x) => f64::from(*x),
        enip::CipValue::Lreal(x) => *x,
        _ => return None,
    })
}

/// The native JSON integer for an integer [`enip::CipValue`] (precision-preserving).
fn native_int_json(v: &enip::CipValue) -> Value {
    match v {
        enip::CipValue::Sint(x) => json!(x),
        enip::CipValue::Int(x) => json!(x),
        enip::CipValue::Dint(x) => json!(x),
        enip::CipValue::Lint(x) => json!(x),
        enip::CipValue::Usint(x) => json!(x),
        enip::CipValue::Uint(x) => json!(x),
        enip::CipValue::Udint(x) => json!(x),
        enip::CipValue::Ulint(x) => json!(x),
        _ => Value::Null,
    }
}

/// A finite f64 as a JSON number (`Number::from_f64` returns `None` only for non-finite input, which
/// callers exclude before calling this).
fn float_json(f: f64) -> Value {
    serde_json::Number::from_f64(f).map_or(Value::Null, Value::Number)
}

// ===================================================================================
// Write: JSON → CipValue
// ===================================================================================

/// Why a write value could not be coerced to the configured CIP type (§5.1). Never a silent clamp:
/// an out-of-range or wrong-shape value is one of these typed failures, surfaced to `sb/write`.
#[derive(Debug, Clone, PartialEq)]
pub enum WriteError {
    /// A `bool` field was given a non-boolean JSON value.
    ExpectedBool,
    /// A numeric field was given a non-number JSON value.
    ExpectedNumber,
    /// An array field was given a non-array JSON value.
    ExpectedArray,
    /// An array field was given the wrong number of elements.
    WrongArrayLen {
        /// The configured element count.
        expected: usize,
        /// The count actually supplied.
        got: usize,
    },
    /// An integer field (no scale/offset) was given a fractional number.
    NonInteger {
        /// The target type.
        ty: EipType,
    },
    /// The (possibly inverse-scaled) device value is outside the CIP type's range — rejected, not
    /// clamped (§5.1).
    OutOfRange {
        /// The target type.
        ty: EipType,
        /// The device value that did not fit, rendered exactly. Text rather than `f64` so a 64-bit
        /// integer names itself in the refusal instead of naming its nearest `f64`.
        value: String,
    },
    /// An integer field whose value a configured `scale`/`offset` cannot carry exactly: the
    /// transform is `f64` arithmetic, and past ±2⁵³ consecutive integers share one `f64`, so the
    /// value is refused rather than silently rounded to its neighbour (§5.1).
    InexactUnderTransform {
        /// The target type.
        ty: EipType,
        /// The exact value the caller sent, rendered as text (it does not survive an `f64`).
        value: String,
    },
    /// The inverse-scaled device value is non-finite (`NaN`/`inf`).
    NonFinite,
}

impl std::fmt::Display for WriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExpectedBool => write!(f, "expected a JSON boolean"),
            Self::ExpectedNumber => write!(f, "expected a JSON number"),
            Self::ExpectedArray => write!(f, "expected a JSON array"),
            Self::WrongArrayLen { expected, got } => {
                write!(f, "expected {expected} elements, got {got}")
            }
            Self::NonInteger { ty } => write!(f, "{} requires an integral number", ty.wire()),
            Self::OutOfRange { ty, value } => {
                write!(f, "value {value} is out of range for {}", ty.wire())
            }
            Self::InexactUnderTransform { ty, value } => write!(
                f,
                "value {value} exceeds the exact integer range (2^53) of the scale/offset \
                 arithmetic for {} - refused rather than rounded",
                ty.wire()
            ),
            Self::NonFinite => write!(f, "value is non-finite after applying scale/offset"),
        }
    }
}

impl std::error::Error for WriteError {}

/// Coerce a JSON write value to an [`enip::CipValue`] for the configured [`EipType`], applying the
/// inverse `device = (value − offset) / scale` transform and range-checking against the CIP type
/// (§5.1). `array_count = Some(n)` requires a JSON array of exactly `n` elements, each coerced to the
/// element type.
///
/// An **integer target** under no value transform (`scale`/`offset` absent, or the identity `1.0`
/// / `0.0`) takes an exact path: a JSON integer literal is range-checked and converted through
/// `i64`/`u64` with no `f64` in between, so it lands on the device bit-for-bit. A JSON float is
/// accepted when it is finite and integral (`5.0` for a `dint`); an integral `f64` inside the
/// target's range converts losslessly. Under a *real* transform the arithmetic is `f64`, so an
/// integer literal past ±2⁵³ is [`WriteError::InexactUnderTransform`] rather than a silent rounding.
///
/// # Errors
///
/// A typed [`WriteError`] for a wrong shape, a fractional integer, a non-finite result, an integer
/// a configured transform cannot carry exactly, or a value outside the CIP type's range (never a
/// clamp).
pub fn encode_write(
    value: &Value,
    ty: EipType,
    scale: Option<f64>,
    offset: Option<f64>,
    array_count: Option<u32>,
) -> Result<enip::CipValue, WriteError> {
    match array_count {
        Some(n) => {
            let arr = value.as_array().ok_or(WriteError::ExpectedArray)?;
            if arr.len() != n as usize {
                return Err(WriteError::WrongArrayLen {
                    expected: n as usize,
                    got: arr.len(),
                });
            }
            let mut elems = Vec::with_capacity(arr.len());
            for e in arr {
                elems.push(encode_scalar(e, ty, scale, offset)?);
            }
            Ok(enip::CipValue::Array(ty.cip_type(), elems))
        }
        None => encode_scalar(value, ty, scale, offset),
    }
}

/// The largest magnitude at which an `f64` still represents every integer exactly (2⁵³). Past it
/// consecutive integers collapse onto the same `f64`, so a value that crosses `f64` arithmetic can
/// come back as its neighbour — `9007199254740993` as `9007199254740992`.
const EXACT_F64_INT_LIMIT: i128 = 1_i128 << 53;

/// Coerce one scalar JSON value to an [`enip::CipValue`].
fn encode_scalar(
    value: &Value,
    ty: EipType,
    scale: Option<f64>,
    offset: Option<f64>,
) -> Result<enip::CipValue, WriteError> {
    if ty == EipType::Bool {
        let b = value.as_bool().ok_or(WriteError::ExpectedBool)?;
        return Ok(enip::CipValue::Bool(b));
    }

    // An integer target written as a JSON integer literal is settled here, before any `f64` exists.
    // With no real transform to apply the caller's exact integer becomes the CIP integer directly —
    // the write-side mirror of the read path's `native_int_json`, so what a `lint`/`ulint` read
    // preserves a `lint`/`ulint` write preserves too. With a real transform the arithmetic is
    // unavoidably `f64`, so a value that arithmetic cannot carry exactly is refused by name instead
    // of being rounded to its `f64` neighbour (§5.1).
    if is_integer_type(ty) {
        if let Some(exact) = json_exact_int(value) {
            if is_identity_transform(scale, offset) {
                return encode_exact_int(ty, exact);
            }
            if !(-EXACT_F64_INT_LIMIT..=EXACT_F64_INT_LIMIT).contains(&exact) {
                return Err(WriteError::InexactUnderTransform {
                    ty,
                    value: exact.to_string(),
                });
            }
        }
    }

    let n = value.as_f64().ok_or(WriteError::ExpectedNumber)?;
    let scaled = scale.is_some() || offset.is_some();
    let device = if scaled {
        (n - offset.unwrap_or(0.0)) / scale.unwrap_or(1.0)
    } else {
        n
    };
    if !device.is_finite() {
        return Err(WriteError::NonFinite);
    }

    match ty {
        EipType::Real => {
            if device < f64::from(f32::MIN) || device > f64::from(f32::MAX) {
                return Err(WriteError::OutOfRange {
                    ty,
                    value: device.to_string(),
                });
            }
            #[allow(clippy::cast_possible_truncation)]
            Ok(enip::CipValue::Real(device as f32))
        }
        EipType::Lreal => Ok(enip::CipValue::Lreal(device)),
        // Integer types reached through a JSON float (or an integer literal under a real transform):
        // an unscaled fractional input is rejected; a scaled result is rounded (coerced), then
        // range-checked. An integral `f64` inside the target's range converts losslessly, so nothing
        // is given up here that the JSON text had not already given up.
        _ => {
            if !scaled && device.fract() != 0.0 {
                return Err(WriteError::NonInteger { ty });
            }
            let r = device.round();
            // `r` is finite and integral, so this cast is exact within `i128`'s range and saturates
            // outside it — either way the exact bounds check below decides, and unlike an `f64`
            // bound it cannot let `i64::MAX + 1` through into a saturating cast (a clamp, §5.1).
            #[allow(clippy::cast_possible_truncation)]
            let exact = r as i128;
            let (lo, hi) = int_bounds(ty);
            if exact < lo || exact > hi {
                return Err(WriteError::OutOfRange {
                    ty,
                    value: device.to_string(),
                });
            }
            make_int(ty, exact).ok_or(WriteError::NonInteger { ty })
        }
    }
}

/// Whether `ty` is one of the eight CIP integer widths (§5.1) — the targets whose writes must land
/// on the device bit-for-bit.
fn is_integer_type(ty: EipType) -> bool {
    matches!(
        ty,
        EipType::Sint
            | EipType::Usint
            | EipType::Int
            | EipType::Uint
            | EipType::Dint
            | EipType::Udint
            | EipType::Lint
            | EipType::Ulint
    )
}

/// Whether the configured value transform is the identity map: `scale`/`offset` absent, or present
/// and spelled `1.0`/`0.0`. `device = (value − 0) / 1` is `value` for every finite input, so an
/// identity transform is arithmetic that need not happen — and an integer target that skips it keeps
/// the caller's exact integer.
fn is_identity_transform(scale: Option<f64>, offset: Option<f64>) -> bool {
    scale.unwrap_or(1.0) == 1.0 && offset.unwrap_or(0.0) == 0.0
}

/// The exact integer a JSON number carries when the caller wrote it as an integer literal, widened
/// to `i128` so the whole `i64` ∪ `u64` span fits with room to compare against any target's bounds.
/// `None` for a JSON float (serde_json keeps that distinction) and for a non-number.
fn json_exact_int(v: &Value) -> Option<i128> {
    v.as_u64()
        .map(i128::from)
        .or_else(|| v.as_i64().map(i128::from))
}

/// Coerce an exact integer to `ty`, range-checked against the type's true bounds. No `f64` anywhere
/// on this path, so a `lint`/`ulint` beyond 2⁵³ reaches the device with every bit intact (§5.1).
fn encode_exact_int(ty: EipType, v: i128) -> Result<enip::CipValue, WriteError> {
    let (lo, hi) = int_bounds(ty);
    if v < lo || v > hi {
        return Err(WriteError::OutOfRange {
            ty,
            value: v.to_string(),
        });
    }
    make_int(ty, v).ok_or(WriteError::NonInteger { ty })
}

/// The exact inclusive `[min, max]` range of an integer [`EipType`]. `i128`, deliberately not `f64`:
/// `i64::MAX as f64` rounds *up* to 2⁶³, so an `f64` bound admits a value one past the maximum and
/// hands it to a saturating cast — a clamp, which §5.1 forbids. Callers pass only integer types.
fn int_bounds(ty: EipType) -> (i128, i128) {
    match ty {
        EipType::Sint => (i128::from(i8::MIN), i128::from(i8::MAX)),
        EipType::Usint => (0, i128::from(u8::MAX)),
        EipType::Int => (i128::from(i16::MIN), i128::from(i16::MAX)),
        EipType::Uint => (0, i128::from(u16::MAX)),
        EipType::Dint => (i128::from(i32::MIN), i128::from(i32::MAX)),
        EipType::Udint => (0, i128::from(u32::MAX)),
        EipType::Lint => (i128::from(i64::MIN), i128::from(i64::MAX)),
        EipType::Ulint => (0, i128::from(u64::MAX)),
        // Non-integer types never reach here.
        EipType::Bool | EipType::Real | EipType::Lreal => (0, 0),
    }
}

/// Build the integer [`enip::CipValue`] for `ty` from an exact integer. `None` for a non-integer
/// `ty` or a value outside the target's range — callers range-check against [`int_bounds`] first, so
/// the conversion failures below are unreachable rather than swallowed.
fn make_int(ty: EipType, v: i128) -> Option<enip::CipValue> {
    Some(match ty {
        EipType::Sint => enip::CipValue::Sint(i8::try_from(v).ok()?),
        EipType::Usint => enip::CipValue::Usint(u8::try_from(v).ok()?),
        EipType::Int => enip::CipValue::Int(i16::try_from(v).ok()?),
        EipType::Uint => enip::CipValue::Uint(u16::try_from(v).ok()?),
        EipType::Dint => enip::CipValue::Dint(i32::try_from(v).ok()?),
        EipType::Udint => enip::CipValue::Udint(u32::try_from(v).ok()?),
        EipType::Lint => enip::CipValue::Lint(i64::try_from(v).ok()?),
        EipType::Ulint => enip::CipValue::Ulint(u64::try_from(v).ok()?),
        // Unreachable for non-integer types.
        EipType::Bool | EipType::Real | EipType::Lreal => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use enip::CipValue;

    // ---- §5.1 per-row round-trips: JSON → CipValue → JSON ----

    fn roundtrip(ty: EipType, json_in: Value, expect_wire: CipValue) {
        let cip = encode_write(&json_in, ty, None, None, None).expect("encode");
        assert_eq!(cip, expect_wire, "encode {}", ty.wire());
        let back = decode_value(&cip, ty, None, None).expect("decode");
        assert_eq!(back.value, json_in, "decode {}", ty.wire());
        assert!(!back.non_finite);
    }

    #[test]
    fn row_bool() {
        roundtrip(EipType::Bool, json!(true), CipValue::Bool(true));
        roundtrip(EipType::Bool, json!(false), CipValue::Bool(false));
    }
    #[test]
    fn row_sint() {
        roundtrip(EipType::Sint, json!(-5), CipValue::Sint(-5));
    }
    #[test]
    fn row_usint() {
        roundtrip(EipType::Usint, json!(200), CipValue::Usint(200));
    }
    #[test]
    fn row_int() {
        roundtrip(EipType::Int, json!(-1234), CipValue::Int(-1234));
    }
    #[test]
    fn row_uint() {
        roundtrip(EipType::Uint, json!(50000), CipValue::Uint(50000));
    }
    #[test]
    fn row_dint() {
        roundtrip(EipType::Dint, json!(-123456), CipValue::Dint(-123456));
    }
    #[test]
    fn row_udint() {
        roundtrip(
            EipType::Udint,
            json!(4_000_000_000u64),
            CipValue::Udint(4_000_000_000),
        );
    }
    #[test]
    fn row_lint() {
        roundtrip(
            EipType::Lint,
            json!(-1_000_000_000_000i64),
            CipValue::Lint(-1_000_000_000_000),
        );
    }
    #[test]
    fn row_ulint() {
        roundtrip(
            EipType::Ulint,
            json!(9_000_000_000_000u64),
            CipValue::Ulint(9_000_000_000_000),
        );
    }
    #[test]
    fn row_real() {
        roundtrip(EipType::Real, json!(3.5), CipValue::Real(3.5));
    }
    #[test]
    fn row_lreal() {
        roundtrip(EipType::Lreal, json!(2.5), CipValue::Lreal(2.5));
    }

    // ---- arrays ----

    #[test]
    fn array_roundtrips_json_array() {
        let json_in = json!([1, 2, 3, 4]);
        let cip = encode_write(&json_in, EipType::Dint, None, None, Some(4)).unwrap();
        assert_eq!(
            cip,
            CipValue::Array(
                enip::CipType::Dint,
                vec![
                    CipValue::Dint(1),
                    CipValue::Dint(2),
                    CipValue::Dint(3),
                    CipValue::Dint(4)
                ]
            )
        );
        let back = decode_value(&cip, EipType::Dint, None, None).unwrap();
        assert_eq!(back.value, json_in);
    }

    #[test]
    fn array_write_wrong_length_is_rejected() {
        let e = encode_write(&json!([1, 2, 3]), EipType::Dint, None, None, Some(4)).unwrap_err();
        assert_eq!(
            e,
            WriteError::WrongArrayLen {
                expected: 4,
                got: 3
            }
        );
    }

    // ---- scale/offset both directions ----

    #[test]
    fn read_applies_scale_and_offset() {
        // raw 100 * 0.1 + 5 = 15.0
        let d = decode_value(&CipValue::Dint(100), EipType::Dint, Some(0.1), Some(5.0)).unwrap();
        assert_eq!(d.value, json!(15.0));
        assert!(!d.non_finite);
    }

    #[test]
    fn write_applies_inverse_scale_and_offset() {
        // device = (15 - 5) / 0.1 = 100
        let cip = encode_write(&json!(15.0), EipType::Dint, Some(0.1), Some(5.0), None).unwrap();
        assert_eq!(cip, CipValue::Dint(100));
    }

    #[test]
    fn write_out_of_range_is_rejected_not_clamped() {
        // sint range is [-128, 127]; 500 must be rejected, not clamped to 127.
        let e = encode_write(&json!(500), EipType::Sint, None, None, None).unwrap_err();
        assert!(matches!(
            e,
            WriteError::OutOfRange {
                ty: EipType::Sint,
                ..
            }
        ));
    }

    #[test]
    fn write_scaled_out_of_range_is_rejected() {
        // device = 1000 / 0.001 = 1_000_000, out of range for int (i16 max 32767).
        let e = encode_write(&json!(1000.0), EipType::Int, Some(0.001), None, None).unwrap_err();
        assert!(matches!(
            e,
            WriteError::OutOfRange {
                ty: EipType::Int,
                ..
            }
        ));
    }

    #[test]
    fn write_unscaled_fractional_integer_is_rejected() {
        let e = encode_write(&json!(3.5), EipType::Dint, None, None, None).unwrap_err();
        assert_eq!(e, WriteError::NonInteger { ty: EipType::Dint });
    }

    #[test]
    fn write_bool_rejects_number() {
        assert_eq!(
            encode_write(&json!(1), EipType::Bool, None, None, None).unwrap_err(),
            WriteError::ExpectedBool
        );
    }

    #[test]
    fn write_numeric_rejects_non_number() {
        assert_eq!(
            encode_write(&json!("x"), EipType::Dint, None, None, None).unwrap_err(),
            WriteError::ExpectedNumber
        );
    }

    // ---- non-finite after scale ⇒ UNCERTAIN (§5.4) ----

    #[test]
    fn read_non_finite_after_scale_is_uncertain() {
        // 1e300 * 1e100 = inf
        let d = decode_value(&CipValue::Lreal(1e300), EipType::Lreal, Some(1e100), None).unwrap();
        assert!(d.non_finite);
        assert_eq!(d.value, Value::Null);
    }

    #[test]
    fn read_raw_non_finite_float_is_uncertain() {
        let d = decode_value(&CipValue::Real(f32::NAN), EipType::Real, None, None).unwrap();
        assert!(d.non_finite);
        assert_eq!(d.value, Value::Null);
    }

    #[test]
    fn read_array_with_a_non_finite_element_is_uncertain() {
        let arr = CipValue::Array(
            enip::CipType::Real,
            vec![CipValue::Real(1.0), CipValue::Real(f32::INFINITY)],
        );
        let d = decode_value(&arr, EipType::Real, None, None).unwrap();
        assert!(d.non_finite);
        assert_eq!(d.value, Value::Null);
    }

    // ---- type mismatch ⇒ BAD ----

    #[test]
    fn read_type_mismatch_is_reported() {
        let e = decode_value(&CipValue::Dint(1), EipType::Real, None, None).unwrap_err();
        assert_eq!(
            e,
            DecodeError::TypeMismatch {
                expected: EipType::Real,
                got: enip::CipType::Dint
            }
        );
        assert!(e.quality_raw().starts_with("DECODE type mismatch"));
    }

    #[test]
    fn read_array_element_type_mismatch_is_reported() {
        let arr = CipValue::Array(enip::CipType::Int, vec![CipValue::Int(1)]);
        let e = decode_value(&arr, EipType::Dint, None, None).unwrap_err();
        assert!(matches!(
            e,
            DecodeError::TypeMismatch {
                expected: EipType::Dint,
                ..
            }
        ));
    }

    // ==============================================================================
    // Exact 64-bit integer writes (§5.1 "integral number in range")
    //
    // Every test below that carries a value past 2^53 fails on the pre-fix codec, which funnelled
    // every JSON number through `Value::as_f64()`: an f64 has 53 mantissa bits, so ULINT
    // 9007199254740993 was written to the PLC as 9007199254740992 and reported `ok: true`. The
    // read path never had this problem (`native_int_json`); these are the write path catching up.
    // ==============================================================================

    /// 2⁵³ + 1 — the smallest positive integer an f64 cannot represent (it rounds to 2⁵³).
    const TWO_53_PLUS_1: u64 = 9_007_199_254_740_993;
    /// 2⁵³ — the largest magnitude at which every integer IS exactly representable.
    const TWO_53: u64 = 9_007_199_254_740_992;

    #[test]
    fn write_ulint_past_2_53_keeps_every_bit() {
        // The headline defect: pre-fix this encoded Ulint(9007199254740992) and said ok.
        let cip = encode_write(&json!(TWO_53_PLUS_1), EipType::Ulint, None, None, None).unwrap();
        assert_eq!(cip, CipValue::Ulint(TWO_53_PLUS_1));
    }

    #[test]
    fn write_lint_below_negative_2_53_keeps_every_bit() {
        let v: i64 = -9_007_199_254_740_993;
        let cip = encode_write(&json!(v), EipType::Lint, None, None, None).unwrap();
        assert_eq!(cip, CipValue::Lint(v));
    }

    #[test]
    fn write_lint_epoch_nanoseconds_keep_every_bit() {
        // A wall-clock epoch-nanosecond stamp: ~1.75e18, four orders of magnitude past f64's exact
        // integer range. Pre-fix the last three digits were noise.
        let epoch_ns: i64 = 1_754_899_200_123_456_789;
        let cip = encode_write(&json!(epoch_ns), EipType::Lint, None, None, None).unwrap();
        assert_eq!(cip, CipValue::Lint(epoch_ns));
    }

    #[test]
    fn write_at_the_2_53_boundary_still_works() {
        // Exactly representable: the boundary must keep working, not become collateral damage.
        assert_eq!(
            encode_write(&json!(TWO_53), EipType::Ulint, None, None, None).unwrap(),
            CipValue::Ulint(TWO_53)
        );
        let neg: i64 = -9_007_199_254_740_992;
        assert_eq!(
            encode_write(&json!(neg), EipType::Lint, None, None, None).unwrap(),
            CipValue::Lint(neg)
        );
    }

    #[test]
    fn write_lint_and_ulint_extremes_are_exact() {
        assert_eq!(
            encode_write(&json!(i64::MIN), EipType::Lint, None, None, None).unwrap(),
            CipValue::Lint(i64::MIN)
        );
        assert_eq!(
            encode_write(&json!(i64::MAX), EipType::Lint, None, None, None).unwrap(),
            CipValue::Lint(i64::MAX)
        );
        assert_eq!(
            encode_write(&json!(u64::MAX), EipType::Ulint, None, None, None).unwrap(),
            CipValue::Ulint(u64::MAX)
        );
    }

    #[test]
    fn write_one_past_the_lint_maximum_is_refused_not_saturated() {
        // 2^63 is one past i64::MAX. Pre-fix the bound was `i64::MAX as f64`, which rounds UP to
        // 2^63 — so this passed the range check and `as i64` saturated it to i64::MAX: a clamp,
        // which §5.1 forbids outright.
        let e = encode_write(
            &json!(9_223_372_036_854_775_808_u64),
            EipType::Lint,
            None,
            None,
            None,
        )
        .unwrap_err();
        assert_eq!(
            e,
            WriteError::OutOfRange {
                ty: EipType::Lint,
                value: "9223372036854775808".into()
            }
        );
    }

    #[test]
    fn write_negative_to_ulint_is_refused() {
        let e = encode_write(&json!(-1), EipType::Ulint, None, None, None).unwrap_err();
        assert_eq!(
            e,
            WriteError::OutOfRange {
                ty: EipType::Ulint,
                value: "-1".into()
            }
        );
    }

    #[test]
    fn out_of_range_refusal_names_the_exact_value_not_its_f64_neighbour() {
        // A 64-bit value aimed at a 32-bit tag. The refusal must quote what the caller actually
        // sent; pre-fix the message carried the f64 rounding (…992) of the value (…993).
        let e = encode_write(&json!(TWO_53_PLUS_1), EipType::Dint, None, None, None).unwrap_err();
        assert_eq!(
            e.to_string(),
            "value 9007199254740993 is out of range for dint"
        );
    }

    #[test]
    fn write_exact_integers_survive_an_explicit_identity_transform() {
        // `scale: 1.0` / `valueOffset: 0.0` is the identity map — arithmetic that need not happen,
        // so it must not cost the caller precision either.
        for (scale, offset) in [(Some(1.0), None), (None, Some(0.0)), (Some(1.0), Some(0.0))] {
            assert_eq!(
                encode_write(&json!(TWO_53_PLUS_1), EipType::Ulint, scale, offset, None).unwrap(),
                CipValue::Ulint(TWO_53_PLUS_1),
                "identity transform scale={scale:?} offset={offset:?}"
            );
        }
    }

    #[test]
    fn write_scaled_integer_past_exact_f64_range_is_refused_not_rounded() {
        // A real transform means f64 arithmetic, and f64 cannot carry this value in the first
        // place. Pre-fix it silently became 4503599627370496 (= 9007199254740992 / 2) and reported
        // success; now it is a typed refusal naming the value.
        let e =
            encode_write(&json!(TWO_53_PLUS_1), EipType::Ulint, Some(2.0), None, None).unwrap_err();
        assert_eq!(
            e,
            WriteError::InexactUnderTransform {
                ty: EipType::Ulint,
                value: "9007199254740993".into()
            }
        );
        assert!(e.to_string().contains("9007199254740993"));

        // The offset-only form is the same story.
        let e =
            encode_write(&json!(TWO_53_PLUS_1), EipType::Lint, None, Some(1.0), None).unwrap_err();
        assert!(matches!(
            e,
            WriteError::InexactUnderTransform {
                ty: EipType::Lint,
                ..
            }
        ));
    }

    #[test]
    fn write_scaled_integer_within_exact_f64_range_still_scales() {
        // The refusal above is a ceiling, not a ban: ordinary scaled integer writes are untouched.
        assert_eq!(
            encode_write(&json!(150), EipType::Dint, Some(0.1), Some(5.0), None).unwrap(),
            CipValue::Dint(1450)
        );
        assert_eq!(
            encode_write(&json!(TWO_53), EipType::Lint, Some(2.0), None, None).unwrap(),
            CipValue::Lint(4_503_599_627_370_496)
        );
    }

    #[test]
    fn write_integral_json_float_is_still_accepted_for_an_integer_target() {
        // The acceptance rule: a JSON float reaches an integer target when it is finite and
        // integral. An integral f64 inside the target's range converts losslessly.
        assert_eq!(
            encode_write(&json!(5.0), EipType::Dint, None, None, None).unwrap(),
            CipValue::Dint(5)
        );
        assert_eq!(
            encode_write(&json!(-2.0), EipType::Sint, None, None, None).unwrap(),
            CipValue::Sint(-2)
        );
        assert_eq!(
            encode_write(&json!(1e18), EipType::Lint, None, None, None).unwrap(),
            CipValue::Lint(1_000_000_000_000_000_000)
        );
        // …and a fractional one is still refused (unchanged).
        assert_eq!(
            encode_write(&json!(5.5), EipType::Dint, None, None, None).unwrap_err(),
            WriteError::NonInteger { ty: EipType::Dint }
        );
    }

    #[test]
    fn write_array_of_exact_64_bit_values_keeps_every_element() {
        let json_in = json!([TWO_53_PLUS_1, 9_007_199_254_740_995_u64]);
        let cip = encode_write(&json_in, EipType::Ulint, None, None, Some(2)).unwrap();
        assert_eq!(
            cip,
            CipValue::Array(
                enip::CipType::Ulint,
                vec![
                    CipValue::Ulint(TWO_53_PLUS_1),
                    CipValue::Ulint(9_007_199_254_740_995)
                ]
            )
        );
        // …and the read path hands the same array back, unrounded.
        assert_eq!(
            decode_value(&cip, EipType::Ulint, None, None)
                .unwrap()
                .value,
            json_in
        );
    }

    #[test]
    fn read_and_write_preserve_the_same_integers() {
        // The symmetry claim, stated as a test: every value the read path publishes natively, the
        // write path accepts back and encodes to the value it came from.
        for (ty, v) in [
            (EipType::Ulint, CipValue::Ulint(TWO_53_PLUS_1)),
            (EipType::Ulint, CipValue::Ulint(u64::MAX)),
            (EipType::Lint, CipValue::Lint(i64::MIN)),
            (EipType::Lint, CipValue::Lint(1_754_899_200_123_456_789)),
        ] {
            let published = decode_value(&v, ty, None, None).unwrap().value;
            let back = encode_write(&published, ty, None, None, None).unwrap();
            assert_eq!(back, v, "round trip {published} as {}", ty.wire());
        }
    }

    #[test]
    fn exact_write_reaches_the_wire_unrounded() {
        // End-to-end through the real protocol encoder: what `encode_write` produces is what the
        // enip crate serializes into the CIP Write Tag request, so this is the value the PLC
        // receives. (The SimBackend cannot stand in here — see the note on `SIM_TAGS`: the sim's
        // cpppo layout carries no LINT/ULINT tag, and `SimSession::write_signal` stores the JSON
        // verbatim without going through this codec at all.)
        for (ty, json_in, want_bytes) in [
            (
                EipType::Ulint,
                json!(TWO_53_PLUS_1),
                TWO_53_PLUS_1.to_le_bytes(),
            ),
            (
                EipType::Lint,
                json!(1_754_899_200_123_456_789_i64),
                1_754_899_200_123_456_789_i64.to_le_bytes(),
            ),
        ] {
            let cip = encode_write(&json_in, ty, None, None, None).unwrap();
            let mut w = enip::WireWriter::new();
            cip.encode_value(&mut w).expect("encode to the wire");
            assert_eq!(
                w.as_slice(),
                &want_bytes[..],
                "wire bytes for {}",
                ty.wire()
            );

            // …and the device's echo of those bytes decodes back to the caller's JSON.
            let decoded = CipValue::decode(ty.cip_type(), w.as_slice()).expect("decode");
            assert_eq!(decoded, cip);
            assert_eq!(
                decode_value(&decoded, ty, None, None).unwrap().value,
                json_in
            );
        }
    }

    #[test]
    fn non_integer_targets_still_take_large_integer_literals_as_floats() {
        // real/lreal are float targets: a huge integer literal is float input, not an exactness
        // claim, so the exact-integer path must not intercept it.
        assert_eq!(
            encode_write(&json!(TWO_53_PLUS_1), EipType::Lreal, None, None, None).unwrap(),
            CipValue::Lreal(9_007_199_254_740_992.0)
        );
        assert_eq!(
            encode_write(&json!(TWO_53_PLUS_1), EipType::Real, None, None, None).unwrap(),
            CipValue::Real(9_007_199_254_740_992.0)
        );
        // A float target's own range check is unchanged.
        assert!(matches!(
            encode_write(&json!(1e39), EipType::Real, None, None, None).unwrap_err(),
            WriteError::OutOfRange {
                ty: EipType::Real,
                ..
            }
        ));
    }
}
