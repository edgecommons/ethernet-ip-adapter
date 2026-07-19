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
                format!("DECODE type mismatch (expected {}, got {:?})", expected.wire(), got)
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
                return Err(DecodeError::TypeMismatch { expected: ty, got: *el_ty });
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
                Ok(Decoded { value: Value::Null, non_finite: true })
            } else {
                Ok(Decoded { value: Value::Array(out), non_finite: false })
            }
        }
        scalar => {
            if scalar.wire_type() != want {
                return Err(DecodeError::TypeMismatch { expected: ty, got: scalar.wire_type() });
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
            return Err(DecodeError::TypeMismatch { expected: ty, got: v.wire_type() });
        };
        return Ok(Decoded { value: json!(b), non_finite: false });
    }

    let raw = numeric_to_f64(v).ok_or(DecodeError::TypeMismatch { expected: ty, got: v.wire_type() })?;

    if scale.is_some() || offset.is_some() {
        let published = raw * scale.unwrap_or(1.0) + offset.unwrap_or(0.0);
        if !published.is_finite() {
            return Ok(Decoded { value: Value::Null, non_finite: true });
        }
        return Ok(Decoded { value: float_json(published), non_finite: false });
    }

    // No transform: preserve native precision (integers stay JSON integers), but a raw non-finite
    // float is likewise not representable ⇒ UNCERTAIN.
    match v {
        enip::CipValue::Real(f) => {
            if f.is_finite() {
                Ok(Decoded { value: float_json(f64::from(*f)), non_finite: false })
            } else {
                Ok(Decoded { value: Value::Null, non_finite: true })
            }
        }
        enip::CipValue::Lreal(f) => {
            if f.is_finite() {
                Ok(Decoded { value: float_json(*f), non_finite: false })
            } else {
                Ok(Decoded { value: Value::Null, non_finite: true })
            }
        }
        other => Ok(Decoded { value: native_int_json(other), non_finite: false }),
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
        /// The device value that did not fit.
        value: f64,
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
/// # Errors
///
/// A typed [`WriteError`] for a wrong shape, a fractional integer, a non-finite result, or a value
/// outside the CIP type's range (never a clamp).
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
                return Err(WriteError::WrongArrayLen { expected: n as usize, got: arr.len() });
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
                return Err(WriteError::OutOfRange { ty, value: device });
            }
            #[allow(clippy::cast_possible_truncation)]
            Ok(enip::CipValue::Real(device as f32))
        }
        EipType::Lreal => Ok(enip::CipValue::Lreal(device)),
        // Integer types: an unscaled fractional input is rejected; a scaled result is rounded
        // (coerced), then range-checked.
        _ => {
            if !scaled && device.fract() != 0.0 {
                return Err(WriteError::NonInteger { ty });
            }
            let r = device.round();
            let (lo, hi) = int_bounds(ty);
            if r < lo || r > hi {
                return Err(WriteError::OutOfRange { ty, value: device });
            }
            Ok(make_int(ty, r))
        }
    }
}

/// The inclusive `[min, max]` f64 range of an integer [`EipType`]. Callers pass only integer types.
fn int_bounds(ty: EipType) -> (f64, f64) {
    match ty {
        EipType::Sint => (f64::from(i8::MIN), f64::from(i8::MAX)),
        EipType::Usint => (0.0, f64::from(u8::MAX)),
        EipType::Int => (f64::from(i16::MIN), f64::from(i16::MAX)),
        EipType::Uint => (0.0, f64::from(u16::MAX)),
        EipType::Dint => (f64::from(i32::MIN), f64::from(i32::MAX)),
        EipType::Udint => (0.0, f64::from(u32::MAX)),
        #[allow(clippy::cast_precision_loss)]
        EipType::Lint => (i64::MIN as f64, i64::MAX as f64),
        #[allow(clippy::cast_precision_loss)]
        EipType::Ulint => (0.0, u64::MAX as f64),
        // Non-integer types never reach here.
        EipType::Bool | EipType::Real | EipType::Lreal => (0.0, 0.0),
    }
}

/// Build the integer [`enip::CipValue`] for `ty` from an in-range, rounded f64.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]
fn make_int(ty: EipType, r: f64) -> enip::CipValue {
    match ty {
        EipType::Sint => enip::CipValue::Sint(r as i8),
        EipType::Usint => enip::CipValue::Usint(r as u8),
        EipType::Int => enip::CipValue::Int(r as i16),
        EipType::Uint => enip::CipValue::Uint(r as u16),
        EipType::Dint => enip::CipValue::Dint(r as i32),
        EipType::Udint => enip::CipValue::Udint(r as u32),
        EipType::Lint => enip::CipValue::Lint(r as i64),
        EipType::Ulint => enip::CipValue::Ulint(r as u64),
        // Unreachable for non-integer types.
        EipType::Bool | EipType::Real | EipType::Lreal => enip::CipValue::Dint(0),
    }
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
        roundtrip(EipType::Udint, json!(4_000_000_000u64), CipValue::Udint(4_000_000_000));
    }
    #[test]
    fn row_lint() {
        roundtrip(EipType::Lint, json!(-1_000_000_000_000i64), CipValue::Lint(-1_000_000_000_000));
    }
    #[test]
    fn row_ulint() {
        roundtrip(EipType::Ulint, json!(9_000_000_000_000u64), CipValue::Ulint(9_000_000_000_000));
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
                vec![CipValue::Dint(1), CipValue::Dint(2), CipValue::Dint(3), CipValue::Dint(4)]
            )
        );
        let back = decode_value(&cip, EipType::Dint, None, None).unwrap();
        assert_eq!(back.value, json_in);
    }

    #[test]
    fn array_write_wrong_length_is_rejected() {
        let e = encode_write(&json!([1, 2, 3]), EipType::Dint, None, None, Some(4)).unwrap_err();
        assert_eq!(e, WriteError::WrongArrayLen { expected: 4, got: 3 });
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
        assert!(matches!(e, WriteError::OutOfRange { ty: EipType::Sint, .. }));
    }

    #[test]
    fn write_scaled_out_of_range_is_rejected() {
        // device = 1000 / 0.001 = 1_000_000, out of range for int (i16 max 32767).
        let e = encode_write(&json!(1000.0), EipType::Int, Some(0.001), None, None).unwrap_err();
        assert!(matches!(e, WriteError::OutOfRange { ty: EipType::Int, .. }));
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
        let arr = CipValue::Array(enip::CipType::Real, vec![CipValue::Real(1.0), CipValue::Real(f32::INFINITY)]);
        let d = decode_value(&arr, EipType::Real, None, None).unwrap();
        assert!(d.non_finite);
        assert_eq!(d.value, Value::Null);
    }

    // ---- type mismatch ⇒ BAD ----

    #[test]
    fn read_type_mismatch_is_reported() {
        let e = decode_value(&CipValue::Dint(1), EipType::Real, None, None).unwrap_err();
        assert_eq!(e, DecodeError::TypeMismatch { expected: EipType::Real, got: enip::CipType::Dint });
        assert!(e.quality_raw().starts_with("DECODE type mismatch"));
    }

    #[test]
    fn read_array_element_type_mismatch_is_reported() {
        let arr = CipValue::Array(enip::CipType::Int, vec![CipValue::Int(1)]);
        let e = decode_value(&arr, EipType::Dint, None, None).unwrap_err();
        assert!(matches!(e, DecodeError::TypeMismatch { expected: EipType::Dint, .. }));
    }
}
