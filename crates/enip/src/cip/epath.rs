//! EPATH encoding (PROTOCOL-DESIGN §6.2).
//!
//! [`Segment`] is the logical-segment set; [`EPath`] is the builder that emits the **padded** form
//! CIP messaging uses (each segment is self-padding, so the whole path is even and `<= 255` words).
//! v1 rejects route port numbers `> 14` at the API (D-ENIP-13) — the extended-port encoding is not
//! shipped unverified. [`TagAddress`] parses Logix symbolic paths (`Program:Main.FillTimer.ACC`,
//! `ZONE_TEMPS[3]`, multi-dim `[a,b]`) into segments, with a typed [`PathError`] surfaced at
//! adapter config validation.

use bytes::Bytes;

use crate::error::EnipError;
use crate::wire::WireWriter;

const CONTEXT: &str = "epath";

/// The Connection Manager object path `[0x20 0x06 0x24 0x01]` — the target of Unconnected_Send and
/// ForwardOpen/ForwardClose (§7.1, §8.2).
pub const CONNECTION_MANAGER: [u8; 4] = [0x20, 0x06, 0x24, 0x01];

/// The maximum EPATH length in 16-bit words (the request-path-size field is a `u8`, §6.1).
pub const MAX_PATH_WORDS: usize = 255;

/// A routing port segment (§6.2). v1 supports port numbers `<= 14` only (D-ENIP-13). For backplane
/// routing the port is 1 and the link is `[slot]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortSegment {
    /// The port to leave the current node by (1 = backplane).
    pub port: u8,
    /// The link address (a slot number for the backplane, or an IP as ASCII bytes).
    pub link: Vec<u8>,
}

impl PortSegment {
    /// A backplane route to `slot` (port 1, link `[slot]`).
    #[must_use]
    pub fn backplane_slot(slot: u8) -> Self {
        Self {
            port: 1,
            link: vec![slot],
        }
    }

    fn encode(&self, w: &mut WireWriter) -> Result<(), EnipError> {
        if self.port > 14 {
            // D-ENIP-13: the extended-port encoding is implemented per spec but gated behind a
            // conformance vector from real routed hardware; until then it is a declared limitation.
            return Err(EnipError::Unsupported {
                what: "route port > 14 (D-ENIP-13)",
            });
        }
        let link_len = self.link.len();
        let size = u8::try_from(link_len).map_err(|_| EnipError::TooLarge { limit: 255 })?;
        let extended = link_len > 1;
        let mut first = self.port;
        if extended {
            first |= 0x10;
        }
        w.u8(first);
        if extended {
            w.u8(size);
        }
        w.put_slice(&self.link);
        // Pad the segment to an even byte count: 1 (+1 if extended) + link_len.
        let base: usize = if extended { 2 } else { 1 };
        let seg_len = base.checked_add(link_len).ok_or(EnipError::TooLarge { limit: 255 })?;
        if seg_len % 2 != 0 {
            w.u8(0);
        }
        Ok(())
    }
}

/// A logical EPATH segment (§6.2). The builder chooses the 8-bit or 16-bit encoding by magnitude.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Segment {
    /// Class id (`0x20`/`0x21`).
    Class(u16),
    /// Instance id (`0x24`/`0x25`).
    Instance(u16),
    /// Attribute id (`0x30`/`0x31`).
    Attribute(u16),
    /// Member/element index (`0x28`/`0x29`/`0x2A`).
    Element(u32),
    /// Assembly connection point (`0x2C`/`0x2D`) — used in I/O paths (§8.4).
    ConnectionPoint(u16),
    /// ANSI extended symbolic segment (`0x91`) — a Logix tag/program name.
    Symbol(String),
    /// Port segment — backplane/routing (§6.2).
    Port(PortSegment),
}

impl Segment {
    fn encode_logical(
        w: &mut WireWriter,
        code8: u8,
        code16: u8,
        value: u16,
    ) {
        if value <= u16::from(u8::MAX) {
            w.u8(code8);
            w.u8(value as u8);
        } else {
            w.u8(code16);
            w.u8(0x00); // pad
            w.u16(value);
        }
    }

    fn encode(&self, w: &mut WireWriter) -> Result<(), EnipError> {
        match self {
            Self::Class(v) => Self::encode_logical(w, 0x20, 0x21, *v),
            Self::Instance(v) => Self::encode_logical(w, 0x24, 0x25, *v),
            Self::Attribute(v) => Self::encode_logical(w, 0x30, 0x31, *v),
            Self::ConnectionPoint(v) => Self::encode_logical(w, 0x2C, 0x2D, *v),
            Self::Element(v) => {
                if *v <= u32::from(u8::MAX) {
                    w.u8(0x28);
                    w.u8(*v as u8);
                } else if *v <= u32::from(u16::MAX) {
                    w.u8(0x29);
                    w.u8(0x00);
                    w.u16(*v as u16);
                } else {
                    w.u8(0x2A);
                    w.u8(0x00);
                    w.u32(*v);
                }
            }
            Self::Symbol(name) => {
                let bytes = name.as_bytes();
                let count = u8::try_from(bytes.len()).map_err(|_| EnipError::TooLarge { limit: 255 })?;
                if count == 0 {
                    return Err(EnipError::Malformed(crate::error::WireError::Malformed {
                        context: CONTEXT,
                        detail: "empty symbolic segment",
                    }));
                }
                w.u8(0x91);
                w.u8(count);
                w.put_slice(bytes);
                if bytes.len() % 2 != 0 {
                    w.u8(0x00); // pad odd-length names to an even word boundary
                }
            }
            Self::Port(port) => port.encode(w)?,
        }
        Ok(())
    }
}

/// A CIP EPATH — an ordered list of [`Segment`]s that encodes to the padded wire form (§6.2).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EPath {
    segments: Vec<Segment>,
}

impl EPath {
    /// An empty path.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A path from the given segments.
    #[must_use]
    pub fn from_segments(segments: Vec<Segment>) -> Self {
        Self { segments }
    }

    /// Append a class segment.
    #[must_use]
    pub fn class(mut self, id: u16) -> Self {
        self.segments.push(Segment::Class(id));
        self
    }

    /// Append an instance segment.
    #[must_use]
    pub fn instance(mut self, id: u16) -> Self {
        self.segments.push(Segment::Instance(id));
        self
    }

    /// Append an attribute segment.
    #[must_use]
    pub fn attribute(mut self, id: u16) -> Self {
        self.segments.push(Segment::Attribute(id));
        self
    }

    /// Append an element segment.
    #[must_use]
    pub fn element(mut self, idx: u32) -> Self {
        self.segments.push(Segment::Element(idx));
        self
    }

    /// Append a connection-point segment.
    #[must_use]
    pub fn connection_point(mut self, id: u16) -> Self {
        self.segments.push(Segment::ConnectionPoint(id));
        self
    }

    /// Append a symbolic segment.
    #[must_use]
    pub fn symbol(mut self, name: impl Into<String>) -> Self {
        self.segments.push(Segment::Symbol(name.into()));
        self
    }

    /// Append a port segment (rejected at encode time if `port > 14`, D-ENIP-13).
    #[must_use]
    pub fn port(mut self, port: PortSegment) -> Self {
        self.segments.push(Segment::Port(port));
        self
    }

    /// Prepend a segment (used to route an already-built request path).
    pub fn prepend(&mut self, segment: Segment) {
        self.segments.insert(0, segment);
    }

    /// The segments.
    #[must_use]
    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    /// Encode the padded EPATH bytes (§6.2). The result is always even-length; a path exceeding
    /// [`MAX_PATH_WORDS`] words is [`EnipError::TooLarge`]; a route port `> 14` is
    /// [`EnipError::Unsupported`].
    pub fn encode(&self) -> Result<Bytes, EnipError> {
        let mut w = WireWriter::new();
        for seg in &self.segments {
            seg.encode(&mut w)?;
        }
        let len = w.len();
        // Each segment self-pads, so the total is even; assert it defensively.
        if len % 2 != 0 {
            return Err(EnipError::Malformed(crate::error::WireError::Malformed {
                context: CONTEXT,
                detail: "epath encoded to odd length",
            }));
        }
        let words = len.checked_div(2).unwrap_or(0);
        if words > MAX_PATH_WORDS {
            return Err(EnipError::TooLarge {
                limit: MAX_PATH_WORDS,
            });
        }
        Ok(w.into_bytes())
    }

    /// The encoded length in 16-bit words (the value the MR request-path-size field carries, §6.1).
    pub fn word_len(&self) -> Result<u8, EnipError> {
        let bytes = self.encode()?;
        let words = bytes.len().checked_div(2).unwrap_or(0);
        u8::try_from(words).map_err(|_| EnipError::TooLarge {
            limit: MAX_PATH_WORDS,
        })
    }
}

/// A typed tag-path parse error (§6.2).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PathError {
    /// The input was empty.
    Empty,
    /// A dotted component was empty (`a..b`, a leading/trailing dot).
    EmptyComponent,
    /// A symbol name started with an illegal character or was too long.
    InvalidName,
    /// A bracket index was malformed (missing `]`, empty, trailing bytes, non-numeric).
    InvalidIndex,
    /// An index or numeric member did not fit in a `u32`.
    NumberOverflow,
}

impl core::fmt::Display for PathError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::Empty => "empty tag path",
            Self::EmptyComponent => "empty path component",
            Self::InvalidName => "invalid symbol name",
            Self::InvalidIndex => "invalid array index",
            Self::NumberOverflow => "index out of range",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for PathError {}

/// A parsed Logix tag address (§6.2) — a symbolic EPATH plus the original text for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagAddress {
    path: EPath,
    display: String,
}

impl TagAddress {
    /// Parse a Logix symbolic tag path into segments (§6.2). Dotted components become symbolic
    /// segments; a bare numeric component (`word.3`) or a bracket index (`[3]`, `[a,b]`) becomes
    /// element segment(s). Parse failures are typed ([`PathError`]).
    pub fn parse(input: &str) -> Result<Self, PathError> {
        if input.is_empty() {
            return Err(PathError::Empty);
        }
        let mut segments = Vec::new();
        for component in input.split('.') {
            parse_component(component, &mut segments)?;
        }
        Ok(Self {
            path: EPath::from_segments(segments),
            display: input.to_owned(),
        })
    }

    /// The symbolic EPATH.
    #[must_use]
    pub fn path(&self) -> &EPath {
        &self.path
    }

    /// Consume into the EPATH.
    #[must_use]
    pub fn into_path(self) -> EPath {
        self.path
    }

    /// The original tag text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.display
    }

    /// Encode the tag path to padded EPATH bytes (§6.2).
    pub fn encode(&self) -> Result<Bytes, EnipError> {
        self.path.encode()
    }
}

fn parse_component(component: &str, segments: &mut Vec<Segment>) -> Result<(), PathError> {
    if component.is_empty() {
        return Err(PathError::EmptyComponent);
    }
    let first = component.as_bytes().first().copied().unwrap_or(0);
    if first.is_ascii_digit() {
        // A bare numeric member (bit position / element): the whole component must be digits.
        let num = parse_index(component)?;
        segments.push(Segment::Element(num));
        return Ok(());
    }
    // Split the symbol name from an optional bracket index group.
    let (name, index_group) = match component.find('[') {
        Some(i) => (
            component.get(..i).unwrap_or(""),
            component.get(i..).unwrap_or(""),
        ),
        None => (component, ""),
    };
    validate_name(name)?;
    segments.push(Segment::Symbol(name.to_owned()));
    if !index_group.is_empty() {
        parse_index_group(index_group, segments)?;
    }
    Ok(())
}

fn parse_index_group(group: &str, segments: &mut Vec<Segment>) -> Result<(), PathError> {
    let inner = group
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or(PathError::InvalidIndex)?;
    if inner.is_empty() {
        return Err(PathError::InvalidIndex);
    }
    for idx in inner.split(',') {
        segments.push(Segment::Element(parse_index(idx)?));
    }
    Ok(())
}

fn parse_index(text: &str) -> Result<u32, PathError> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(PathError::InvalidIndex);
    }
    text.parse::<u32>().map_err(|_| PathError::NumberOverflow)
}

fn validate_name(name: &str) -> Result<(), PathError> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 255 {
        return Err(PathError::InvalidName);
    }
    let first = bytes.first().copied().unwrap_or(0);
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return Err(PathError::InvalidName);
    }
    // Subsequent chars: alphanumeric, underscore, or the ':' of a `Program:Name` scope prefix.
    if !bytes
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'_' || b == b':')
    {
        return Err(PathError::InvalidName);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn connection_manager_path_encodes_exactly() {
        let p = EPath::new().class(0x06).instance(0x01);
        assert_eq!(p.encode().unwrap().as_ref(), &CONNECTION_MANAGER);
        assert_eq!(p.word_len().unwrap(), 2);
    }

    #[test]
    fn class_16bit_is_padded() {
        let p = EPath::new().class(0x0100);
        assert_eq!(p.encode().unwrap().as_ref(), &[0x21, 0x00, 0x00, 0x01]);
    }

    #[test]
    fn symbol_even_and_odd_padding() {
        // "TotalCount" (10 chars, even): 0x91,0x0A + bytes, no pad.
        let even = EPath::new().symbol("TotalCount").encode().unwrap();
        assert_eq!(even.len(), 12);
        assert_eq!(even[0], 0x91);
        assert_eq!(even[1], 0x0A);
        // 11-char name gets a trailing pad byte.
        let odd = EPath::new().symbol("TotalCountt").encode().unwrap();
        assert_eq!(odd.len(), 14);
        assert_eq!(*odd.last().unwrap(), 0x00);
    }

    #[test]
    fn element_widths() {
        assert_eq!(EPath::new().element(3).encode().unwrap().as_ref(), &[0x28, 0x03]);
        assert_eq!(
            EPath::new().element(300).encode().unwrap().as_ref(),
            &[0x29, 0x00, 0x2C, 0x01]
        );
        assert_eq!(
            EPath::new().element(0x0001_0000).encode().unwrap().as_ref(),
            &[0x2A, 0x00, 0x00, 0x00, 0x01, 0x00]
        );
    }

    #[test]
    fn backplane_port_slot() {
        let p = EPath::new().port(PortSegment::backplane_slot(0));
        assert_eq!(p.encode().unwrap().as_ref(), &[0x01, 0x00]);
        let p3 = EPath::new().port(PortSegment::backplane_slot(3));
        assert_eq!(p3.encode().unwrap().as_ref(), &[0x01, 0x03]);
    }

    #[test]
    fn port_over_14_is_unsupported() {
        let p = EPath::new().port(PortSegment {
            port: 15,
            link: vec![0],
        });
        assert!(matches!(p.encode(), Err(EnipError::Unsupported { .. })));
    }

    #[test]
    fn parse_simple_and_scoped_and_indexed() {
        let simple = TagAddress::parse("ZONE_TEMPS").unwrap();
        assert_eq!(simple.path().segments(), &[Segment::Symbol("ZONE_TEMPS".into())]);

        let scoped = TagAddress::parse("Program:Main.FillTimer.ACC").unwrap();
        assert_eq!(
            scoped.path().segments(),
            &[
                Segment::Symbol("Program:Main".into()),
                Segment::Symbol("FillTimer".into()),
                Segment::Symbol("ACC".into()),
            ]
        );

        let indexed = TagAddress::parse("ZONE_TEMPS[3]").unwrap();
        assert_eq!(
            indexed.path().segments(),
            &[Segment::Symbol("ZONE_TEMPS".into()), Segment::Element(3)]
        );

        let multi = TagAddress::parse("PROFILE[0,1,257]").unwrap();
        assert_eq!(
            multi.path().segments(),
            &[
                Segment::Symbol("PROFILE".into()),
                Segment::Element(0),
                Segment::Element(1),
                Segment::Element(257),
            ]
        );
    }

    #[test]
    fn parse_rejects_bad_input() {
        assert_eq!(TagAddress::parse(""), Err(PathError::Empty));
        assert_eq!(TagAddress::parse("a..b"), Err(PathError::EmptyComponent));
        assert_eq!(TagAddress::parse("1abc"), Err(PathError::InvalidIndex));
        assert_eq!(TagAddress::parse("ZONE[").err().unwrap(), PathError::InvalidIndex);
        assert_eq!(TagAddress::parse("ZONE[]").err().unwrap(), PathError::InvalidIndex);
        assert_eq!(TagAddress::parse("ZONE[a]").err().unwrap(), PathError::InvalidIndex);
    }

    #[test]
    fn parsed_symbol_encodes_to_padded_epath() {
        let t = TagAddress::parse("Tag1").unwrap();
        // 0x91, 0x04, 'T','a','g','1'
        assert_eq!(t.encode().unwrap().as_ref(), &[0x91, 0x04, b'T', b'a', b'g', b'1']);
    }
}
