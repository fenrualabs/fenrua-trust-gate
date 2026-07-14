use std::collections::BTreeMap;

use crate::{Problem, ProblemCode};

/// Hard limits applied before any future schema validation. They are part of
/// the local R1 foundation only and are not a released schema-profile limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseLimits {
    pub max_bytes: usize,
    pub max_depth: usize,
    pub max_array_items: usize,
    pub max_object_members: usize,
    pub max_string_bytes: usize,
    pub max_number_bytes: usize,
}

impl ParseLimits {
    pub const R1_FOUNDATION: Self = Self {
        max_bytes: 1_048_576,
        max_depth: 32,
        max_array_items: 1_024,
        max_object_members: 1_024,
        max_string_bytes: 65_536,
        max_number_bytes: 256,
    };
}

impl Default for ParseLimits {
    fn default() -> Self {
        Self::R1_FOUNDATION
    }
}

/// A strict JSON number preserves its original exact token until the explicit
/// canonicalisation step. It never passes through a floating-point conversion.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct JsonNumber(String);

impl JsonNumber {
    pub fn lexeme(&self) -> &str {
        &self.0
    }
}

/// JSON parsed with duplicate-key rejection and bounded structural resources.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Number(JsonNumber),
    String(String),
    Array(Vec<JsonValue>),
    Object(BTreeMap<String, JsonValue>),
}

/// Parses one complete JSON value from exact local bytes.
///
/// This parser rejects duplicate object keys instead of delegating to a general
/// deserializer that could silently overwrite one of the values.
pub fn parse_json(input: &[u8], limits: ParseLimits) -> Result<JsonValue, Problem> {
    if input.len() > limits.max_bytes {
        return Err(Problem::new(ProblemCode::InputTooLarge));
    }
    if std::str::from_utf8(input).is_err() {
        return Err(Problem::new(ProblemCode::InputInvalidUtf8));
    }

    let mut parser = Parser {
        input,
        limits,
        position: 0,
    };
    parser.skip_whitespace();
    if parser.peek().is_none() {
        return Err(parser.problem(ProblemCode::InvalidJson));
    }
    let value = parser.parse_value(0)?;
    parser.skip_whitespace();
    if parser.peek().is_some() {
        return Err(parser.problem(ProblemCode::TrailingData));
    }
    Ok(value)
}

struct Parser<'input> {
    input: &'input [u8],
    limits: ParseLimits,
    position: usize,
}

impl<'input> Parser<'input> {
    fn parse_value(&mut self, depth: usize) -> Result<JsonValue, Problem> {
        self.skip_whitespace();
        match self.peek() {
            Some(b'n') => self.parse_literal(b"null", JsonValue::Null),
            Some(b't') => self.parse_literal(b"true", JsonValue::Bool(true)),
            Some(b'f') => self.parse_literal(b"false", JsonValue::Bool(false)),
            Some(b'\"') => self.parse_string().map(JsonValue::String),
            Some(b'[') => self.parse_array(depth),
            Some(b'{') => self.parse_object(depth),
            Some(b'-' | b'0'..=b'9') => self.parse_number().map(JsonValue::Number),
            Some(_) | None => Err(self.problem(ProblemCode::InvalidJson)),
        }
    }

    fn parse_literal(&mut self, literal: &[u8], value: JsonValue) -> Result<JsonValue, Problem> {
        let end = self.position.saturating_add(literal.len());
        if self.input.get(self.position..end) != Some(literal) {
            return Err(self.problem(ProblemCode::InvalidJson));
        }
        self.position = end;
        Ok(value)
    }

    fn parse_array(&mut self, depth: usize) -> Result<JsonValue, Problem> {
        self.require_depth(depth)?;
        self.position = self.position.saturating_add(1);
        self.skip_whitespace();
        let mut values = Vec::new();
        if self.consume_if(b']') {
            return Ok(JsonValue::Array(values));
        }

        loop {
            if values.len() >= self.limits.max_array_items {
                return Err(self.problem(ProblemCode::MaxArrayItemsExceeded));
            }
            values.push(self.parse_value(depth.saturating_add(1))?);
            self.skip_whitespace();
            if self.consume_if(b']') {
                return Ok(JsonValue::Array(values));
            }
            if !self.consume_if(b',') {
                return Err(self.problem(ProblemCode::InvalidJson));
            }
            self.skip_whitespace();
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<JsonValue, Problem> {
        self.require_depth(depth)?;
        self.position = self.position.saturating_add(1);
        self.skip_whitespace();
        let mut values = BTreeMap::new();
        if self.consume_if(b'}') {
            return Ok(JsonValue::Object(values));
        }

        loop {
            if values.len() >= self.limits.max_object_members {
                return Err(self.problem(ProblemCode::MaxObjectMembersExceeded));
            }
            if self.peek() != Some(b'\"') {
                return Err(self.problem(ProblemCode::InvalidJson));
            }
            let key = self.parse_string()?;
            if values.contains_key(&key) {
                return Err(self.problem(ProblemCode::DuplicateKey));
            }
            self.skip_whitespace();
            if !self.consume_if(b':') {
                return Err(self.problem(ProblemCode::InvalidJson));
            }
            let value = self.parse_value(depth.saturating_add(1))?;
            values.insert(key, value);
            self.skip_whitespace();
            if self.consume_if(b'}') {
                return Ok(JsonValue::Object(values));
            }
            if !self.consume_if(b',') {
                return Err(self.problem(ProblemCode::InvalidJson));
            }
            self.skip_whitespace();
        }
    }

    fn parse_string(&mut self) -> Result<String, Problem> {
        if !self.consume_if(b'\"') {
            return Err(self.problem(ProblemCode::InvalidJson));
        }
        let mut value = String::new();
        let mut segment_start = self.position;

        loop {
            let byte = match self.peek() {
                Some(byte) => byte,
                None => return Err(self.problem(ProblemCode::InvalidJson)),
            };
            match byte {
                b'\"' => {
                    self.append_raw_segment(&mut value, segment_start, self.position)?;
                    self.position = self.position.saturating_add(1);
                    return Ok(value);
                }
                b'\\' => {
                    self.append_raw_segment(&mut value, segment_start, self.position)?;
                    self.position = self.position.saturating_add(1);
                    self.parse_escape(&mut value)?;
                    segment_start = self.position;
                }
                0..=0x1f => return Err(self.problem(ProblemCode::InvalidJson)),
                _ => self.position = self.position.saturating_add(1),
            }
        }
    }

    fn append_raw_segment(
        &self,
        target: &mut String,
        start: usize,
        end: usize,
    ) -> Result<(), Problem> {
        let segment = match std::str::from_utf8(&self.input[start..end]) {
            Ok(segment) => segment,
            Err(_) => return Err(self.problem(ProblemCode::InputInvalidUtf8)),
        };
        let next_length = target.len().saturating_add(segment.len());
        if next_length > self.limits.max_string_bytes {
            return Err(self.problem(ProblemCode::MaxStringBytesExceeded));
        }
        target.push_str(segment);
        Ok(())
    }

    fn parse_escape(&mut self, target: &mut String) -> Result<(), Problem> {
        let escape = match self.peek() {
            Some(byte) => byte,
            None => return Err(self.problem(ProblemCode::InvalidJson)),
        };
        self.position = self.position.saturating_add(1);
        match escape {
            b'\"' => self.push_char(target, '\"'),
            b'\\' => self.push_char(target, '\\'),
            b'/' => self.push_char(target, '/'),
            b'b' => self.push_char(target, '\u{0008}'),
            b'f' => self.push_char(target, '\u{000c}'),
            b'n' => self.push_char(target, '\n'),
            b'r' => self.push_char(target, '\r'),
            b't' => self.push_char(target, '\t'),
            b'u' => self.parse_unicode_escape(target),
            _ => Err(self.problem(ProblemCode::InvalidJson)),
        }
    }

    fn parse_unicode_escape(&mut self, target: &mut String) -> Result<(), Problem> {
        let first = self.read_hex_quad()?;
        let scalar = if (0xd800..=0xdbff).contains(&first) {
            if self.peek() != Some(b'\\')
                || self.input.get(self.position.saturating_add(1)) != Some(&b'u')
            {
                return Err(self.problem(ProblemCode::InvalidJson));
            }
            self.position = self.position.saturating_add(2);
            let second = self.read_hex_quad()?;
            if !(0xdc00..=0xdfff).contains(&second) {
                return Err(self.problem(ProblemCode::InvalidJson));
            }
            0x1_0000 + (((first as u32 - 0xd800) << 10) | (second as u32 - 0xdc00))
        } else if (0xdc00..=0xdfff).contains(&first) {
            return Err(self.problem(ProblemCode::InvalidJson));
        } else {
            u32::from(first)
        };
        let character = match char::from_u32(scalar) {
            Some(character) => character,
            None => return Err(self.problem(ProblemCode::InvalidJson)),
        };
        self.push_char(target, character)
    }

    fn read_hex_quad(&mut self) -> Result<u16, Problem> {
        let end = self.position.saturating_add(4);
        let digits = match self.input.get(self.position..end) {
            Some(digits) => digits,
            None => return Err(self.problem(ProblemCode::InvalidJson)),
        };
        let mut value = 0_u16;
        for digit in digits {
            let nibble = match digit {
                b'0'..=b'9' => u16::from(digit - b'0'),
                b'a'..=b'f' => u16::from(digit - b'a' + 10),
                b'A'..=b'F' => u16::from(digit - b'A' + 10),
                _ => return Err(self.problem(ProblemCode::InvalidJson)),
            };
            value = (value << 4) | nibble;
        }
        self.position = end;
        Ok(value)
    }

    fn push_char(&self, target: &mut String, character: char) -> Result<(), Problem> {
        let next_length = target.len().saturating_add(character.len_utf8());
        if next_length > self.limits.max_string_bytes {
            return Err(self.problem(ProblemCode::MaxStringBytesExceeded));
        }
        target.push(character);
        Ok(())
    }

    fn parse_number(&mut self) -> Result<JsonNumber, Problem> {
        let start = self.position;
        self.consume_if(b'-');
        match self.peek() {
            Some(b'0') => {
                self.position = self.position.saturating_add(1);
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err(self.problem(ProblemCode::InvalidJson));
                }
            }
            Some(b'1'..=b'9') => {
                self.position = self.position.saturating_add(1);
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.position = self.position.saturating_add(1);
                }
            }
            _ => return Err(self.problem(ProblemCode::InvalidJson)),
        }

        if self.consume_if(b'.') {
            let fraction_start = self.position;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.position = self.position.saturating_add(1);
            }
            if self.position == fraction_start {
                return Err(self.problem(ProblemCode::InvalidJson));
            }
        }

        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.position = self.position.saturating_add(1);
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.position = self.position.saturating_add(1);
            }
            let exponent_start = self.position;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.position = self.position.saturating_add(1);
            }
            if self.position == exponent_start {
                return Err(self.problem(ProblemCode::InvalidJson));
            }
        }

        if self.position.saturating_sub(start) > self.limits.max_number_bytes {
            return Err(self.problem(ProblemCode::MaxNumberBytesExceeded));
        }
        let token = match std::str::from_utf8(&self.input[start..self.position]) {
            Ok(token) => token,
            Err(_) => return Err(self.problem(ProblemCode::InputInvalidUtf8)),
        };
        Ok(JsonNumber(token.to_owned()))
    }

    fn require_depth(&self, depth: usize) -> Result<(), Problem> {
        if depth >= self.limits.max_depth {
            return Err(self.problem(ProblemCode::MaxDepthExceeded));
        }
        Ok(())
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.position = self.position.saturating_add(1);
        }
    }

    fn consume_if(&mut self, expected: u8) -> bool {
        if self.peek() == Some(expected) {
            self.position = self.position.saturating_add(1);
            true
        } else {
            false
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.position).copied()
    }

    fn problem(&self, code: ProblemCode) -> Problem {
        Problem::at(code, self.position)
    }
}

#[cfg(test)]
mod tests {
    use super::{JsonValue, ParseLimits, parse_json};
    use crate::ProblemCode;

    fn parse(input: &[u8]) -> Result<JsonValue, crate::Problem> {
        parse_json(input, ParseLimits::R1_FOUNDATION)
    }

    #[test]
    fn rejects_duplicate_object_keys_before_value_overwrite() {
        let error = match parse(br#"{"subject":"first","subject":"second"}"#) {
            Ok(_) => panic!("duplicate key must fail"),
            Err(error) => error,
        };
        assert_eq!(error.code(), ProblemCode::DuplicateKey);
    }

    #[test]
    fn rejects_nested_duplicate_keys() {
        let error = match parse(br#"{"a":{"b":1,"b":2}}"#) {
            Ok(_) => panic!("nested duplicate key must fail"),
            Err(error) => error,
        };
        assert_eq!(error.code(), ProblemCode::DuplicateKey);
    }

    #[test]
    fn rejects_inputs_above_the_byte_limit_before_parsing() {
        let limits = ParseLimits {
            max_bytes: 5,
            ..ParseLimits::R1_FOUNDATION
        };
        let error = match parse_json(br#"{"a":1}"#, limits) {
            Ok(_) => panic!("oversized input must fail"),
            Err(error) => error,
        };
        assert_eq!(error.code(), ProblemCode::InputTooLarge);
    }

    #[test]
    fn rejects_excessive_nesting() {
        let limits = ParseLimits {
            max_depth: 2,
            ..ParseLimits::R1_FOUNDATION
        };
        let error = match parse_json(br#"[[[]]]"#, limits) {
            Ok(_) => panic!("over-depth input must fail"),
            Err(error) => error,
        };
        assert_eq!(error.code(), ProblemCode::MaxDepthExceeded);
    }

    #[test]
    fn enforces_array_object_string_and_number_bounds() {
        let array_limits = ParseLimits {
            max_array_items: 1,
            ..ParseLimits::R1_FOUNDATION
        };
        let array_error = match parse_json(br#"[1,2]"#, array_limits) {
            Ok(_) => panic!("overlong array must fail"),
            Err(error) => error,
        };
        assert_eq!(array_error.code(), ProblemCode::MaxArrayItemsExceeded);

        let object_limits = ParseLimits {
            max_object_members: 1,
            ..ParseLimits::R1_FOUNDATION
        };
        let object_error = match parse_json(br#"{"a":1,"b":2}"#, object_limits) {
            Ok(_) => panic!("overlong object must fail"),
            Err(error) => error,
        };
        assert_eq!(object_error.code(), ProblemCode::MaxObjectMembersExceeded);

        let string_limits = ParseLimits {
            max_string_bytes: 1,
            ..ParseLimits::R1_FOUNDATION
        };
        let string_error = match parse_json(br#""ab""#, string_limits) {
            Ok(_) => panic!("overlong decoded string must fail"),
            Err(error) => error,
        };
        assert_eq!(string_error.code(), ProblemCode::MaxStringBytesExceeded);

        let number_limits = ParseLimits {
            max_number_bytes: 1,
            ..ParseLimits::R1_FOUNDATION
        };
        let number_error = match parse_json(br#"12"#, number_limits) {
            Ok(_) => panic!("overlong number token must fail"),
            Err(error) => error,
        };
        assert_eq!(number_error.code(), ProblemCode::MaxNumberBytesExceeded);
    }

    #[test]
    fn decodes_valid_surrogate_pairs_and_rejects_unpaired_surrogates() {
        let parsed = match parse(br#""\ud83d\ude80""#) {
            Ok(parsed) => parsed,
            Err(error) => panic!("valid pair must parse: {error}"),
        };
        assert_eq!(parsed, JsonValue::String("🚀".to_owned()));

        let error = match parse(br#""\ud83d""#) {
            Ok(_) => panic!("unpaired surrogate must fail"),
            Err(error) => error,
        };
        assert_eq!(error.code(), ProblemCode::InvalidJson);
    }

    #[test]
    fn rejects_multiple_exponent_signs() {
        let error = match parse(br#"1e+-2"#) {
            Ok(_) => panic!("multiple exponent signs must fail"),
            Err(error) => error,
        };
        assert_eq!(error.code(), ProblemCode::InvalidJson);
    }

    #[test]
    fn emits_a_non_leaky_problem_envelope() {
        let problem = crate::Problem::at(ProblemCode::DuplicateKey, 17);
        assert_eq!(
            problem.envelope().to_json(),
            "{\"schema\":\"fenrua.problem-envelope.r1-draft\",\"code\":\"duplicate_key\",\"title\":\"JSON object contains a duplicate key\",\"status\":400,\"retryable\":false,\"offset\":17}"
        );
    }
}
