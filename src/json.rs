//! Minimal JSON writer (no serde). A `J` builds a JSON document via
//! small method calls; separators and quoting are handled internally.

pub struct J {
    s: String,
    stack: Vec<Frame>,
}

struct Frame {
    kind: Kind,
    /// Members written (object) / elements written (array).
    n: usize,
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Obj,
    Arr,
}

impl J {
    pub fn new() -> J {
        J {
            s: String::new(),
            stack: Vec::new(),
        }
    }

    /// Begin an object `{` (an array element or an object value).
    pub fn obj(&mut self) {
        self.open(Kind::Obj, b'{');
    }

    /// Begin an array `[`.
    pub fn arr(&mut self) {
        self.open(Kind::Arr, b'[');
    }

    fn open(&mut self, kind: Kind, ch: u8) {
        self.reserve();
        self.s.push(ch as char);
        self.stack.push(Frame { kind, n: 0 });
    }

    /// End the current object or array.
    pub fn end(&mut self) {
        if let Some(frame) = self.stack.pop() {
            self.s.push(if frame.kind == Kind::Obj { '}' } else { ']' });
        }
    }

    /// Emit comma before an array element if one was already written.
    fn reserve(&mut self) {
        let (kind, n) = match self.stack.last() {
            Some(f) => (f.kind, f.n),
            None => return,
        };
        if kind == Kind::Arr {
            if n > 0 {
                self.s.push(',');
            }
            self.stack.last_mut().map(|f| f.n += 1);
        }
    }

    /// Write an object key `"name":`. Valid inside objects only.
    pub fn key(&mut self, k: &str) {
        let (kind, n) = match self.stack.last() {
            Some(f) => (f.kind, f.n),
            None => panic!("key() outside object"),
        };
        assert!(kind == Kind::Obj, "key() inside array");
        if n > 0 {
            self.s.push(',');
        }
        self.s.push('"');
        esc(&mut self.s, k);
        self.s.push_str("\":");
        self.stack.last_mut().map(|f| f.n += 1);
    }

    /// String value.
    pub fn s(&mut self, v: &str) {
        self.reserve();
        self.s.push('"');
        esc(&mut self.s, v);
        self.s.push('"');
    }

    pub fn i(&mut self, v: i64) {
        self.reserve();
        self.s.push_str(&v.to_string());
    }

    pub fn u(&mut self, v: u64) {
        self.reserve();
        self.s.push_str(&v.to_string());
    }

    /// Float value printed with 1 decimal, ".0" trimmed.
    pub fn f(&mut self, v: f64) {
        self.reserve();
        let s = format!("{v:.1}");
        self.s.push_str(s.trim_end_matches(".0"));
    }

    pub fn n(&mut self) {
        self.reserve();
        self.s.push_str("null");
    }

    pub fn out(self) -> String {
        self.s
    }
}

impl Default for J {
    fn default() -> Self {
        J::new()
    }
}

/// Escape a string for JSON output, appending to `out`.
pub fn esc(out: &mut String, v: &str) {
    for c in v.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_object() {
        let mut j = J::new();
        j.obj();
        j.key("a");
        j.i(1);
        j.key("b");
        j.s("x");
        j.key("c");
        j.arr();
        j.i(1);
        j.i(2);
        j.end();
        j.end();
        assert_eq!(j.out(), r#"{"a":1,"b":"x","c":[1,2]}"#);
    }

    #[test]
    fn objects_in_array() {
        let mut j = J::new();
        j.arr();
        j.obj();
        j.key("x");
        j.i(1);
        j.end();
        j.obj();
        j.key("x");
        j.i(2);
        j.end();
        j.end();
        assert_eq!(j.out(), r#"[{"x":1},{"x":2}]"#);
    }

    #[test]
    fn nested() {
        let mut j = J::new();
        j.obj();
        j.key("k");
        j.obj();
        j.key("n");
        j.i(5);
        j.key("arr");
        j.arr();
        j.obj();
        j.key("a");
        j.i(1);
        j.end();
        j.i(7);
        j.end();
        j.end();
        j.end();
        assert_eq!(j.out(), r#"{"k":{"n":5,"arr":[{"a":1},7]}}"#);
    }

    #[test]
    fn top_level_array() {
        let mut j = J::new();
        j.arr();
        j.s("a");
        j.s("b");
        j.end();
        assert_eq!(j.out(), r#"["a","b"]"#);
    }

    #[test]
    fn escaping() {
        let mut j = J::new();
        j.obj();
        j.key("q");
        j.s("say \"hi\"\n\\done");
        j.end();
        assert_eq!(j.out(), r#"{"q":"say \"hi\"\n\\done"}"#);
    }

    #[test]
    fn float_format() {
        let mut j = J::new();
        j.obj();
        j.key("a");
        j.f(12.34);
        j.key("b");
        j.f(5.0);
        j.end();
        assert_eq!(j.out(), r#"{"a":12.3,"b":5}"#);
    }

    #[test]
    fn null_and_u64() {
        let mut j = J::new();
        j.obj();
        j.key("x");
        j.n();
        j.key("z");
        j.u(18446744073709551615);
        j.end();
        assert_eq!(j.out(), r#"{"x":null,"z":18446744073709551615}"#);
    }
}
