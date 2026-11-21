/// Linear-time, allocation-free glob matcher supporting `*` (any sequence) and `?` (single char).
/// Immune to catastrophic regex backtracking (ReDoS).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobPattern {
    raw: String,
    chars: Vec<char>,
}

impl GlobPattern {
    pub fn new(pattern: impl Into<String>) -> Self {
        let raw = pattern.into();
        let chars = raw.chars().collect();
        Self { raw, chars }
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }

    pub fn matches(&self, text: &str) -> bool {
        let pat = &self.chars;
        let txt: Vec<char> = text.chars().collect();
        let (mut p, mut t) = (0usize, 0usize);
        let mut star_p: Option<usize> = None;
        let mut star_t: usize = 0;

        while t < txt.len() {
            if p < pat.len() && (pat[p] == '?' || pat[p] == txt[t]) {
                p += 1;
                t += 1;
            } else if p < pat.len() && pat[p] == '*' {
                star_p = Some(p);
                p += 1;
                star_t = t;
            } else if let Some(sp) = star_p {
                p = sp + 1;
                star_t += 1;
                t = star_t;
            } else {
                return false;
            }
        }

        while p < pat.len() && pat[p] == '*' {
            p += 1;
        }

        p == pat.len()
    }
}

pub fn compile_globs(patterns: &[String]) -> Vec<GlobPattern> {
    patterns.iter().cloned().map(GlobPattern::new).collect()
}

pub fn matches_any<'a>(patterns: &'a [GlobPattern], text: &str) -> Option<&'a str> {
    patterns
        .iter()
        .find(|g| g.matches(text))
        .map(GlobPattern::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_matching_edge_cases() {
        assert!(GlobPattern::new("*__delete_*").matches("github__delete_repo"));
        assert!(!GlobPattern::new("*__delete_*").matches("github__list_repos"));
        assert!(GlobPattern::new("foo?bar").matches("fooXbar"));
        assert!(!GlobPattern::new("foo?bar").matches("foobar"));
        assert!(GlobPattern::new("*").matches("anything"));
        assert!(GlobPattern::new("***").matches(""));
        assert!(GlobPattern::new("exact").matches("exact"));
        assert!(!GlobPattern::new("exact").matches("exact2"));
    }
}
