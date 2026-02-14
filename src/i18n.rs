#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    En,
    De,
}

impl Language {
    pub fn from_config(s: &str) -> Self {
        if s.eq_ignore_ascii_case("de") {
            Self::De
        } else {
            Self::En
        }
    }
}

pub fn tr(lang: Language, en: &'static str, de: &'static str) -> &'static str {
    match lang {
        Language::En => en,
        Language::De => de,
    }
}
