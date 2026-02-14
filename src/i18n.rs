use crate::models::{ModuleId, NetworkAnomaly, RiskLevel, RiskyAction};

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

pub fn risk_level_label(lang: Language, risk: RiskLevel) -> &'static str {
    match lang {
        Language::En => match risk {
            RiskLevel::Green => "Green",
            RiskLevel::Yellow => "Yellow",
            RiskLevel::Red => "Red",
        },
        Language::De => match risk {
            RiskLevel::Green => "Gruen",
            RiskLevel::Yellow => "Gelb",
            RiskLevel::Red => "Rot",
        },
    }
}

pub fn module_label(lang: Language, module: ModuleId) -> &'static str {
    match lang {
        Language::En => match module {
            ModuleId::Integrity => "System Integrity",
            ModuleId::Behavior => "Behavior Detection",
            ModuleId::Network => "Network Intelligence",
            ModuleId::HumanRisk => "Human Risk",
            ModuleId::Response => "Response Engine",
            ModuleId::Kernel => "Kernel Control",
        },
        Language::De => match module {
            ModuleId::Integrity => "Systemintegritaet",
            ModuleId::Behavior => "Verhaltenserkennung",
            ModuleId::Network => "Netzwerk-Intelligenz",
            ModuleId::HumanRisk => "Menschliches Risiko",
            ModuleId::Response => "Reaktions-Engine",
            ModuleId::Kernel => "Kernel-Kontrolle",
        },
    }
}

pub fn risky_action_text(lang: Language, action: &RiskyAction) -> String {
    match (action, lang) {
        (RiskyAction::RecentExecutableDownloads { count }, Language::En) => {
            format!("Recent executable downloads detected ({count})")
        }
        (RiskyAction::RecentExecutableDownloads { count }, Language::De) => {
            format!("Aktuelle EXE/MSI Downloads erkannt ({count})")
        }
        (RiskyAction::WeakPasswordAccountsPresent { count }, Language::En) => {
            format!("Weak-password account policy hit ({count})")
        }
        (RiskyAction::WeakPasswordAccountsPresent { count }, Language::De) => {
            format!("Schwache-Passwort-Accounts gefunden ({count})")
        }
        (RiskyAction::GuestInAdministratorsGroup, Language::En) => {
            "Guest account appears in local Administrators group".to_string()
        }
        (RiskyAction::GuestInAdministratorsGroup, Language::De) => {
            "Gastkonto ist in der lokalen Administratorengruppe".to_string()
        }
        (RiskyAction::HighRiskProfile, Language::En) => {
            "User risk profile exceeds threshold".to_string()
        }
        (RiskyAction::HighRiskProfile, Language::De) => {
            "Risikoprofil ueberschreitet Schwellwert".to_string()
        }
    }
}

pub fn network_anomaly_text(lang: Language, anomaly: &NetworkAnomaly) -> String {
    match (anomaly, lang) {
        (NetworkAnomaly::UnusualEstablishedDnsFlow { local, remote }, Language::En) => {
            format!("Unusual established DNS flow: {local} -> {remote}")
        }
        (NetworkAnomaly::UnusualEstablishedDnsFlow { local, remote }, Language::De) => {
            format!("Ungewoehnlicher DNS-Flow (ESTABLISHED): {local} -> {remote}")
        }
        (NetworkAnomaly::DiscoveryPortUsage { remote }, Language::En) => {
            format!("Potential discovery abuse port usage: {remote}")
        }
        (NetworkAnomaly::DiscoveryPortUsage { remote }, Language::De) => {
            format!("Moeglicher Missbrauch von Discovery-Port: {remote}")
        }
        (NetworkAnomaly::EstablishedToUnspecifiedEndpoint { remote }, Language::En) => {
            format!("Established connection to unspecified endpoint: {remote}")
        }
        (NetworkAnomaly::EstablishedToUnspecifiedEndpoint { remote }, Language::De) => {
            format!("ESTABLISHED zu unspezifiziertem Endpoint: {remote}")
        }
    }
}
