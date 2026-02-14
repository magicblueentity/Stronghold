use crate::models::AppVersion;

pub fn current_version() -> AppVersion {
    let major = 26;
    let minor = 1;
    let patch = 1;
    AppVersion {
        major,
        minor,
        patch,
        string: format!("{}.{}.{}", major, minor, patch),
    }
}
