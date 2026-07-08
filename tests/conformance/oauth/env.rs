use std::env;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    Mock,
    Google,
    Microsoft,
    GitHub,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    pub kind: ProviderKind,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub tenant_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub live_enabled: bool,
}

#[allow(dead_code)]
impl ProviderConfig {
    #[allow(dead_code)]
    pub fn is_live(&self) -> bool {
        !matches!(self.kind, ProviderKind::Mock)
    }
}

pub fn detect_provider() -> ProviderConfig {
    let provider = env::var("OAUTH_PROVIDER")
        .unwrap_or_else(|_| "mock".into())
        .to_ascii_lowercase();
    let live_enabled = truthy("LIVE_OAUTH");

    match provider.as_str() {
        "google" => ProviderConfig {
            kind: ProviderKind::Google,
            client_id: env::var("GOOGLE_CLIENT_ID").ok(),
            client_secret: env::var("GOOGLE_CLIENT_SECRET").ok(),
            tenant_id: None,
            redirect_uri: env::var("GOOGLE_REDIRECT_URI").ok(),
            live_enabled,
        },
        "microsoft" | "entra" => ProviderConfig {
            kind: ProviderKind::Microsoft,
            client_id: env::var("MS_CLIENT_ID").ok(),
            client_secret: env::var("MS_CLIENT_SECRET").ok(),
            tenant_id: env::var("MS_TENANT_ID").ok(),
            redirect_uri: env::var("MS_REDIRECT_URI").ok(),
            live_enabled,
        },
        "github" => ProviderConfig {
            kind: ProviderKind::GitHub,
            client_id: env::var("GITHUB_CLIENT_ID").ok(),
            client_secret: env::var("GITHUB_CLIENT_SECRET").ok(),
            tenant_id: None,
            redirect_uri: env::var("GITHUB_REDIRECT_URI").ok(),
            live_enabled,
        },
        _ => ProviderConfig {
            kind: ProviderKind::Mock,
            client_id: None,
            client_secret: None,
            tenant_id: None,
            redirect_uri: None,
            live_enabled: false,
        },
    }
}

pub fn truthy(name: &str) -> bool {
    env::var(name)
        .map(|val| {
            let normalized = val.trim().to_ascii_lowercase();
            matches!(normalized.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false)
}
