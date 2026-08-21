use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
};

use anyhow::{Context, Result, anyhow};
use axum::{
    Json, Router,
    extract::{Form, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use once_cell::sync::Lazy;
use rand::{
    distr::{Alphanumeric, SampleString},
    rng,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use time::{Duration as TimeDuration, OffsetDateTime};
use tokio::{
    net::TcpListener,
    sync::{RwLock, oneshot},
};
use url::Url;
use uuid::Uuid;

static DEFAULT_SCOPE: Lazy<HashSet<String>> = Lazy::new(|| {
    ["openid", "profile", "email"]
        .into_iter()
        .map(|s| s.to_string())
        .collect()
});

#[derive(Debug, Clone, Serialize)]
struct Jwk {
    kty: String,
    use_: String,
    kid: String,
    alg: String,
    n: String,
    e: String,
}

#[derive(Clone)]
struct SigningKeys {
    encoding: jsonwebtoken::EncodingKey,
    jwk: Jwk,
}

impl std::fmt::Debug for SigningKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKeys")
            .field("jwk", &self.jwk)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
struct ClientConfig {
    client_id: String,
    client_secret: String,
    redirect_uris: HashSet<String>,
    allowed_scopes: HashSet<String>,
}

#[derive(Debug, Clone)]
pub struct MockUser {
    sub: String,
    email: String,
    preferred_username: String,
    groups: Vec<String>,
}

impl Default for MockUser {
    fn default() -> Self {
        Self {
            sub: "user-123".to_string(),
            email: "mock.user@example.com".to_string(),
            preferred_username: "mock.user".to_string(),
            groups: vec!["mockers".into(), "testers".into()],
        }
    }
}

#[derive(Debug, Clone)]
struct AuthorizationCode {
    client_id: String,
    redirect_uri: String,
    scope: HashSet<String>,
    code_challenge: Option<String>,
    nonce: Option<String>,
    _created_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
struct RefreshTokenEntry {
    client_id: String,
    scope: HashSet<String>,
    _subject: MockUser,
    _issued_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
enum DeviceCodeStatus {
    Pending { poll_count: u32 },
    Approved,
    Denied,
    Expired,
    Completed,
}

#[derive(Debug, Clone)]
struct DeviceCodeEntry {
    client_id: String,
    scope: HashSet<String>,
    _device_code: String,
    user_code: String,
    expires_at: OffsetDateTime,
    _interval: u64,
    status: DeviceCodeStatus,
}

#[derive(Debug)]
struct InnerState {
    issuer: String,
    signing: SigningKeys,
    clients: HashMap<String, ClientConfig>,
    user: MockUser,
    authorization_codes: HashMap<String, AuthorizationCode>,
    refresh_tokens: HashMap<String, RefreshTokenEntry>,
    access_tokens: HashSet<String>,
    device_codes: HashMap<String, DeviceCodeEntry>,
}

impl InnerState {
    fn generate_code(&self) -> String {
        let mut rng = rng();
        Alphanumeric.sample_string(&mut rng, 32)
    }

    fn client(&self, client_id: &str) -> Option<&ClientConfig> {
        self.clients.get(client_id)
    }
}

type SharedState = Arc<RwLock<InnerState>>;

/// Builder for configuring the mock server.
#[derive(Debug, Clone)]
pub struct MockServerBuilder {
    clients: HashMap<String, ClientConfig>,
    user: MockUser,
    issuer_suffix: Option<String>,
}

impl Default for MockServerBuilder {
    fn default() -> Self {
        let mut clients = HashMap::new();
        clients.insert(
            "mock-client".into(),
            ClientConfig {
                client_id: "mock-client".into(),
                client_secret: "mock-secret".into(),
                redirect_uris: ["https://example.com/callback".into()]
                    .into_iter()
                    .collect(),
                allowed_scopes: DEFAULT_SCOPE.clone(),
            },
        );
        Self {
            clients,
            user: MockUser::default(),
            issuer_suffix: None,
        }
    }
}

impl MockServerBuilder {
    /// Overrides the default mock user.
    pub fn with_user(mut self, user: MockUser) -> Self {
        self.user = user;
        self
    }

    /// Adds or replaces a client configuration.
    pub fn with_client(
        mut self,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uris: impl IntoIterator<Item = impl Into<String>>,
        scopes: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        let client_id = client_id.into();
        let secret = client_secret.into();
        let redirect_uris = redirect_uris.into_iter().map(Into::into).collect();
        let scopes = scopes.into_iter().map(Into::into).collect();
        self.clients.insert(
            client_id.clone(),
            ClientConfig {
                client_id,
                client_secret: secret,
                redirect_uris,
                allowed_scopes: scopes,
            },
        );
        self
    }

    /// Customises the issuer suffix (useful when sharing base URLs across tests).
    pub fn with_issuer_suffix(mut self, suffix: impl Into<String>) -> Self {
        self.issuer_suffix = Some(suffix.into());
        self
    }

    /// Spawns the server using a random free port.
    pub async fn spawn_on_free_port(self) -> Result<MockServer> {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .context("failed to bind mock OAuth listener")?;
        let addr = listener
            .local_addr()
            .context("failed to determine listener address")?;
        self.spawn_with_listener(listener, addr).await
    }

    async fn spawn_with_listener(
        self,
        listener: TcpListener,
        addr: SocketAddr,
    ) -> Result<MockServer> {
        let base_url = format!("http://{addr}");
        let issuer = if let Some(suffix) = &self.issuer_suffix {
            format!("{base_url}/{suffix}")
        } else {
            base_url.clone()
        };

        let signing = generate_signing_keys()?;
        let state = Arc::new(RwLock::new(InnerState {
            issuer: issuer.clone(),
            signing: signing.clone(),
            clients: self.clients.clone(),
            user: self.user.clone(),
            authorization_codes: HashMap::new(),
            refresh_tokens: HashMap::new(),
            access_tokens: HashSet::new(),
            device_codes: HashMap::new(),
        }));

        let jwks = json!({ "keys": [serde_json::to_value(&signing.jwk)?] });

        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let app = router(state.clone());
        let server = axum::serve(listener, app).with_graceful_shutdown(async {
            let _ = shutdown_rx.await;
        });

        let handle = tokio::spawn(async move {
            if let Err(err) = server.await {
                eprintln!("oauth-mock server error: {err:?}");
            }
        });

        Ok(MockServer {
            base_url,
            issuer,
            jwks,
            state,
            shutdown: Some(shutdown_tx),
            _task: handle,
        })
    }
}

fn router(state: SharedState) -> Router {
    Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks.json", get(jwks_endpoint))
        .route("/authorize", get(authorize))
        .route("/token", post(token))
        .route("/device_authorization", post(device_authorization))
        .route("/userinfo", get(userinfo))
        .route("/introspect", post(introspect))
        .route("/revoke", post(revoke))
        .with_state(state)
}

/// Running instance of the mock server.
pub struct MockServer {
    base_url: String,
    issuer: String,
    jwks: Value,
    state: SharedState,
    shutdown: Option<oneshot::Sender<()>>,
    _task: tokio::task::JoinHandle<()>,
}

impl MockServer {
    pub fn builder() -> MockServerBuilder {
        MockServerBuilder::default()
    }

    /// Convenience helper to spawn using defaults.
    pub async fn spawn_on_free_port() -> Result<Self> {
        MockServerBuilder::default().spawn_on_free_port().await
    }

    /// Returns the base URL (http://host:port).
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Returns the configured issuer URL.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Returns the JWKS document.
    pub fn jwks(&self) -> &Value {
        &self.jwks
    }

    /// Retrieves the default client credentials (first configured client).
    pub async fn default_client(&self) -> Option<(String, String)> {
        let state = self.state.read().await;
        state
            .clients
            .values()
            .next()
            .map(|client| (client.client_id.clone(), client.client_secret.clone()))
    }

    /// Marks a device user code as approved.
    pub async fn approve_device_code(&self, user_code: &str) -> Result<()> {
        let mut state = self.state.write().await;
        let entry = state
            .device_codes
            .values_mut()
            .find(|entry| entry.user_code.eq_ignore_ascii_case(user_code))
            .ok_or_else(|| anyhow!("device code {user_code} not found"))?;
        entry.status = DeviceCodeStatus::Approved;
        Ok(())
    }

    /// Denies a device code request.
    pub async fn deny_device_code(&self, user_code: &str) -> Result<()> {
        let mut state = self.state.write().await;
        let entry = state
            .device_codes
            .values_mut()
            .find(|entry| entry.user_code.eq_ignore_ascii_case(user_code))
            .ok_or_else(|| anyhow!("device code {user_code} not found"))?;
        entry.status = DeviceCodeStatus::Denied;
        Ok(())
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

/// Metadata returned by the discovery endpoint.
#[derive(Debug, Serialize)]
struct DiscoveryDocument {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    device_authorization_endpoint: String,
    userinfo_endpoint: String,
    introspection_endpoint: String,
    revocation_endpoint: String,
    response_types_supported: Vec<String>,
    grant_types_supported: Vec<String>,
    code_challenge_methods_supported: Vec<String>,
    scopes_supported: Vec<String>,
}

async fn discovery(State(state): State<SharedState>) -> impl IntoResponse {
    let state = state.read().await;
    let issuer = state.issuer.clone();
    let doc = DiscoveryDocument {
        issuer: issuer.clone(),
        authorization_endpoint: format!("{issuer}/authorize"),
        token_endpoint: format!("{issuer}/token"),
        jwks_uri: format!("{issuer}/jwks.json"),
        device_authorization_endpoint: format!("{issuer}/device_authorization"),
        userinfo_endpoint: format!("{issuer}/userinfo"),
        introspection_endpoint: format!("{issuer}/introspect"),
        revocation_endpoint: format!("{issuer}/revoke"),
        response_types_supported: vec!["code".into(), "token".into()],
        grant_types_supported: vec![
            "authorization_code".into(),
            "refresh_token".into(),
            "client_credentials".into(),
            "urn:ietf:params:oauth:grant-type:device_code".into(),
            "device_code".into(),
        ],
        code_challenge_methods_supported: vec!["S256".into()],
        scopes_supported: state
            .clients
            .values()
            .flat_map(|client| client.allowed_scopes.iter().cloned())
            .collect(),
    };
    Json(doc)
}

async fn jwks_endpoint(State(state): State<SharedState>) -> impl IntoResponse {
    let state = state.read().await;
    Json(json!({ "keys": [serde_json::to_value(&state.signing.jwk).unwrap()] }))
}

#[derive(Debug, Deserialize)]
struct AuthorizeQuery {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    nonce: Option<String>,
}

async fn authorize(
    State(state): State<SharedState>,
    Query(query): Query<AuthorizeQuery>,
) -> Result<Response, MockError> {
    if query.response_type != "code" {
        return Err(MockError::invalid_request("unsupported response_type"));
    }
    let mut state_guard = state.write().await;
    let client = state_guard
        .client(&query.client_id)
        .cloned()
        .ok_or_else(|| MockError::invalid_client("unknown client"))?;
    if !client.redirect_uris.contains(&query.redirect_uri) {
        return Err(MockError::invalid_request("redirect_uri mismatch"));
    }

    let scope_set = parse_scope(&query.scope)?;
    let allowed: HashSet<_> = scope_set
        .intersection(&client.allowed_scopes)
        .cloned()
        .collect();
    if allowed.is_empty() {
        return Err(MockError::invalid_scope("no allowed scopes requested"));
    }

    #[cfg(feature = "pkce")]
    {
        if let Some(method) = &query.code_challenge_method {
            if method != "S256" {
                return Err(MockError::invalid_request("only S256 accepted"));
            }
        } else {
            return Err(MockError::invalid_request("missing code_challenge_method"));
        }
        if query.code_challenge.is_none() {
            return Err(MockError::invalid_request("missing code_challenge"));
        }
    }

    let code = state_guard.generate_code();
    state_guard.authorization_codes.insert(
        code.clone(),
        AuthorizationCode {
            client_id: client.client_id.clone(),
            redirect_uri: query.redirect_uri.clone(),
            scope: allowed,
            code_challenge: query.code_challenge.clone(),
            nonce: query.nonce.clone(),
            _created_at: OffsetDateTime::now_utc(),
        },
    );

    let mut redirect = Url::parse(&query.redirect_uri)
        .map_err(|_| MockError::invalid_request("invalid redirect_uri"))?;
    {
        let mut pairs = redirect.query_pairs_mut();
        pairs.append_pair("code", &code);
        if let Some(state) = &query.state {
            pairs.append_pair("state", state);
        }
    }

    let response = (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, redirect.to_string())],
    );
    Ok(response.into_response())
}

#[derive(Debug, Deserialize)]
struct TokenRequest {
    grant_type: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    device_code: Option<String>,
    scope: Option<String>,
}

async fn token(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Form(request): Form<TokenRequest>,
) -> Result<Json<Value>, MockError> {
    let credentials = extract_client_credentials(&headers, &request)?;

    match request.grant_type.as_str() {
        "authorization_code" => handle_authorization_code(state, credentials, request).await,
        "client_credentials" => handle_client_credentials(state, credentials, request).await,
        "refresh_token" => handle_refresh_token(state, credentials, request).await,
        "urn:ietf:params:oauth:grant-type:device_code" | "device_code" => {
            handle_device_code(state, credentials, request).await
        }
        other => Err(MockError::invalid_request(format!(
            "unsupported grant_type {other}"
        ))),
    }
}

async fn handle_authorization_code(
    state: SharedState,
    credentials: ClientCredentials,
    request: TokenRequest,
) -> Result<Json<Value>, MockError> {
    let code = request
        .code
        .as_ref()
        .ok_or_else(|| MockError::invalid_request("missing code"))?;
    let redirect_uri = request
        .redirect_uri
        .as_ref()
        .ok_or_else(|| MockError::invalid_request("missing redirect_uri"))?;

    #[cfg(feature = "pkce")]
    let code_verifier = request
        .code_verifier
        .clone()
        .ok_or_else(|| MockError::invalid_request("PKCE enabled; code_verifier is required"))?;

    let mut state_guard = state.write().await;
    let entry = state_guard
        .authorization_codes
        .remove(code)
        .ok_or_else(|| MockError::invalid_grant("invalid authorization code"))?;

    if entry.client_id != credentials.client_id {
        return Err(MockError::invalid_grant(
            "authorization code client mismatch",
        ));
    }
    if entry.redirect_uri != *redirect_uri {
        return Err(MockError::invalid_grant("redirect_uri mismatch"));
    }

    #[cfg(feature = "pkce")]
    {
        let expected = entry
            .code_challenge
            .ok_or_else(|| MockError::invalid_grant("missing code challenge"))?;
        let verified = verify_code_challenge(&code_verifier, &expected)?;
        if !verified {
            return Err(MockError::invalid_grant("code_verifier mismatch"));
        }
    }

    let client = state_guard
        .client(&credentials.client_id)
        .cloned()
        .ok_or_else(|| MockError::invalid_client("unknown client"))?;

    let scope = entry.scope.clone();
    let issued_at = OffsetDateTime::now_utc();
    let access_token = issue_access_token(&state_guard, &client, &scope, issued_at)?;
    let id_token = issue_id_token(&state_guard, &client, &scope, issued_at, entry.nonce)?;
    let refresh_token = issue_refresh_token(&mut state_guard, &client, &scope, issued_at)?;
    state_guard.access_tokens.insert(access_token.clone());

    Ok(Json(json!({
        "token_type": "Bearer",
        "expires_in": 3600,
        "access_token": access_token,
        "id_token": id_token,
        "scope": scope_to_string(&scope),
        "refresh_token": refresh_token,
    })))
}

async fn handle_client_credentials(
    state: SharedState,
    credentials: ClientCredentials,
    request: TokenRequest,
) -> Result<Json<Value>, MockError> {
    let mut state_guard = state.write().await;
    let client = state_guard
        .client(&credentials.client_id)
        .cloned()
        .ok_or_else(|| MockError::invalid_client("unknown client"))?;

    if client.client_secret != credentials.client_secret {
        return Err(MockError::invalid_client("invalid client_secret"));
    }

    let requested_scope = parse_scope(&request.scope)?;
    let scope = if requested_scope.is_empty() {
        client.allowed_scopes.clone()
    } else {
        requested_scope
            .intersection(&client.allowed_scopes)
            .cloned()
            .collect()
    };

    let issued_at = OffsetDateTime::now_utc();
    let access_token = issue_access_token(&state_guard, &client, &scope, issued_at)?;
    state_guard.access_tokens.insert(access_token.clone());

    Ok(Json(json!({
        "token_type": "Bearer",
        "expires_in": 3600,
        "access_token": access_token,
        "scope": scope_to_string(&scope),
    })))
}

async fn handle_refresh_token(
    state: SharedState,
    credentials: ClientCredentials,
    request: TokenRequest,
) -> Result<Json<Value>, MockError> {
    let refresh_token = request
        .refresh_token
        .as_ref()
        .ok_or_else(|| MockError::invalid_request("missing refresh_token"))?;

    let mut state_guard = state.write().await;
    let entry = state_guard
        .refresh_tokens
        .remove(refresh_token)
        .ok_or_else(|| MockError::invalid_grant("invalid refresh token"))?;

    if entry.client_id != credentials.client_id {
        return Err(MockError::invalid_grant(
            "client mismatch for refresh token",
        ));
    }

    let client = state_guard
        .client(&credentials.client_id)
        .cloned()
        .ok_or_else(|| MockError::invalid_client("unknown client"))?;

    let scope = entry.scope.clone();
    let issued_at = OffsetDateTime::now_utc();
    let access_token = issue_access_token(&state_guard, &client, &entry.scope, issued_at)?;
    let id_token = issue_id_token(&state_guard, &client, &scope, issued_at, None)?;
    let new_refresh_token = issue_refresh_token(&mut state_guard, &client, &scope, issued_at)?;
    state_guard.access_tokens.insert(access_token.clone());

    Ok(Json(json!({
        "token_type": "Bearer",
        "expires_in": 3600,
        "access_token": access_token,
        "id_token": id_token,
        "scope": scope_to_string(&scope),
        "refresh_token": new_refresh_token,
    })))
}

async fn handle_device_code(
    state: SharedState,
    credentials: ClientCredentials,
    request: TokenRequest,
) -> Result<Json<Value>, MockError> {
    let device_code = request
        .device_code
        .as_ref()
        .ok_or_else(|| MockError::invalid_request("missing device_code"))?;

    let mut state_guard = state.write().await;
    let mut entry = state_guard
        .device_codes
        .remove(device_code)
        .ok_or_else(|| MockError::invalid_grant("invalid device_code"))?;

    if entry.client_id != credentials.client_id {
        state_guard.device_codes.insert(device_code.clone(), entry);
        return Err(MockError::invalid_client("client mismatch for device_code"));
    }

    if OffsetDateTime::now_utc() > entry.expires_at {
        entry.status = DeviceCodeStatus::Expired;
    }

    let result = match &mut entry.status {
        DeviceCodeStatus::Pending { poll_count } => {
            *poll_count += 1;
            if *poll_count % 3 == 0 {
                Err(MockError::slow_down())
            } else {
                Err(MockError::authorization_pending())
            }
        }
        DeviceCodeStatus::Approved => {
            let client = state_guard
                .client(&credentials.client_id)
                .cloned()
                .ok_or_else(|| MockError::invalid_client("unknown client"))?;
            let issued_at = OffsetDateTime::now_utc();
            let scope = entry.scope.clone();
            let access_token = issue_access_token(&state_guard, &client, &scope, issued_at)?;
            let id_token = issue_id_token(&state_guard, &client, &scope, issued_at, None)?;
            let refresh_token =
                issue_refresh_token(&mut state_guard, &client, &entry.scope, issued_at)?;
            state_guard.access_tokens.insert(access_token.clone());
            entry.status = DeviceCodeStatus::Completed;
            Ok(Json(json!({
                "token_type": "Bearer",
                "expires_in": 3600,
                "access_token": access_token,
                "id_token": id_token,
                "scope": scope_to_string(&scope),
                "refresh_token": refresh_token,
            })))
        }
        DeviceCodeStatus::Denied => Err(MockError::access_denied()),
        DeviceCodeStatus::Expired => Err(MockError::expired_token()),
        DeviceCodeStatus::Completed => Err(MockError::invalid_grant("device_code already used")),
    };

    state_guard.device_codes.insert(device_code.clone(), entry);
    result
}

#[derive(Debug, Deserialize)]
struct DeviceAuthorizationRequest {
    client_id: String,
    scope: Option<String>,
}

async fn device_authorization(
    State(state): State<SharedState>,
    Form(request): Form<DeviceAuthorizationRequest>,
) -> Result<Json<Value>, MockError> {
    #[cfg(not(feature = "device_code"))]
    {
        let _ = state;
        let _ = request;
        return Err(MockError::invalid_request("device_code feature disabled"));
    }

    #[cfg(feature = "device_code")]
    {
        let mut state_guard = state.write().await;
        let client = state_guard
            .client(&request.client_id)
            .cloned()
            .ok_or_else(|| MockError::invalid_client("unknown client"))?;

        let requested_scope = parse_scope(&request.scope)?;
        let scope = if requested_scope.is_empty() {
            client.allowed_scopes.clone()
        } else {
            requested_scope
                .intersection(&client.allowed_scopes)
                .cloned()
                .collect()
        };

        let device_code: String = state_guard.generate_code();
        let mut rng = rng();
        let user_code: String = Alphanumeric
            .sample_string(&mut rng, 8)
            .chars()
            .map(|ch| ch.to_ascii_uppercase())
            .collect();

        let entry = DeviceCodeEntry {
            client_id: client.client_id.clone(),
            scope: scope.clone(),
            _device_code: device_code.clone(),
            user_code: user_code.clone(),
            expires_at: OffsetDateTime::now_utc() + TimeDuration::minutes(10),
            _interval: 5,
            status: DeviceCodeStatus::Pending { poll_count: 0 },
        };
        state_guard.device_codes.insert(device_code.clone(), entry);

        Ok(Json(json!({
            "device_code": device_code,
            "user_code": user_code,
            "verification_uri": format!("{}/device", state_guard.issuer),
            "verification_uri_complete": format!("{}/device?user_code={}", state_guard.issuer, user_code),
            "expires_in": 600,
            "interval": 5,
        })))
    }
}

async fn userinfo(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<Json<Value>, MockError> {
    let token = extract_bearer_token(&headers)?;

    let state_guard = state.read().await;
    if !state_guard.access_tokens.contains(token) {
        return Err(MockError::invalid_token("unknown access token"));
    }

    let claims = json!({
        "sub": state_guard.user.sub,
        "email": state_guard.user.email,
        "preferred_username": state_guard.user.preferred_username,
        "groups": state_guard.user.groups,
    });
    Ok(Json(claims))
}

async fn introspect(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Form(body): Form<HashMap<String, String>>,
) -> Result<Json<Value>, MockError> {
    let _ = extract_client_credentials(
        &headers,
        &TokenRequest {
            grant_type: "".into(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            client_id: None,
            client_secret: None,
            device_code: None,
            scope: None,
        },
    )?;

    let token = body
        .get("token")
        .cloned()
        .ok_or_else(|| MockError::invalid_request("missing token"))?;
    let state_guard = state.read().await;
    let active = state_guard.access_tokens.contains(&token)
        || state_guard.refresh_tokens.contains_key(&token);

    Ok(Json(json!({
        "active": active,
        "iss": state_guard.issuer,
        "client_id": "mock-client",
        "scope": scope_to_string(&DEFAULT_SCOPE),
        "token_type": "Bearer"
    })))
}

async fn revoke(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Form(body): Form<HashMap<String, String>>,
) -> Result<StatusCode, MockError> {
    let _ = extract_client_credentials(
        &headers,
        &TokenRequest {
            grant_type: "".into(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            client_id: None,
            client_secret: None,
            device_code: None,
            scope: None,
        },
    )?;
    let token = body
        .get("token")
        .cloned()
        .ok_or_else(|| MockError::invalid_request("missing token"))?;
    let mut state_guard = state.write().await;
    state_guard.access_tokens.remove(&token);
    state_guard.refresh_tokens.remove(&token);
    Ok(StatusCode::OK)
}

#[derive(Debug, Clone)]
struct ClientCredentials {
    client_id: String,
    client_secret: String,
}

fn extract_client_credentials(
    headers: &HeaderMap,
    request: &TokenRequest,
) -> Result<ClientCredentials, MockError> {
    if let Some(header_value) = headers.get(header::AUTHORIZATION) {
        let auth = header_value
            .to_str()
            .map_err(|_| MockError::invalid_client("invalid Authorization header"))?;
        if let Some(encoded) = auth.strip_prefix("Basic ") {
            let decoded = STANDARD
                .decode(encoded)
                .map_err(|_| MockError::invalid_client("invalid basic auth"))?;
            let decoded = String::from_utf8(decoded)
                .map_err(|_| MockError::invalid_client("invalid utf8 basic auth"))?;
            if let Some((id, secret)) = decoded.split_once(':') {
                return Ok(ClientCredentials {
                    client_id: id.to_string(),
                    client_secret: secret.to_string(),
                });
            }
        }
        return Err(MockError::invalid_client("invalid Authorization header"));
    }

    let client_id = request
        .client_id
        .clone()
        .ok_or_else(|| MockError::invalid_client("missing client_id"))?;
    let client_secret = request
        .client_secret
        .clone()
        .ok_or_else(|| MockError::invalid_client("missing client_secret"))?;

    Ok(ClientCredentials {
        client_id,
        client_secret,
    })
}

fn extract_bearer_token(headers: &HeaderMap) -> Result<&str, MockError> {
    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| MockError::invalid_token("missing Authorization header"))?;
    auth.strip_prefix("Bearer ")
        .ok_or_else(|| MockError::invalid_token("invalid bearer token header"))
}

fn issue_access_token(
    state: &InnerState,
    client: &ClientConfig,
    scope: &HashSet<String>,
    issued_at: OffsetDateTime,
) -> Result<String, MockError> {
    #[derive(Debug, Serialize)]
    struct AccessClaims<'a> {
        iss: &'a str,
        sub: &'a str,
        aud: &'a str,
        exp: i64,
        iat: i64,
        scope: String,
        client_id: &'a str,
        jti: String,
    }

    let claims = AccessClaims {
        iss: &state.issuer,
        sub: &state.user.sub,
        aud: &client.client_id,
        exp: (issued_at + TimeDuration::hours(1)).unix_timestamp(),
        iat: issued_at.unix_timestamp(),
        scope: scope_to_string(scope),
        client_id: &client.client_id,
        jti: Uuid::new_v4().to_string(),
    };

    jsonwebtoken::encode(
        &jsonwebtoken::Header {
            alg: jsonwebtoken::Algorithm::RS256,
            kid: Some(state.signing.jwk.kid.clone()),
            ..jsonwebtoken::Header::default()
        },
        &claims,
        &state.signing.encoding,
    )
    .map_err(|err| MockError::server_error(format!("encode access token: {err}")))
}

fn issue_id_token(
    state: &InnerState,
    client: &ClientConfig,
    scope: &HashSet<String>,
    issued_at: OffsetDateTime,
    nonce: Option<String>,
) -> Result<String, MockError> {
    #[derive(Debug, Serialize)]
    struct IdClaims<'a> {
        iss: &'a str,
        sub: &'a str,
        aud: &'a str,
        exp: i64,
        iat: i64,
        email: &'a str,
        preferred_username: &'a str,
        groups: &'a [String],
        scope: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        nonce: Option<String>,
    }

    let claims = IdClaims {
        iss: &state.issuer,
        sub: &state.user.sub,
        aud: &client.client_id,
        exp: (issued_at + TimeDuration::hours(1)).unix_timestamp(),
        iat: issued_at.unix_timestamp(),
        email: &state.user.email,
        preferred_username: &state.user.preferred_username,
        groups: &state.user.groups,
        scope: scope_to_string(scope),
        nonce,
    };

    jsonwebtoken::encode(
        &jsonwebtoken::Header {
            alg: jsonwebtoken::Algorithm::RS256,
            kid: Some(state.signing.jwk.kid.clone()),
            ..jsonwebtoken::Header::default()
        },
        &claims,
        &state.signing.encoding,
    )
    .map_err(|err| MockError::server_error(format!("encode id token: {err}")))
}

fn issue_refresh_token(
    state: &mut InnerState,
    client: &ClientConfig,
    scope: &HashSet<String>,
    issued_at: OffsetDateTime,
) -> Result<String, MockError> {
    let refresh_token = state.generate_code();
    state.refresh_tokens.insert(
        refresh_token.clone(),
        RefreshTokenEntry {
            client_id: client.client_id.clone(),
            scope: scope.clone(),
            _subject: state.user.clone(),
            _issued_at: issued_at,
        },
    );
    Ok(refresh_token)
}

fn parse_scope(scope: &Option<String>) -> Result<HashSet<String>, MockError> {
    Ok(scope
        .as_ref()
        .map(|value| {
            value
                .split_whitespace()
                .filter(|part| !part.is_empty())
                .map(|part| part.to_string())
                .collect()
        })
        .unwrap_or_default())
}

fn scope_to_string(scope: &HashSet<String>) -> String {
    let mut parts: Vec<_> = scope.iter().cloned().collect();
    parts.sort();
    parts.join(" ")
}

fn verify_code_challenge(verifier: &str, expected_challenge: &str) -> Result<bool, MockError> {
    use sha2::{Digest, Sha256};
    let hashed = Sha256::digest(verifier.as_bytes());
    let encoded = URL_SAFE_NO_PAD.encode(hashed);
    Ok(encoded == expected_challenge)
}

/// Pins the jsonwebtoken crypto provider for this process.
///
/// jsonwebtoken 10 picks its provider from crate features, and refuses to guess
/// when both `rust_crypto` and `aws_lc_rs` are on — it installs a provider whose
/// signer and verifier panic instead. This workspace hits exactly that: the mock
/// asks for `rust_crypto`, while `oci-client`'s `rustls-tls` (reached through
/// greentic-distributor-client -> greentic-flow -> greentic-pack-lib) turns on
/// `aws_lc_rs`, and Cargo unifies features across the workspace. Nothing in this
/// repo can drop either side, so the choice is made explicitly here instead.
///
/// Idempotent, and deliberately tolerant of `Err`: that only means another
/// component installed a provider first, and either one signs and verifies the
/// RS256 tokens this mock issues.
pub fn install_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER.install_default();
    });
}

fn generate_signing_keys() -> Result<SigningKeys> {
    // Every mock server start funnels through here, so this is the one place
    // that has to run before the first sign or verify.
    install_crypto_provider();

    use rsa::rand_core::OsRng;
    use rsa::traits::PublicKeyParts;
    use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPrivateKey};

    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048).context("generate RSA key")?;
    let public_key = private_key.to_public_key();

    let pem = private_key
        .to_pkcs1_pem(Default::default())
        .context("encode RSA key to PEM")?;
    let encoding =
        jsonwebtoken::EncodingKey::from_rsa_pem(pem.as_bytes()).context("create encoding key")?;
    let jwk = Jwk {
        kty: "RSA".into(),
        use_: "sig".into(),
        kid: Uuid::new_v4().to_string(),
        alg: "RS256".into(),
        n: URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be()),
        e: URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be()),
    };

    Ok(SigningKeys { encoding, jwk })
}

#[derive(Debug, Error)]
enum MockError {
    #[error("invalid_request: {0}")]
    InvalidRequest(String),
    #[error("invalid_client: {0}")]
    InvalidClient(String),
    #[error("invalid_grant: {0}")]
    InvalidGrant(String),
    #[error("invalid_scope: {0}")]
    InvalidScope(String),
    #[error("invalid_token: {0}")]
    InvalidToken(String),
    #[error("access_denied")]
    AccessDenied,
    #[error("authorization_pending")]
    AuthorizationPending,
    #[error("slow_down")]
    SlowDown,
    #[error("expired_token")]
    ExpiredToken,
    #[error("server_error: {0}")]
    ServerError(String),
}

impl MockError {
    fn invalid_request<T: Into<String>>(msg: T) -> Self {
        Self::InvalidRequest(msg.into())
    }
    fn invalid_client<T: Into<String>>(msg: T) -> Self {
        Self::InvalidClient(msg.into())
    }
    fn invalid_grant<T: Into<String>>(msg: T) -> Self {
        Self::InvalidGrant(msg.into())
    }
    fn invalid_scope<T: Into<String>>(msg: T) -> Self {
        Self::InvalidScope(msg.into())
    }
    fn invalid_token<T: Into<String>>(msg: T) -> Self {
        Self::InvalidToken(msg.into())
    }
    fn server_error<T: Into<String>>(msg: T) -> Self {
        Self::ServerError(msg.into())
    }
    fn authorization_pending() -> Self {
        Self::AuthorizationPending
    }
    fn slow_down() -> Self {
        Self::SlowDown
    }
    fn access_denied() -> Self {
        Self::AccessDenied
    }
    fn expired_token() -> Self {
        Self::ExpiredToken
    }
}

impl IntoResponse for MockError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            MockError::InvalidRequest(msg) => {
                (StatusCode::BAD_REQUEST, json_error("invalid_request", msg))
            }
            MockError::InvalidClient(msg) => {
                (StatusCode::UNAUTHORIZED, json_error("invalid_client", msg))
            }
            MockError::InvalidGrant(msg) => {
                (StatusCode::BAD_REQUEST, json_error("invalid_grant", msg))
            }
            MockError::InvalidScope(msg) => {
                (StatusCode::BAD_REQUEST, json_error("invalid_scope", msg))
            }
            MockError::InvalidToken(msg) => {
                (StatusCode::UNAUTHORIZED, json_error("invalid_token", msg))
            }
            MockError::AccessDenied => (
                StatusCode::BAD_REQUEST,
                json_error("access_denied", "user denied the request"),
            ),
            MockError::AuthorizationPending => (
                StatusCode::BAD_REQUEST,
                json_error("authorization_pending", "authorization pending"),
            ),
            MockError::SlowDown => (
                StatusCode::BAD_REQUEST,
                json_error("slow_down", "slow down"),
            ),
            MockError::ExpiredToken => (
                StatusCode::BAD_REQUEST,
                json_error("expired_token", "device code expired"),
            ),
            MockError::ServerError(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                json_error("server_error", msg),
            ),
        };
        (status, Json(body)).into_response()
    }
}

fn json_error(code: impl Into<String>, description: impl Into<String>) -> Value {
    json!({
        "error": code.into(),
        "error_description": description.into(),
    })
}
