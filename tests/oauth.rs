#![cfg(feature = "oauth")]

mod conformance;

use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use conformance::oauth::env::{ProviderKind, detect_provider};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use oauth_mock::MockServer;
use rand::{
    distr::{Alphanumeric, SampleString},
    rng,
};
use reqwest::{Client, StatusCode, header, redirect::Policy};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io;
use url::Url;

struct TestContext {
    provider_kind: ProviderKind,
    client: Client,
    mock: Option<MockServer>,
    base_url: String,
    issuer: String,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
}

impl TestContext {
    async fn new() -> Result<Self> {
        let detected = detect_provider();
        let client = Client::builder().redirect(Policy::none()).build()?;

        // At present only the embedded mock provider is automated.
        let mock = MockServer::spawn_on_free_port().await?;
        let (client_id, client_secret) = mock
            .default_client()
            .await
            .ok_or_else(|| anyhow!("mock server missing default client"))?;

        if detected.kind != ProviderKind::Mock && detected.live_enabled {
            println!(
                "LIVE_OAUTH requested for {:?}, but automated live provider flows are not yet implemented. Falling back to mock server.",
                detected.kind
            );
        }

        let base_url = mock.base_url().to_string();
        let issuer = mock.issuer().to_string();

        Ok(Self {
            provider_kind: ProviderKind::Mock,
            client,
            mock: Some(mock),
            base_url,
            issuer,
            client_id,
            client_secret,
            redirect_uri: "https://example.com/callback".into(),
        })
    }

    fn is_mock(&self) -> bool {
        matches!(self.provider_kind, ProviderKind::Mock)
    }

    fn jwks(&self) -> &Value {
        self.mock
            .as_ref()
            .map(|mock| mock.jwks())
            .expect("JWKS only available for mock provider")
    }
}

async fn context_or_skip() -> Result<Option<TestContext>> {
    match TestContext::new().await {
        Ok(ctx) => Ok(Some(ctx)),
        Err(err) if binding_permission_denied(&err) => {
            eprintln!("[skip] oauth tests require permission to bind loopback sockets: {err}");
            Ok(None)
        }
        Err(err) => Err(err),
    }
}

fn binding_permission_denied(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .is_some_and(|io_err| io_err.kind() == io::ErrorKind::PermissionDenied)
    })
}

async fn spawn_mock_server() -> Result<Option<MockServer>> {
    match MockServer::spawn_on_free_port().await {
        Ok(server) => Ok(Some(server)),
        Err(err) if binding_permission_denied(&err) => {
            eprintln!("[skip] oauth tests require permission to bind loopback sockets: {err}");
            Ok(None)
        }
        Err(err) => Err(err),
    }
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    token_type: String,
}

#[tokio::test]
async fn code_pkce_roundtrip() -> Result<()> {
    let Some(ctx) = context_or_skip().await? else {
        return Ok(());
    };
    if !ctx.is_mock() {
        return Ok(());
    }

    let verifier = random_verifier();
    let code =
        authorize_with_pkce(&ctx, &verifier, "openid email profile", Some("state-123")).await?;

    let tokens = exchange_code(&ctx, &code, &verifier).await?;
    assert_eq!(tokens.token_type, "Bearer");
    assert!(tokens.access_token.starts_with("ey"));
    assert!(tokens.id_token.is_some());
    assert!(tokens.refresh_token.is_some());

    let claims = decode_id_token(&ctx, tokens.id_token.as_ref().unwrap())?;
    assert_eq!(claims.iss, ctx.issuer);
    assert_eq!(claims.aud, ctx.client_id);
    assert!(claims.exp > claims.iat);
    assert!(claims.scope.unwrap_or_default().contains("openid"));
    Ok(())
}

#[tokio::test]
async fn client_credentials_roundtrip() -> Result<()> {
    let Some(ctx) = context_or_skip().await? else {
        return Ok(());
    };
    if !ctx.is_mock() {
        return Ok(());
    }

    let tokens = ctx
        .client
        .post(format!("{}/token", ctx.base_url))
        .basic_auth(&ctx.client_id, Some(&ctx.client_secret))
        .form(&[
            ("grant_type", "client_credentials"),
            ("scope", "openid email"),
        ])
        .send()
        .await?
        .error_for_status()?
        .json::<TokenResponse>()
        .await?;

    assert_eq!(tokens.token_type, "Bearer");
    assert!(tokens.id_token.is_none());
    assert!(tokens.refresh_token.is_none());
    Ok(())
}

#[tokio::test]
async fn refresh_token_works() -> Result<()> {
    let Some(ctx) = context_or_skip().await? else {
        return Ok(());
    };
    if !ctx.is_mock() {
        return Ok(());
    }

    let verifier = random_verifier();
    let code = authorize_with_pkce(&ctx, &verifier, "openid email profile", None).await?;
    let initial = exchange_code(&ctx, &code, &verifier).await?;
    let refresh = initial.refresh_token.clone().unwrap();

    let refreshed = ctx
        .client
        .post(format!("{}/token", ctx.base_url))
        .basic_auth(&ctx.client_id, Some(&ctx.client_secret))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh.as_str()),
        ])
        .send()
        .await?
        .error_for_status()?
        .json::<TokenResponse>()
        .await?;

    assert_ne!(initial.access_token, refreshed.access_token);
    assert_ne!(initial.refresh_token, refreshed.refresh_token);

    let replay = ctx
        .client
        .post(format!("{}/token", ctx.base_url))
        .basic_auth(&ctx.client_id, Some(&ctx.client_secret))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh.as_str()),
        ])
        .send()
        .await?;
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    let err: Value = replay.json().await?;
    assert_eq!(err["error"], "invalid_grant");
    Ok(())
}

#[tokio::test]
async fn device_code_flow() -> Result<()> {
    let Some(ctx) = context_or_skip().await? else {
        return Ok(());
    };
    if !ctx.is_mock() {
        return Ok(());
    }
    let mock = ctx
        .mock
        .as_ref()
        .ok_or_else(|| anyhow!("device code flow requires mock server"))?;

    let device = ctx
        .client
        .post(format!("{}/device_authorization", ctx.base_url))
        .form(&[
            ("client_id", ctx.client_id.as_str()),
            ("scope", "openid email"),
        ])
        .send()
        .await?
        .error_for_status()?
        .json::<Value>()
        .await?;

    let device_code = device["device_code"].as_str().unwrap().to_string();
    let user_code = device["user_code"].as_str().unwrap().to_string();

    for _ in 0..2 {
        let pending = ctx
            .client
            .post(format!("{}/token", ctx.base_url))
            .basic_auth(&ctx.client_id, Some(&ctx.client_secret))
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", device_code.as_str()),
            ])
            .send()
            .await?;
        assert_eq!(pending.status(), StatusCode::BAD_REQUEST);
        let body: Value = pending.json().await?;
        assert!(
            body["error"] == "authorization_pending" || body["error"] == "slow_down",
            "unexpected response: {body}"
        );
    }

    mock.approve_device_code(&user_code).await?;

    let token = ctx
        .client
        .post(format!("{}/token", ctx.base_url))
        .basic_auth(&ctx.client_id, Some(&ctx.client_secret))
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", device_code.as_str()),
        ])
        .send()
        .await?
        .error_for_status()?
        .json::<TokenResponse>()
        .await?;

    assert!(token.access_token.starts_with("ey"));
    Ok(())
}

#[tokio::test]
async fn scope_enforcement() -> Result<()> {
    let Some(ctx) = context_or_skip().await? else {
        return Ok(());
    };
    if !ctx.is_mock() {
        return Ok(());
    }

    let response = ctx
        .client
        .get(format!("{}/authorize", ctx.base_url))
        .query(&[
            ("response_type", "code"),
            ("client_id", ctx.client_id.as_str()),
            ("redirect_uri", ctx.redirect_uri.as_str()),
            ("scope", "unapproved"),
            ("code_challenge", "ignored"),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = response.json().await?;
    assert_eq!(body["error"], "invalid_scope");
    Ok(())
}

#[tokio::test]
async fn jwks_key_rotation_ok() -> Result<()> {
    let Some(server_a) = spawn_mock_server().await? else {
        return Ok(());
    };
    let kid_a = server_a.jwks()["keys"][0]["kid"]
        .as_str()
        .unwrap()
        .to_string();
    drop(server_a);

    let Some(server_b) = spawn_mock_server().await? else {
        return Ok(());
    };
    let kid_b = server_b.jwks()["keys"][0]["kid"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(kid_a, kid_b, "each mock server run should rotate keys");
    Ok(())
}

fn random_verifier() -> String {
    let mut rng = rng();
    Alphanumeric.sample_string(&mut rng, 64)
}

fn pkce_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

async fn authorize_with_pkce(
    ctx: &TestContext,
    verifier: &str,
    scope: &str,
    state: Option<&str>,
) -> Result<String> {
    let challenge = pkce_challenge(verifier);
    let mut request = ctx
        .client
        .get(format!("{}/authorize", ctx.base_url))
        .query(&[
            ("response_type", "code"),
            ("client_id", ctx.client_id.as_str()),
            ("redirect_uri", ctx.redirect_uri.as_str()),
            ("scope", scope),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
        ]);
    if let Some(state) = state {
        request = request.query(&[("state", state)]);
    }

    let response = request.send().await?;
    let status = response.status();
    if status != StatusCode::SEE_OTHER {
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow!("expected redirect, got {status} {body}"));
    }
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| anyhow!("redirect missing Location header"))?;
    let redirect = Url::parse(location)?;
    if let Some(expected_state) = state {
        let returned_state = redirect
            .query_pairs()
            .find(|(k, _)| k == "state")
            .map(|(_, v)| v.to_string());
        if returned_state.as_deref() != Some(expected_state) {
            return Err(anyhow!(
                "state mismatch; expected {expected_state:?}, got {returned_state:?}"
            ));
        }
    }

    let code = redirect
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.to_string())
        .ok_or_else(|| anyhow!("redirect missing authorization code"))?;
    Ok(code)
}

async fn exchange_code(ctx: &TestContext, code: &str, verifier: &str) -> Result<TokenResponse> {
    Ok(ctx
        .client
        .post(format!("{}/token", ctx.base_url))
        .basic_auth(&ctx.client_id, Some(&ctx.client_secret))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", ctx.redirect_uri.as_str()),
            ("code_verifier", verifier),
        ])
        .send()
        .await?
        .error_for_status()?
        .json::<TokenResponse>()
        .await?)
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone)]
struct IdTokenClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: i64,
    iat: i64,
    email: String,
    preferred_username: String,
    scope: Option<String>,
}

fn decode_id_token(ctx: &TestContext, token: &str) -> Result<IdTokenClaims> {
    let jwk = &ctx.jwks()["keys"][0];
    let n = jwk["n"]
        .as_str()
        .ok_or_else(|| anyhow!("JWKS missing modulus"))?;
    let e = jwk["e"]
        .as_str()
        .ok_or_else(|| anyhow!("JWKS missing exponent"))?;
    let decoding_key = DecodingKey::from_rsa_components(n, e)
        .map_err(|err| anyhow!("failed to build decoding key: {err}"))?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(std::slice::from_ref(&ctx.client_id));
    validation.set_issuer(std::slice::from_ref(&ctx.issuer));

    let token_data = jsonwebtoken::decode::<IdTokenClaims>(token, &decoding_key, &validation)?;
    Ok(token_data.claims)
}
