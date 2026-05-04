mod assets;
mod rate_limit;
mod storage;

use axum::{
    extract::{Path, Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::{from_fn, from_fn_with_state, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use std::{
    path::{Path as FsPath, PathBuf},
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use storage::{CleanupSummary, StoredShare, Store};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct SecretLinkConfig {
    pub database_url: String,
    pub bind_addr: String,
    pub web_dev_dir: Option<PathBuf>,
    pub claim_lease: Duration,
    pub cleanup_interval: Duration,
    pub tombstone_retention: Duration,
}

impl SecretLinkConfig {
    pub fn for_tests(database_url: impl Into<String>) -> Self {
        Self {
            database_url: database_url.into(),
            bind_addr: "127.0.0.1:0".to_string(),
            web_dev_dir: None,
            claim_lease: Duration::from_secs(60),
            cleanup_interval: Duration::from_secs(30),
            tombstone_retention: Duration::from_secs(60 * 60 * 24),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ShareStatus {
    Available,
    Claimed,
    Consumed,
    Revoked,
    Expired,
}

impl ShareStatus {
    fn as_str(self) -> &'static str {
        match self {
            ShareStatus::Available => "available",
            ShareStatus::Claimed => "claimed",
            ShareStatus::Consumed => "consumed",
            ShareStatus::Revoked => "revoked",
            ShareStatus::Expired => "expired",
        }
    }
}

impl std::fmt::Display for ShareStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for ShareStatus {
    type Err = AppError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "available" => Ok(Self::Available),
            "claimed" => Ok(Self::Claimed),
            "consumed" => Ok(Self::Consumed),
            "revoked" => Ok(Self::Revoked),
            "expired" => Ok(Self::Expired),
            other => Err(AppError::internal(format!("invalid share status {other}"))),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateShareRequest {
    pub share_id: Uuid,
    pub ciphertext_b64: String,
    pub nonce_b64: String,
    pub expires_at: DateTime<Utc>,
    pub one_time: bool,
    pub aad_version: u32,
    pub admin_token_hash: String,
}

#[derive(Debug, Serialize)]
pub struct CreateShareResponse {
    pub share_id: Uuid,
    pub status: ShareStatus,
}

#[derive(Debug, Serialize)]
pub struct ClaimShareResponse {
    pub share_id: Uuid,
    pub status: ShareStatus,
    pub ciphertext_b64: String,
    pub nonce_b64: String,
    pub expires_at: DateTime<Utc>,
    pub one_time: bool,
    pub aad_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ConsumeShareRequest {
    pub claim_token: String,
}

#[derive(Debug, Deserialize)]
pub struct RevokeShareRequest {
    pub admin_token: String,
}

#[derive(Debug, Serialize)]
pub struct ShareStatusResponse {
    pub share_id: Uuid,
    pub status: ShareStatus,
    pub expires_at: DateTime<Utc>,
    pub one_time: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumed_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
struct StatusMutationResponse {
    share_id: Uuid,
    status: ShareStatus,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct ErrorResponse {
    error: &'static str,
}

#[derive(Clone)]
struct AppState {
    store: Store,
    assets: assets::AssetCatalog,
    limiter: Arc<rate_limit::RateLimiter>,
}

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{message}")]
    Http {
        status: StatusCode,
        message: &'static str,
    },
    #[error("{0}")]
    Validation(String),
    #[error("{0}")]
    Internal(String),
}

impl AppError {
    fn unavailable() -> Self {
        Self::Http {
            status: StatusCode::NOT_FOUND,
            message: "share_unavailable",
        }
    }

    fn not_found(message: &'static str) -> Self {
        Self::Http {
            status: StatusCode::NOT_FOUND,
            message,
        }
    }

    fn bad_request(message: &'static str) -> Self {
        Self::Http {
            status: StatusCode::BAD_REQUEST,
            message,
        }
    }

    fn too_many_requests() -> Self {
        Self::Http {
            status: StatusCode::TOO_MANY_REQUESTS,
            message: "rate_limited",
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self::Internal(message.into())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::Http { status, message } => {
                let mut response = (status, Json(ErrorResponse { error: message })).into_response();
                apply_response_headers(response.headers_mut());
                response
            }
            AppError::Validation(message) => {
                let mut response = (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "invalid_request", "message": message })),
                )
                    .into_response();
                apply_response_headers(response.headers_mut());
                response
            }
            AppError::Internal(message) => {
                tracing::error!("secretlink internal error: {message}");
                let mut response = (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "internal_error",
                    }),
                )
                    .into_response();
                apply_response_headers(response.headers_mut());
                response
            }
        }
    }
}

impl From<sqlx::Error> for AppError {
    fn from(error: sqlx::Error) -> Self {
        Self::internal(error.to_string())
    }
}

pub async fn build_app(config: SecretLinkConfig) -> anyhow::Result<Router> {
    let connect_options = SqliteConnectOptions::from_str(&config.database_url)?
        .create_if_missing(true)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5))
        .journal_mode(SqliteJournalMode::Wal);
    let pool = SqlitePoolOptions::new()
        .max_connections(4)
        .connect_with(connect_options)
        .await?;

    let store = Store::new(pool, config.claim_lease, config.tombstone_retention);
    store.initialize().await?;

    let assets = assets::AssetCatalog::new(config.web_dev_dir.clone());
    let limiter = rate_limit::RateLimiter::default();
    let state = Arc::new(AppState {
        store,
        assets,
        limiter: Arc::new(limiter),
    });

    spawn_cleanup_task(state.clone(), config.cleanup_interval);

    let api = Router::new()
        .route("/shares", post(create_share))
        .route("/shares/:id/claim", post(claim_share))
        .route("/shares/:id/consume", post(consume_share))
        .route("/shares/:id/revoke", post(revoke_share))
        .route("/shares/:id/status", get(share_status))
        .layer(from_fn_with_state(state.clone(), api_rate_limit_middleware));

    let router = Router::new()
        .nest("/api/v1", api)
        .route("/", get(render_index))
        .route("/how-it-works", get(render_index))
        .route("/privacy", get(render_index))
        .route("/terms", get(render_index))
        .route("/s/:id", get(render_index))
        .route("/manage/:id", get(render_index))
        .route("/src/app.js", get(serve_asset))
        .route("/src/api.js", get(serve_asset))
        .route("/src/crypto.js", get(serve_asset))
        .route("/src/router.js", get(serve_asset))
        .route("/styles.css", get(serve_asset))
        .route("/favicon.svg", get(serve_asset))
        .layer(ServiceBuilder::new().layer(TraceLayer::new_for_http()))
        .layer(from_fn(security_headers_middleware))
        .with_state(state);

    Ok(router)
}

fn spawn_cleanup_task(state: Arc<AppState>, cleanup_interval: Duration) {
    tokio::spawn(async move {
        let interval = if cleanup_interval.is_zero() {
            Duration::from_secs(30)
        } else {
            cleanup_interval
        };

        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            match state.store.run_cleanup().await {
                Ok(CleanupSummary {
                    expired,
                    released_claims,
                    purged,
                }) if expired > 0 || released_claims > 0 || purged > 0 => {
                    tracing::debug!(
                        expired,
                        released_claims,
                        purged,
                        "secretlink cleanup pass completed"
                    );
                }
                Ok(_) => {}
                Err(error) => tracing::warn!("secretlink cleanup failed: {error}"),
            }
        }
    });
}

async fn create_share(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateShareRequest>,
) -> Result<impl IntoResponse, AppError> {
    validate_create_request(&payload)?;
    let ciphertext = decode_b64("ciphertext_b64", &payload.ciphertext_b64)?;
    let nonce = decode_b64("nonce_b64", &payload.nonce_b64)?;

    state
        .store
        .create_share(
            payload.share_id,
            ciphertext,
            nonce,
            payload.expires_at,
            payload.one_time,
            payload.aad_version,
            payload.admin_token_hash,
        )
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(CreateShareResponse {
            share_id: payload.share_id,
            status: ShareStatus::Available,
        }),
    ))
}

async fn claim_share(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let claim = state
        .store
        .claim_share(id)
        .await?
        .ok_or_else(AppError::unavailable)?;

    Ok(Json(ClaimShareResponse {
        share_id: claim.share_id,
        status: claim.status,
        ciphertext_b64: URL_SAFE_NO_PAD.encode(claim.ciphertext),
        nonce_b64: URL_SAFE_NO_PAD.encode(claim.nonce),
        expires_at: claim.expires_at,
        one_time: claim.one_time,
        aad_version: claim.aad_version,
        claim_token: claim.claim_token,
    }))
}

async fn consume_share(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Json(payload): Json<ConsumeShareRequest>,
) -> Result<impl IntoResponse, AppError> {
    if payload.claim_token.trim().is_empty() {
        return Err(AppError::bad_request("claim_token_required"));
    }

    let status = state
        .store
        .consume_share(id, &payload.claim_token)
        .await?
        .ok_or_else(AppError::unavailable)?;

    Ok(Json(StatusMutationResponse { share_id: id, status }))
}

async fn revoke_share(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Json(payload): Json<RevokeShareRequest>,
) -> Result<impl IntoResponse, AppError> {
    if payload.admin_token.trim().is_empty() {
        return Err(AppError::bad_request("admin_token_required"));
    }

    let status = state
        .store
        .revoke_share(id, &payload.admin_token)
        .await?
        .ok_or_else(|| AppError::not_found("share_not_found"))?;

    Ok(Json(StatusMutationResponse { share_id: id, status }))
}

async fn share_status(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    request: Request,
) -> Result<impl IntoResponse, AppError> {
    let admin_token = request
        .headers()
        .get("x-secretlink-admin-token")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| AppError::bad_request("admin_token_required"))?;

    let share = state
        .store
        .share_status(id, admin_token)
        .await?
        .ok_or_else(|| AppError::not_found("share_not_found"))?;

    Ok(Json(ShareStatusResponse::from(share)))
}

async fn render_index(State(state): State<Arc<AppState>>) -> Result<Html<String>, AppError> {
    let html = state.assets.index_html().await?;
    Ok(Html(html))
}

async fn serve_asset(
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Result<Response, AppError> {
    let asset_name = request.uri().path().trim_start_matches('/');
    let asset = state
        .assets
        .read(asset_name)
        .await?
        .ok_or_else(|| AppError::not_found("asset_not_found"))?;

    let mut response = ([(header::CONTENT_TYPE, asset.content_type)], asset.body).into_response();
    apply_response_headers(response.headers_mut());
    Ok(response)
}

async fn security_headers_middleware(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    apply_response_headers(response.headers_mut());
    response
}

async fn api_rate_limit_middleware(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let ip = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "127.0.0.1".to_string());

    let path = request.uri().path().to_string();
    let category = if path.ends_with("/claim") {
        rate_limit::LimitCategory::Claim
    } else if path.ends_with("/status") || path.ends_with("/revoke") {
        rate_limit::LimitCategory::Manage
    } else {
        rate_limit::LimitCategory::Create
    };

    if !state.limiter.allow(category, &ip) {
        return Err(AppError::too_many_requests());
    }

    Ok(next.run(request).await)
}

fn validate_create_request(payload: &CreateShareRequest) -> Result<(), AppError> {
    if payload.expires_at <= Utc::now() {
        return Err(AppError::Validation(
            "expires_at must be in the future".to_string(),
        ));
    }
    if payload.aad_version == 0 {
        return Err(AppError::Validation(
            "aad_version must be non-zero".to_string(),
        ));
    }
    if payload.admin_token_hash.len() != 64
        || !payload
            .admin_token_hash
            .chars()
            .all(|ch| ch.is_ascii_hexdigit())
    {
        return Err(AppError::Validation(
            "admin_token_hash must be a 64-character hex sha256 digest".to_string(),
        ));
    }
    Ok(())
}

fn decode_b64(field: &'static str, value: &str) -> Result<Vec<u8>, AppError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| AppError::Validation(format!("{field} is not valid base64url")))
}

fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

fn apply_response_headers(headers: &mut axum::http::HeaderMap) {
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate, max-age=0"),
    );
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(header::EXPIRES, HeaderValue::from_static("0"));
    headers.insert(
        header::HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        header::HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
        ),
    );
    headers.insert(
        header::HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static(
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=()",
        ),
    );
}

impl From<StoredShare> for ShareStatusResponse {
    fn from(share: StoredShare) -> Self {
        Self {
            share_id: share.share_id,
            status: share.status,
            expires_at: share.expires_at,
            one_time: share.one_time,
            created_at: share.created_at,
            updated_at: share.updated_at,
            claim_expires_at: share.claim_expires_at,
            consumed_at: share.consumed_at,
            revoked_at: share.revoked_at,
        }
    }
}

pub(crate) fn repo_public_dir() -> PathBuf {
    let path = FsPath::new(env!("CARGO_MANIFEST_DIR"))
        .join("../frontend/public")
        .to_path_buf();
    std::fs::canonicalize(&path).unwrap_or(path)
}

pub(crate) fn repo_src_dir() -> PathBuf {
    let path = FsPath::new(env!("CARGO_MANIFEST_DIR"))
        .join("../frontend/src")
        .to_path_buf();
    std::fs::canonicalize(&path).unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::{build_app, repo_public_dir, SecretLinkConfig};
    use axum::{body::Body, http::{Request, StatusCode}};
    use tempfile::tempdir;
    use tower::util::ServiceExt;

    #[test]
    fn secretlink_default_dev_asset_root_uses_standalone_frontend_public_dir() {
        let path = repo_public_dir();
        let normalized = path.to_string_lossy().replace('\\', "/");
        assert!(
            normalized.ends_with("frontend/public"),
            "expected standalone frontend public dir, got {normalized}"
        );
    }

    #[tokio::test]
    async fn secretlink_serves_public_policy_routes() {
        let tempdir = tempdir().expect("tempdir");
        let database_path = tempdir.path().join("secretlink-test.db");
        let config = SecretLinkConfig::for_tests(format!("sqlite://{}", database_path.display()));
        let app = build_app(config).await.expect("app");

        for route in ["/privacy", "/terms", "/how-it-works"] {
            let response = app
                .clone()
                .oneshot(Request::builder().uri(route).body(Body::empty()).expect("request"))
                .await
                .expect("response");

            assert_eq!(
                response.status(),
                StatusCode::OK,
                "expected {route} to resolve through the public app shell"
            );
        }
    }
}
