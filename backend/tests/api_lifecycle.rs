use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use chrono::{Duration as ChronoDuration, Utc};
use hybridcipher_secretlink_server::{build_app, SecretLinkConfig};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tempfile::TempDir;
use tower::ServiceExt;
use uuid::Uuid;

fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

fn build_create_request(share_id: Uuid, admin_token_hash: String, one_time: bool) -> Value {
    json!({
        "share_id": share_id,
        "ciphertext_b64": "AQIDBAUGBwgJ",
        "nonce_b64": "AAECAwQFBgcICQoL",
        "expires_at": (Utc::now() + ChronoDuration::hours(1)).to_rfc3339(),
        "one_time": one_time,
        "aad_version": 1,
        "admin_token_hash": admin_token_hash
    })
}

async fn spawn_app(claim_lease: Duration) -> (TempDir, axum::Router) {
    let tempdir = TempDir::new().expect("tempdir");
    let db_path = tempdir.path().join("secretlink.sqlite");
    let mut config = SecretLinkConfig::for_tests(format!("sqlite://{}", db_path.display()));
    config.claim_lease = claim_lease;
    let app = build_app(config).await.expect("build app");
    (tempdir, app)
}

async fn json_response(response: axum::response::Response) -> Value {
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response bytes");
    serde_json::from_slice(&body).expect("json response")
}

async fn text_response(response: axum::response::Response) -> String {
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response bytes");
    String::from_utf8(body.to_vec()).expect("utf8 response")
}

#[tokio::test]
async fn create_share_and_status_flow_starts_available() {
    let (_tempdir, app) = spawn_app(Duration::from_secs(60)).await;
    let share_id = Uuid::new_v4();
    let admin_token = "admin-token-1";
    let request = Request::builder()
        .uri("/api/v1/shares")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            build_create_request(share_id, hash_token(admin_token), true).to_string(),
        ))
        .expect("create request");

    let response = app.clone().oneshot(request).await.expect("create response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let create_json = json_response(response).await;
    assert_eq!(create_json["share_id"], share_id.to_string());
    assert_eq!(create_json["status"], "available");

    let status_request = Request::builder()
        .uri(format!("/api/v1/shares/{share_id}/status"))
        .method("GET")
        .header("x-secretlink-admin-token", admin_token)
        .body(Body::empty())
        .expect("status request");

    let status_response = app.oneshot(status_request).await.expect("status response");
    assert_eq!(status_response.status(), StatusCode::OK);
    let status_json = json_response(status_response).await;
    assert_eq!(status_json["share_id"], share_id.to_string());
    assert_eq!(status_json["status"], "available");
    assert_eq!(status_json["one_time"], true);
}

#[tokio::test]
async fn one_time_claim_consume_blocks_second_claim() {
    let (_tempdir, app) = spawn_app(Duration::from_secs(60)).await;
    let share_id = Uuid::new_v4();
    let admin_token = "admin-token-2";

    let create_request = Request::builder()
        .uri("/api/v1/shares")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            build_create_request(share_id, hash_token(admin_token), true).to_string(),
        ))
        .expect("create request");
    let create_response = app
        .clone()
        .oneshot(create_request)
        .await
        .expect("create response");
    assert_eq!(create_response.status(), StatusCode::CREATED);

    let claim_request = Request::builder()
        .uri(format!("/api/v1/shares/{share_id}/claim"))
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .expect("claim request");
    let claim_response = app
        .clone()
        .oneshot(claim_request)
        .await
        .expect("claim response");
    assert_eq!(claim_response.status(), StatusCode::OK);
    let claim_json = json_response(claim_response).await;
    let claim_token = claim_json["claim_token"]
        .as_str()
        .expect("claim token")
        .to_string();

    let consume_request = Request::builder()
        .uri(format!("/api/v1/shares/{share_id}/consume"))
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(json!({ "claim_token": claim_token }).to_string()))
        .expect("consume request");
    let consume_response = app
        .clone()
        .oneshot(consume_request)
        .await
        .expect("consume response");
    assert_eq!(consume_response.status(), StatusCode::OK);

    let second_claim_request = Request::builder()
        .uri(format!("/api/v1/shares/{share_id}/claim"))
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .expect("second claim request");
    let second_claim_response = app
        .clone()
        .oneshot(second_claim_request)
        .await
        .expect("second claim response");
    assert_eq!(second_claim_response.status(), StatusCode::NOT_FOUND);
    let unavailable_json = json_response(second_claim_response).await;
    assert_eq!(unavailable_json["error"], "share_unavailable");

    let status_request = Request::builder()
        .uri(format!("/api/v1/shares/{share_id}/status"))
        .method("GET")
        .header("x-secretlink-admin-token", admin_token)
        .body(Body::empty())
        .expect("status request");
    let status_response = app.oneshot(status_request).await.expect("status response");
    let status_json = json_response(status_response).await;
    assert_eq!(status_json["status"], "consumed");
}

#[tokio::test]
async fn static_share_route_does_not_consume_or_claim() {
    let (_tempdir, app) = spawn_app(Duration::from_secs(60)).await;
    let share_id = Uuid::new_v4();
    let admin_token = "admin-token-3";
    let create_request = Request::builder()
        .uri("/api/v1/shares")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            build_create_request(share_id, hash_token(admin_token), true).to_string(),
        ))
        .expect("create request");
    let create_response = app
        .clone()
        .oneshot(create_request)
        .await
        .expect("create response");
    assert_eq!(create_response.status(), StatusCode::CREATED);

    let open_request = Request::builder()
        .uri(format!("/s/{share_id}"))
        .method("GET")
        .body(Body::empty())
        .expect("open request");
    let open_response = app.clone().oneshot(open_request).await.expect("open response");
    assert_eq!(open_response.status(), StatusCode::OK);

    let status_request = Request::builder()
        .uri(format!("/api/v1/shares/{share_id}/status"))
        .method("GET")
        .header("x-secretlink-admin-token", admin_token)
        .body(Body::empty())
        .expect("status request");
    let status_response = app.oneshot(status_request).await.expect("status response");
    let status_json = json_response(status_response).await;
    assert_eq!(status_json["status"], "available");
}

#[tokio::test]
async fn revoke_invalidates_active_claim() {
    let (_tempdir, app) = spawn_app(Duration::from_secs(60)).await;
    let share_id = Uuid::new_v4();
    let admin_token = "admin-token-4";
    let create_request = Request::builder()
        .uri("/api/v1/shares")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            build_create_request(share_id, hash_token(admin_token), true).to_string(),
        ))
        .expect("create request");
    let create_response = app
        .clone()
        .oneshot(create_request)
        .await
        .expect("create response");
    assert_eq!(create_response.status(), StatusCode::CREATED);

    let claim_request = Request::builder()
        .uri(format!("/api/v1/shares/{share_id}/claim"))
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .expect("claim request");
    let claim_response = app
        .clone()
        .oneshot(claim_request)
        .await
        .expect("claim response");
    let claim_json = json_response(claim_response).await;
    let claim_token = claim_json["claim_token"]
        .as_str()
        .expect("claim token")
        .to_string();

    let revoke_request = Request::builder()
        .uri(format!("/api/v1/shares/{share_id}/revoke"))
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(json!({ "admin_token": admin_token }).to_string()))
        .expect("revoke request");
    let revoke_response = app
        .clone()
        .oneshot(revoke_request)
        .await
        .expect("revoke response");
    assert_eq!(revoke_response.status(), StatusCode::OK);

    let consume_request = Request::builder()
        .uri(format!("/api/v1/shares/{share_id}/consume"))
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(json!({ "claim_token": claim_token }).to_string()))
        .expect("consume request");
    let consume_response = app
        .clone()
        .oneshot(consume_request)
        .await
        .expect("consume response");
    assert_eq!(consume_response.status(), StatusCode::NOT_FOUND);
    let consume_json = json_response(consume_response).await;
    assert_eq!(consume_json["error"], "share_unavailable");
}

#[tokio::test]
async fn robots_txt_disallows_api_and_secret_routes_and_points_to_sitemap() {
    let (_tempdir, app) = spawn_app(Duration::from_secs(60)).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/robots.txt")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("text/plain; charset=utf-8")
    );
    let text = text_response(response).await;
    assert!(text.contains("User-agent: *"));
    assert!(text.contains("Disallow: /api/"));
    assert!(text.contains("Disallow: /s/"));
    assert!(text.contains("Disallow: /manage/"));
    assert!(text.contains("Sitemap: https://secretlink.hybridcipher.com/sitemap.xml"));
}

#[tokio::test]
async fn sitemap_xml_lists_only_public_marketing_routes() {
    let (_tempdir, app) = spawn_app(Duration::from_secs(60)).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/sitemap.xml")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/xml")
    );
    let text = text_response(response).await;
    assert_eq!(text.matches("<url>").count(), 4);
    assert!(text.contains("<loc>https://secretlink.hybridcipher.com/</loc>"));
    assert!(text.contains("<loc>https://secretlink.hybridcipher.com/how-it-works</loc>"));
    assert!(text.contains("<loc>https://secretlink.hybridcipher.com/privacy</loc>"));
    assert!(text.contains("<loc>https://secretlink.hybridcipher.com/terms</loc>"));
    assert!(!text.contains("/s/"));
    assert!(!text.contains("/manage/"));
}

#[tokio::test]
async fn public_pages_include_canonical_meta_without_noindex() {
    let (_tempdir, app) = spawn_app(Duration::from_secs(60)).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/how-it-works")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let text = text_response(response).await;
    assert!(text.contains(
        r#"<link rel="canonical" href="https://secretlink.hybridcipher.com/how-it-works">"#
    ));
    assert!(text.contains(r#"<meta name="description" content=""#));
    assert!(!text.contains(r#"<meta name="robots" content="noindex, nofollow">"#));
}

#[tokio::test]
async fn secret_html_routes_include_noindex_meta() {
    let (_tempdir, app) = spawn_app(Duration::from_secs(60)).await;
    let share_id = Uuid::new_v4();

    for route in [format!("/s/{share_id}"), format!("/manage/{share_id}")] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&route)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK, "route {route}");
        let text = text_response(response).await;
        assert!(text.contains(r#"<meta name="robots" content="noindex, nofollow">"#));
    }
}

#[tokio::test]
async fn api_responses_send_x_robots_tag_noindex() {
    let (_tempdir, app) = spawn_app(Duration::from_secs(60)).await;
    let share_id = Uuid::new_v4();
    let admin_token = "admin-token-seo";

    let create_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/shares")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(
                    build_create_request(share_id, hash_token(admin_token), true).to_string(),
                ))
                .expect("create request"),
        )
        .await
        .expect("create response");
    assert_eq!(create_response.status(), StatusCode::CREATED);
    assert_eq!(
        create_response.headers().get("x-robots-tag").and_then(|value| value.to_str().ok()),
        Some("noindex, nofollow")
    );

    let status_response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/shares/{share_id}/status"))
                .method("GET")
                .header("x-secretlink-admin-token", admin_token)
                .body(Body::empty())
                .expect("status request"),
        )
        .await
        .expect("status response");
    assert_eq!(status_response.status(), StatusCode::OK);
    assert_eq!(
        status_response.headers().get("x-robots-tag").and_then(|value| value.to_str().ok()),
        Some("noindex, nofollow")
    );
}

#[tokio::test]
async fn claim_lease_timeout_returns_share_to_available() {
    let (_tempdir, app) = spawn_app(Duration::from_millis(25)).await;
    let share_id = Uuid::new_v4();
    let admin_token = "admin-token-5";
    let create_request = Request::builder()
        .uri("/api/v1/shares")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            build_create_request(share_id, hash_token(admin_token), true).to_string(),
        ))
        .expect("create request");
    let create_response = app
        .clone()
        .oneshot(create_request)
        .await
        .expect("create response");
    assert_eq!(create_response.status(), StatusCode::CREATED);

    let claim_request = Request::builder()
        .uri(format!("/api/v1/shares/{share_id}/claim"))
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .expect("claim request");
    let first_claim = app
        .clone()
        .oneshot(claim_request)
        .await
        .expect("first claim response");
    assert_eq!(first_claim.status(), StatusCode::OK);

    tokio::time::sleep(Duration::from_millis(40)).await;

    let second_claim_request = Request::builder()
        .uri(format!("/api/v1/shares/{share_id}/claim"))
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .expect("second claim request");
    let second_claim = app
        .clone()
        .oneshot(second_claim_request)
        .await
        .expect("second claim response");
    assert_eq!(second_claim.status(), StatusCode::OK);

    let status_request = Request::builder()
        .uri(format!("/api/v1/shares/{share_id}/status"))
        .method("GET")
        .header("x-secretlink-admin-token", admin_token)
        .body(Body::empty())
        .expect("status request");
    let status_response = app.oneshot(status_request).await.expect("status response");
    let status_json = json_response(status_response).await;
    assert_eq!(status_json["status"], "claimed");
}

#[tokio::test]
async fn claim_hides_difference_between_missing_and_consumed() {
    let (_tempdir, app) = spawn_app(Duration::from_secs(60)).await;
    let missing_id = Uuid::new_v4();

    let missing_request = Request::builder()
        .uri(format!("/api/v1/shares/{missing_id}/claim"))
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .expect("missing claim request");
    let missing_response = app
        .clone()
        .oneshot(missing_request)
        .await
        .expect("missing claim response");
    assert_eq!(missing_response.status(), StatusCode::NOT_FOUND);
    let missing_json = json_response(missing_response).await;

    let share_id = Uuid::new_v4();
    let admin_token = "admin-token-6";
    let create_request = Request::builder()
        .uri("/api/v1/shares")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            build_create_request(share_id, hash_token(admin_token), true).to_string(),
        ))
        .expect("create request");
    let create_response = app
        .clone()
        .oneshot(create_request)
        .await
        .expect("create response");
    assert_eq!(create_response.status(), StatusCode::CREATED);

    let claim_request = Request::builder()
        .uri(format!("/api/v1/shares/{share_id}/claim"))
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .expect("claim request");
    let claim_response = app
        .clone()
        .oneshot(claim_request)
        .await
        .expect("claim response");
    let claim_json = json_response(claim_response).await;
    let claim_token = claim_json["claim_token"]
        .as_str()
        .expect("claim token")
        .to_string();

    let consume_request = Request::builder()
        .uri(format!("/api/v1/shares/{share_id}/consume"))
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(json!({ "claim_token": claim_token }).to_string()))
        .expect("consume request");
    let consume_response = app
        .clone()
        .oneshot(consume_request)
        .await
        .expect("consume response");
    assert_eq!(consume_response.status(), StatusCode::OK);

    let consumed_claim_request = Request::builder()
        .uri(format!("/api/v1/shares/{share_id}/claim"))
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .expect("consumed claim request");
    let consumed_claim_response = app
        .clone()
        .oneshot(consumed_claim_request)
        .await
        .expect("consumed claim response");
    assert_eq!(consumed_claim_response.status(), StatusCode::NOT_FOUND);
    let consumed_json = json_response(consumed_claim_response).await;

    assert_eq!(missing_json, consumed_json);
}
