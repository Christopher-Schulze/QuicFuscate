//! Admin HTTP API client with CSRF protection.

use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, CONTENT_TYPE};
use serde::de::DeserializeOwned;

const CSRF_TOKEN_HEADER: &str = "X-CSRF-Token";
const CSRF_NONCE_HEADER: &str = "X-CSRF-Nonce";
const CSRF_STORAGE_KEY: &str = "qf_admin_csrf_token";

const SERVER_ERROR_PATTERN: &[&str] = &["500", "HTTP 500", "Internal Server Error", "temporarily unavailable"];
const GENERIC_FAILURE_PATTERN: &[&str] = &["request failed", "could not", "failed", "no status"];
const NOT_FOUND_PATTERN: &str = "not found";

#[derive(Debug, Clone)]
pub struct ApiError {
    pub message: String,
    pub status: Option<u16>,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ApiError {}

impl ApiError {
    pub fn new(message: impl Into<String>, status: Option<u16>) -> Self {
        Self {
            message: message.into(),
            status,
        }
    }
}

pub fn is_auth_error(e: &ApiError) -> bool {
    e.status == Some(401)
}

pub fn sanitize_error_message(message: &str, fallback: &str) -> String {
    let raw = message.trim();
    let fallback_text = fallback.trim();

    if raw.is_empty() {
        if matches_generic_failure(fallback_text) {
            return String::new();
        }
        return fallback_text.to_string();
    }
    if matches_server_error(raw) || raw.contains(NOT_FOUND_PATTERN) || matches_generic_failure(raw) {
        return String::new();
    }
    raw.to_string()
}

fn matches_server_error(text: &str) -> bool {
    let lower = text.to_lowercase();
    SERVER_ERROR_PATTERN.iter().any(|p| lower.contains(&p.to_lowercase()))
}

fn matches_generic_failure(text: &str) -> bool {
    let lower = text.to_lowercase();
    GENERIC_FAILURE_PATTERN.iter().any(|p| lower.contains(&p.to_lowercase()))
}

fn truncate_utf8_like(text: &str, max_chars: usize) -> String {
    if text.len() <= max_chars {
        text.to_string()
    } else {
        format!("{}...", &text[..max_chars])
    }
}

fn window() -> Option<web_sys::Window> {
    web_sys::window()
}

fn storage() -> Option<web_sys::Storage> {
    window()?.session_storage().ok().flatten()
}

fn read_persisted_csrf_token() -> Option<String> {
    let storage = storage()?;
    let raw = storage.get_item(CSRF_STORAGE_KEY).ok().flatten()?;
    let trimmed = raw.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn persist_csrf_token(token: Option<&str>) {
    if let Some(storage) = storage() {
        if let Some(t) = token {
            let _ = storage.set_item(CSRF_STORAGE_KEY, t.trim());
        } else {
            let _ = storage.remove_item(CSRF_STORAGE_KEY);
        }
    }
}

fn csrf_token() -> Option<String> {
    read_persisted_csrf_token()
}

fn create_csrf_nonce() -> String {
    format!("{}-{}", js_sys::Date::now(), js_sys::Math::random())
}

fn is_csrf_error(status: u16, message: &str) -> bool {
    status == 403 && message.to_lowercase().contains("csrf")
}

async fn ensure_csrf_token(force_refresh: bool) {
    if !force_refresh && csrf_token().is_some() {
        return;
    }
    let client = reqwest::Client::new();
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));

    if let Ok(resp) = client.get("/api/csrf").headers(headers).send().await {
        if let Some(token) = resp.headers().get(CSRF_TOKEN_HEADER) {
            if let Ok(token) = token.to_str() {
                persist_csrf_token(Some(token));
            }
        }
        if resp.status() == 401 {
            persist_csrf_token(None);
        }
    }
}

fn parse_error_message_body(text: &str) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }

    if trimmed.starts_with('{') || trimmed.starts_with('[') || trimmed.starts_with('"') {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
            if let Some(s) = value.as_str() {
                if !s.trim().is_empty() {
                    return Some(s.to_string());
                }
            }
            if let Some(obj) = value.as_object() {
                for key in ["message", "error"] {
                    if let Some(v) = obj.get(key).and_then(|v| v.as_str()) {
                        if !v.trim().is_empty() {
                            return Some(v.to_string());
                        }
                    }
                }
            }
        }
    }

    Some(truncate_utf8_like(trimmed, 240))
}

async fn extract_error_message(resp: reqwest::Response) -> Option<String> {
    let status = resp.status().as_u16();
    let text = resp.text().await.ok()?;
    let msg = parse_error_message_body(&text);
    if msg.is_some() {
        return msg;
    }
    if status >= 500 {
        return None;
    }
    Some(text)
}

async fn send_request(path: &str, method: &str, body: Option<String>) -> Result<reqwest::Response, ApiError> {
    let client = reqwest::Client::new();
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
    if let Some(token) = csrf_token() {
        if let Ok(value) = HeaderValue::from_str(&token) {
            headers.insert(CSRF_TOKEN_HEADER, value);
        }
        if method == "POST" {
            if let Ok(value) = HeaderValue::from_str(&create_csrf_nonce()) {
                headers.insert(CSRF_NONCE_HEADER, value);
            }
        }
    }

    let mut builder = client.request(
        reqwest::Method::from_bytes(method.as_bytes()).map_err(|e| ApiError::new(e.to_string(), None))?,
        path,
    );
    if let Some(b) = body {
        builder = builder.body(b);
    }
    let resp = builder.headers(headers).send().await.map_err(|e| ApiError::new(e.to_string(), None))?;
    if let Some(token) = resp.headers().get(CSRF_TOKEN_HEADER) {
        if let Ok(token) = token.to_str() {
            persist_csrf_token(Some(token));
        }
    }
    Ok(resp)
}

async fn request(path: &str, method: &str, body: Option<String>) -> Result<reqwest::Response, ApiError> {
    if method == "POST" && csrf_token().is_none() {
        ensure_csrf_token(false).await;
    }

    let resp = send_request(path, method, body.clone()).await?;
    if resp.status().is_success() {
        return Ok(resp);
    }

    let status = resp.status().as_u16();
    let mut msg = extract_error_message(resp).await;

    if method == "POST" && is_csrf_error(status, msg.as_deref().unwrap_or("")) {
        ensure_csrf_token(true).await;
        let resp = send_request(path, method, body).await?;
        if resp.status().is_success() {
            return Ok(resp);
        }
        msg = extract_error_message(resp).await;
    }

    if status == 401 {
        persist_csrf_token(None);
    }
    if status == 423 {
        if let Some(window) = window() {
            let _ = window.dispatch_event(&web_sys::Event::new("qf:admin-password-change-required").unwrap_or_else(|_| web_sys::Event::new("").unwrap()));
        }
    }

    Err(ApiError::new(
        sanitize_error_message(msg.as_deref().unwrap_or(""), ""),
        Some(status),
    ))
}

pub async fn get_json<T: DeserializeOwned>(path: &str) -> Result<T, ApiError> {
    let resp = request(path, "GET", None).await?;
    resp.json::<T>().await.map_err(|e| ApiError::new(e.to_string(), None))
}

pub async fn post_json<T: DeserializeOwned, B: serde::Serialize>(path: &str, body: &B) -> Result<T, ApiError> {
    let body = serde_json::to_string(body).map_err(|e| ApiError::new(e.to_string(), None))?;
    let resp = request(path, "POST", Some(body)).await?;
    resp.json::<T>().await.map_err(|e| ApiError::new(e.to_string(), None))
}
