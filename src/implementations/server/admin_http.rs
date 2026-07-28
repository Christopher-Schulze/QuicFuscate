//! HTTP admin server for web dashboard control.
//!
//! Serves static web assets and exposes a JSON API backed by an AdminHttpHandler.
//! Uses hyper 1.x for HTTP/1.1 parsing and response writing.

include!("admin_http_parts/server_and_auth.rs");
include!("admin_http_parts/tests.rs");
include!("admin_http_parts/api_handlers.rs");
