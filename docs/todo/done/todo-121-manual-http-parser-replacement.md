# TODO-121: Manual HTTP Parser Replacement

## Status
**DONE** - Full hyper 1.x migration complete. Both request parsing AND response writing now use hyper. ~230 lines of hand-rolled HTTP code removed.

## Severity
**CRITICAL**

## Context
In `src/implementations/server/admin_http.rs`, a handwritten HTTP/1.1 parser (~170 lines) plus handwritten response writer (~80 lines) handled the admin API. Security risks: no chunked-TE, header injection potential, no proper connection lifecycle management.

## What Was Done

### Phase 1 (earlier session): httparse migration
- Replaced `read_request()` with httparse-backed parsing.

### Phase 2 (this session): Full hyper 1.x migration
1. Replaced the entire HTTP layer with hyper 1.x `http1::Builder` + `service_fn`.
2. Added `hyper_to_http_request()` bridge function to preserve `HttpRequest` struct as internal type (minimizes helper function changes).
3. Replaced all `respond_*(&mut TcpStream, ...)` functions with `Response<Full<Bytes>>` builders: `text_response()`, `json_response()`, `admin_json_response()`, `file_response()`.
4. Converted `handle_connection(TcpStream)` to `handle_request(Request<Incoming>) -> Response<Full<Bytes>>`.
5. Converted handler functions (login, logout, admin_auth, api) from async stream-writers to sync response-builders.
6. Updated `AdminHttpServer::run()` to use `TokioIo` + `http1::Builder` + `service_fn`.
7. Set `keep_alive(false)` to match single-request-per-connection behavior.
8. Added application-layer security guards: backslash rejection (400) and header size enforcement (431).
9. Removed all hand-rolled code: `read_request()`, `find_header_end()`, `is_valid_http_token()`, `is_valid_header_name()`, `is_valid_request_path()`, all `respond_*` stream writers.
10. Updated test infrastructure: removed `shutdown(Write)` from `send_req()` (hyper treats TCP FIN as connection error), added read timeout instead.
11. Updated integration test `rt-admin-http-contract.rs`: case-insensitive header matching (hyper normalizes to lowercase), adjusted truncated-body corpus expectation.

## Results
- admin_http.rs: 3000 lines (from 3230, -230 lines net)
- 417 tests GREEN (395 lib + 22 integration)
- cargo clippy clean (-D warnings)
- Zero hand-rolled HTTP parsing or response writing remains

## Affected Files
- `src/implementations/server/admin_http.rs` - major refactor (hyper integration, parser/writer removal)
- `scripts/tests/rust/rt-admin-http-contract.rs` - case-insensitive headers, adjusted corpus expectations
- `Cargo.toml` - hyper/hyper-util/http-body-util made explicit (already transitive deps)
