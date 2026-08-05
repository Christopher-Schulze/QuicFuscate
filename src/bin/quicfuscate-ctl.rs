//! QuicFuscate Admin CLI (quicfuscate-ctl)
//!
//! Command-line interface for managing the QuicFuscate server.

use std::io::{BufRead, Write};
use std::os::unix::net::UnixStream;

use quicfuscate::env_utils::EnvSnapshot;

const DEFAULT_SOCKET: &str = "/var/run/quicfuscate/ctl.sock";
const MAX_RESPONSE_FRAME_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug)]
enum ExpectedResponse {
    Status,
    Clients,
    Message,
    QKey,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage();
        std::process::exit(1);
    }

    let environment = EnvSnapshot::capture();
    let socket_path =
        environment.first(["QUICFUSCATE_CTL_SOCKET"]).unwrap_or_else(|| DEFAULT_SOCKET.to_string());

    let cmd = &args[1];

    let result = match cmd.as_str() {
        "status" => send_command(&socket_path, r#"{"cmd":"status"}"#, ExpectedResponse::Status),
        "clients" => send_command(&socket_path, r#"{"cmd":"clients"}"#, ExpectedResponse::Clients),
        "kick" => {
            if args.len() < 3 {
                eprintln!("Usage: quicfuscate-ctl kick <client_id>");
                std::process::exit(1);
            }
            send_command(
                &socket_path,
                &format!(r#"{{"cmd":"kick","id":"{}"}}"#, args[2]),
                ExpectedResponse::Message,
            )
        }
        "block" => {
            if args.len() < 3 {
                eprintln!("Usage: quicfuscate-ctl block <ip>");
                std::process::exit(1);
            }
            send_command(
                &socket_path,
                &format!(r#"{{"cmd":"block","ip":"{}"}}"#, args[2]),
                ExpectedResponse::Message,
            )
        }
        "unblock" => {
            if args.len() < 3 {
                eprintln!("Usage: quicfuscate-ctl unblock <ip>");
                std::process::exit(1);
            }
            send_command(
                &socket_path,
                &format!(r#"{{"cmd":"unblock","ip":"{}"}}"#, args[2]),
                ExpectedResponse::Message,
            )
        }
        "reload" => send_command(&socket_path, r#"{"cmd":"reload"}"#, ExpectedResponse::Message),
        "qkey" => send_command(&socket_path, r#"{"cmd":"qkey"}"#, ExpectedResponse::QKey),
        "shutdown" => {
            send_command(&socket_path, r#"{"cmd":"shutdown"}"#, ExpectedResponse::Message)
        }
        "help" | "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        _ => {
            eprintln!("Unknown command: {}", cmd);
            print_usage();
            std::process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn print_usage() {
    println!("QuicFuscate Control CLI");
    println!();
    println!("Usage: quicfuscate-ctl <command> [options]");
    println!();
    println!("Commands:");
    println!("  status              Show server status");
    println!("  clients             List connected clients");
    println!("  kick <id>           Disconnect a client");
    println!("  block <ip>          Block an IP address");
    println!("  unblock <ip>        Unblock an IP address");
    println!("  reload              Reload configuration");
    println!("  qkey                Generate client QKey");
    println!("  shutdown            Shutdown the server");
    println!();
    println!("Environment:");
    println!("  QUICFUSCATE_CTL_SOCKET    Control socket path (default: {})", DEFAULT_SOCKET);
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseEnvelope {
    success: bool,
    message: Option<String>,
    data: Option<serde_json::Value>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusStealth {
    http3: u64,
    tls13: u64,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusGeoIp {
    status: String,
    active: bool,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct StatusData {
    version: String,
    uptime_secs: u64,
    clients_active: u64,
    clients_total: u64,
    bytes_in: u64,
    bytes_out: u64,
    #[serde(default)]
    connections_accepted: Option<u64>,
    #[serde(default)]
    connections_rejected: Option<u64>,
    #[serde(default)]
    auth_attempts: Option<u64>,
    #[serde(default)]
    auth_succeeded: Option<u64>,
    #[serde(default)]
    auth_failed: Option<u64>,
    #[serde(default)]
    auth_backoff_rejected: Option<u64>,
    #[serde(default)]
    auth_blocked_rejected: Option<u64>,
    #[serde(default)]
    auth_capacity_rejected: Option<u64>,
    #[serde(default)]
    auth_state_tracked_ips: Option<u64>,
    #[serde(default)]
    stealth: Option<StatusStealth>,
    #[serde(default)]
    fec_recovered: Option<u64>,
    #[serde(default)]
    geoip: Option<StatusGeoIp>,
}

impl StatusData {
    fn validate(&self) -> Result<(), String> {
        if self.version.trim().is_empty() {
            return Err("status response has an empty version".to_string());
        }
        if self.clients_active > self.clients_total {
            return Err(format!(
                "status response has clients_active={} greater than clients_total={}",
                self.clients_active, self.clients_total
            ));
        }
        if let Some(geoip) = &self.geoip {
            if geoip.status.trim().is_empty() {
                return Err("status response has an empty geoip status".to_string());
            }
        }
        Ok(())
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientData {
    id: String,
    ip: String,
    remote_addr: String,
    connected_secs: u64,
    bytes_in: u64,
    bytes_out: u64,
    stealth_mode: String,
}

impl ClientData {
    fn validate(&self) -> Result<(), String> {
        for (name, value) in [
            ("id", self.id.as_str()),
            ("ip", self.ip.as_str()),
            ("remote_addr", self.remote_addr.as_str()),
            ("stealth_mode", self.stealth_mode.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(format!("clients response has an empty {name}"));
            }
        }
        self.bytes_in.checked_add(self.bytes_out).ok_or_else(|| {
            format!("client {} has byte counters that overflow their aggregate", self.id)
        })?;
        Ok(())
    }

    fn total_bytes(&self) -> Result<u64, String> {
        self.bytes_in.checked_add(self.bytes_out).ok_or_else(|| {
            format!("client {} has byte counters that overflow their aggregate", self.id)
        })
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct QKeyData {
    qkey: String,
}

#[derive(Debug)]
enum ParsedResponse {
    Status(Box<StatusData>),
    Clients(Vec<ClientData>),
    Message(String),
    QKey(String),
}

fn cli_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    message.into().into()
}

fn require_message(
    message: Option<String>,
    context: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let message = message.ok_or_else(|| cli_error(format!("{context} is missing message")))?;
    if message.trim().is_empty() {
        return Err(cli_error(format!("{context} has an empty message")));
    }
    Ok(message)
}

fn read_response_frame<R: BufRead>(reader: &mut R) -> Result<String, Box<dyn std::error::Error>> {
    let mut response = Vec::new();

    loop {
        let chunk = reader.fill_buf()?;
        if chunk.is_empty() {
            return Err(cli_error(if response.is_empty() {
                "Admin server returned an empty response"
            } else {
                "Admin server response ended before the newline terminator"
            }));
        }

        if let Some(line_end) = chunk.iter().position(|byte| *byte == b'\n') {
            let frame_len = response.len().saturating_add(line_end + 1);
            if frame_len > MAX_RESPONSE_FRAME_BYTES {
                return Err(cli_error(format!(
                    "Admin server response exceeds the {} byte frame limit",
                    MAX_RESPONSE_FRAME_BYTES
                )));
            }
            response.extend_from_slice(&chunk[..=line_end]);
            reader.consume(line_end + 1);
            return String::from_utf8(response)
                .map_err(|_| cli_error("Admin server response is not valid UTF-8"));
        }

        let frame_len = response.len().saturating_add(chunk.len());
        if frame_len >= MAX_RESPONSE_FRAME_BYTES {
            return Err(cli_error(format!(
                "Admin server response exceeds the {} byte frame limit or lacks a terminator",
                MAX_RESPONSE_FRAME_BYTES
            )));
        }
        let chunk_len = chunk.len();
        response.extend_from_slice(chunk);
        reader.consume(chunk_len);
    }
}

fn decode_response(
    response: &str,
    expected: ExpectedResponse,
) -> Result<ParsedResponse, Box<dyn std::error::Error>> {
    let envelope: ResponseEnvelope = serde_json::from_str(response).map_err(|error| {
        cli_error(format!("Malformed server response (not valid JSON): {error}"))
    })?;

    if !envelope.success {
        if envelope.data.is_some() {
            return Err(cli_error("Server error response unexpectedly contains data"));
        }
        let message = require_message(envelope.message, "Server error response")?;
        return Err(cli_error(format!("Server error: {message}")));
    }

    if matches!(expected, ExpectedResponse::Message) {
        if envelope.data.is_some() {
            return Err(cli_error("Message response unexpectedly contains data"));
        }
        return Ok(ParsedResponse::Message(require_message(
            envelope.message,
            "Successful message response",
        )?));
    }

    if envelope.message.is_some() {
        return Err(cli_error("Data response unexpectedly contains a message"));
    }
    let data =
        envelope.data.ok_or_else(|| cli_error("Successful data response is missing data"))?;

    match expected {
        ExpectedResponse::Status => {
            let status: StatusData = serde_json::from_value(data)
                .map_err(|error| cli_error(format!("Invalid status response data: {error}")))?;
            status.validate().map_err(cli_error)?;
            Ok(ParsedResponse::Status(Box::new(status)))
        }
        ExpectedResponse::Clients => {
            let clients: Vec<ClientData> = serde_json::from_value(data)
                .map_err(|error| cli_error(format!("Invalid clients response data: {error}")))?;
            for client in &clients {
                client.validate().map_err(cli_error)?;
            }
            Ok(ParsedResponse::Clients(clients))
        }
        ExpectedResponse::QKey => {
            let qkey_data: QKeyData = serde_json::from_value(data)
                .map_err(|error| cli_error(format!("Invalid QKey response data: {error}")))?;
            if qkey_data.qkey.trim().is_empty() {
                return Err(cli_error("QKey response contains an empty QKey"));
            }
            quicfuscate::engine::qkey::parse(&qkey_data.qkey).map_err(|error| {
                cli_error(format!("QKey response contains an invalid QKey: {error}"))
            })?;
            Ok(ParsedResponse::QKey(qkey_data.qkey))
        }
        ExpectedResponse::Message => unreachable!("message responses return before data decoding"),
    }
}

fn send_command(
    socket_path: &str,
    cmd: &str,
    expected: ExpectedResponse,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = UnixStream::connect(socket_path)
        .map_err(|e| format!("Cannot connect to server: {} (is it running?)", e))?;

    // Send command
    writeln!(stream, "{}", cmd)?;
    stream.flush()?;

    // Read response
    let mut reader = std::io::BufReader::new(&stream);
    let response = read_response_frame(&mut reader)?;
    let parsed = decode_response(&response, expected)?;
    format_output(parsed)?;

    Ok(())
}

fn format_output(response: ParsedResponse) -> Result<(), Box<dyn std::error::Error>> {
    match response {
        ParsedResponse::Status(status) => {
            println!("QuicFuscate Server v{}", status.version);
            println!("Status: Running");
            println!("Uptime: {}", format_duration(status.uptime_secs));
            println!("Clients: {}/{}", status.clients_active, status.clients_total);
            println!(
                "Traffic: {} down / {} up",
                format_bytes(status.bytes_in),
                format_bytes(status.bytes_out)
            );
            if let Some(stealth) = status.stealth {
                println!("Stealth: {} HTTP/3, {} TLS 1.3", stealth.http3, stealth.tls13);
            }
            if let Some(fec) = status.fec_recovered {
                println!("FEC Recovered: {} packets", fec);
            }
            if let Some(geoip) = status.geoip {
                println!(
                    "GeoIP: {} ({})",
                    geoip.status,
                    if geoip.active { "active" } else { "inactive" }
                );
            }
        }
        ParsedResponse::QKey(qkey) => println!("{}", qkey),
        ParsedResponse::Message(message) => println!("{}", message),
        ParsedResponse::Clients(clients) => {
            if clients.is_empty() {
                println!("No clients connected");
                return Ok(());
            }
            println!("{:<12} {:<15} {:<12} {:<12}", "ID", "IP", "Connected", "Traffic");
            println!("{}", "-".repeat(55));
            for client in clients {
                let total_bytes = client.total_bytes().map_err(cli_error)?;
                println!(
                    "{:<12} {:<15} {:<12} {:<12}",
                    client.id,
                    client.ip,
                    format_duration(client.connected_secs),
                    format_bytes(total_bytes)
                );
            }
        }
    }
    Ok(())
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else if secs < 86400 {
        let hours = secs / 3600;
        let mins = (secs % 3600) / 60;
        format!("{}h {}m", hours, mins)
    } else {
        let days = secs / 86400;
        let hours = (secs % 86400) / 3600;
        format!("{}d {}h", days, hours)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn valid_qkey() -> String {
        let config = quicfuscate::engine::qkey::QKeyConfig::new("127.0.0.1:4433", "example.com");
        quicfuscate::engine::qkey::generate(&config)
    }

    fn valid_status_response() -> String {
        serde_json::json!({
            "success": true,
            "data": {
                "version": "0.4.4",
                "uptime_secs": 65,
                "clients_active": 2,
                "clients_total": 5,
                "connections_accepted": 5,
                "connections_rejected": 1,
                "auth_attempts": 4,
                "auth_succeeded": 2,
                "auth_failed": 1,
                "auth_backoff_rejected": 0,
                "auth_blocked_rejected": 0,
                "auth_capacity_rejected": 0,
                "auth_state_tracked_ips": 1,
                "bytes_in": 2048,
                "bytes_out": 4096,
                "stealth": { "http3": 1, "tls13": 2 },
                "fec_recovered": 3,
                "geoip": { "status": "disabled", "active": false }
            }
        })
        .to_string()
    }

    #[test]
    fn valid_response_variants_are_typed_and_command_specific() {
        assert!(matches!(
            decode_response(&valid_status_response(), ExpectedResponse::Status),
            Ok(ParsedResponse::Status(_))
        ));

        let clients = serde_json::json!({
            "success": true,
            "data": [{
                "id": "session:7",
                "ip": "127.0.0.1",
                "remote_addr": "127.0.0.1:4433",
                "connected_secs": 61,
                "bytes_in": 10,
                "bytes_out": 20,
                "stealth_mode": "off"
            }]
        })
        .to_string();
        assert!(matches!(
            decode_response(&clients, ExpectedResponse::Clients),
            Ok(ParsedResponse::Clients(_))
        ));

        let qkey = serde_json::json!({
            "success": true,
            "data": { "qkey": valid_qkey() }
        })
        .to_string();
        assert!(matches!(
            decode_response(&qkey, ExpectedResponse::QKey),
            Ok(ParsedResponse::QKey(_))
        ));

        let message = r#"{"success":true,"message":"Client disconnected"}"#;
        assert!(matches!(
            decode_response(message, ExpectedResponse::Message),
            Ok(ParsedResponse::Message(_))
        ));
    }

    #[test]
    fn response_shapes_reject_missing_wrong_typed_and_unexpected_fields() {
        let invalid_responses = [
            (r#"{"success":true,"data":{"version":"0.4.4"}}"#, ExpectedResponse::Status),
            (
                r#"{"success":true,"data":{"version":"0.4.4","uptime_secs":"65","clients_active":0,"clients_total":0,"bytes_in":0,"bytes_out":0}}"#,
                ExpectedResponse::Status,
            ),
            (
                r#"{"success":true,"data":{"version":"0.4.4","uptime_secs":0,"clients_active":0,"clients_total":0,"bytes_in":0,"bytes_out":0,"unexpected":true}}"#,
                ExpectedResponse::Status,
            ),
            (r#"{"success":true,"data":{"qkey":42}}"#, ExpectedResponse::QKey),
            (
                r#"{"success":true,"data":[{"id":"session:7","ip":"127.0.0.1","connected_secs":1,"bytes_in":1,"bytes_out":1,"stealth_mode":"off"}]}"#,
                ExpectedResponse::Clients,
            ),
            (r#"{"success":true}"#, ExpectedResponse::Message),
            (r#"{"success":false}"#, ExpectedResponse::Status),
            (r#"{"success":false,"message":"failed","data":{}}"#, ExpectedResponse::Message),
        ];

        for (response, expected) in invalid_responses {
            assert!(
                decode_response(response, expected).is_err(),
                "response unexpectedly accepted: {response}"
            );
        }
    }

    #[test]
    fn response_validation_rejects_counter_overflow_and_inconsistent_status() {
        let overflow = serde_json::json!({
            "success": true,
            "data": [{
                "id": "session:7",
                "ip": "127.0.0.1",
                "remote_addr": "127.0.0.1:4433",
                "connected_secs": 1,
                "bytes_in": u64::MAX,
                "bytes_out": 1,
                "stealth_mode": "off"
            }]
        })
        .to_string();
        assert!(decode_response(&overflow, ExpectedResponse::Clients).is_err());

        let inconsistent = serde_json::json!({
            "success": true,
            "data": {
                "version": "0.4.4",
                "uptime_secs": 1,
                "clients_active": 2,
                "clients_total": 1,
                "bytes_in": 0,
                "bytes_out": 0
            }
        })
        .to_string();
        assert!(decode_response(&inconsistent, ExpectedResponse::Status).is_err());
    }

    #[test]
    fn response_frame_contract_accepts_one_terminated_utf8_frame() {
        let mut reader = Cursor::new(b"{\"success\":true}\n".to_vec());
        assert_eq!(
            read_response_frame(&mut reader).expect("terminated response"),
            "{\"success\":true}\n"
        );
    }

    #[test]
    fn response_frame_contract_rejects_empty_unterminated_oversized_and_invalid_utf8() {
        let mut empty = Cursor::new(Vec::<u8>::new());
        let empty_error = read_response_frame(&mut empty).expect_err("empty response");
        assert!(empty_error.to_string().contains("empty"));

        let mut unterminated = Cursor::new(b"{}".to_vec());
        let unterminated_error =
            read_response_frame(&mut unterminated).expect_err("unterminated response");
        assert!(unterminated_error.to_string().contains("newline"));

        let mut oversized = Cursor::new(vec![b'x'; MAX_RESPONSE_FRAME_BYTES]);
        let oversized_error = read_response_frame(&mut oversized).expect_err("oversized response");
        assert!(oversized_error.to_string().contains("frame limit"));

        let mut invalid_utf8 = Cursor::new(vec![0xff, b'\n']);
        let invalid_utf8_error =
            read_response_frame(&mut invalid_utf8).expect_err("invalid UTF-8 response");
        assert!(invalid_utf8_error.to_string().contains("UTF-8"));
    }
}
