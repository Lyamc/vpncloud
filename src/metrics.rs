// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

//! Minimal read-only HTTP endpoint for Prometheus. Only `/metrics` and `/`
//! are served; there is no write path and no authentication, so bind it to
//! loopback or a trusted management network.

use std::{
    io::{Read, Write},
    net::TcpListener,
    thread
};

use crate::runtime_status;

fn response(body: &str, content_type: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        content_type,
        body.len(),
        body
    )
}

/// Spawn the metrics server. Returns an error only if the bind fails.
pub fn spawn(addr: &str) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    listener.set_nonblocking(false)?;
    thread::Builder::new().name("vpncloud-metrics".into()).spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..n]);
            let path = request.split_whitespace().nth(1).unwrap_or("/");
            let reply = if path == "/metrics" {
                let text = runtime_status::prometheus();
                response(&text, "text/plain; version=0.0.4; charset=utf-8")
            } else if path == "/" {
                response("VpnCloud metrics. See <a href=\"/metrics\">/metrics</a>.\n", "text/html; charset=utf-8")
            } else {
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
            };
            let _ = stream.write_all(reply.as_bytes());
        }
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_has_content_length() {
        let r = response("abc", "text/plain");
        assert!(r.contains("Content-Length: 3\r\n"));
        assert!(r.ends_with("abc"));
    }

    #[test]
    fn serves_metrics_over_http() {
        use std::io::{Read, Write};
        runtime_status::set_prometheus("vpncloud_up 1\n".into());
        // Bind an ephemeral port ourselves so the test does not need a fixed one.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        spawn(&addr.to_string()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        let mut stream = std::net::TcpStream::connect(addr).unwrap();
        stream.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        let mut buf = [0u8; 512];
        let n = stream.read(&mut buf).unwrap();
        let text = String::from_utf8_lossy(&buf[..n]);
        assert!(text.starts_with("HTTP/1.1 200 OK"));
        assert!(text.contains("vpncloud_up 1"));
    }
}
