use anyhow::Result;
use bytes::{BufMut, BytesMut};
use memmap2::Mmap;
use serde_json::Value;
use sqlparser::ast::{
    BinaryOperator, Expr, FunctionArg, FunctionArgExpr, GroupByExpr, JoinConstraint, JoinOperator,
    OrderByExpr, SelectItem, SetExpr, Statement, TableFactor,
};
use sqlparser::dialect::MsSqlDialect;
use sqlparser::parser::Parser;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

// Global write mutex - protects all file writes from concurrent modification
lazy_static::lazy_static! {
    static ref WRITE_LOCK: Arc<Mutex<()>> = Arc::new(Mutex::new(()));
}

pub async fn handle_client_pub(socket: TcpStream, data_dir: &Path) -> Result<()> {
    handle_client(socket, data_dir, None, false).await
}

pub async fn handle_client_tls(socket: TcpStream, data_dir: &Path, acceptor: Arc<TlsAcceptor>, trace: bool) -> Result<()> {
    handle_client(socket, data_dir, Some(acceptor), trace).await
}

fn hex_dump(label: &str, data: &[u8]) {
    print!("{} ({} bytes):", label, data.len());
    for (i, b) in data.iter().enumerate() {
        if i % 16 == 0 { print!("\n  {:04x}: ", i); }
        print!("{:02x} ", b);
    }
    println!();
}

fn parse_prelogin_option(payload: &[u8], opt_type: u8) -> Option<u8> {
    let (off, len) = parse_prelogin_offset(payload, opt_type)?;
    if len > 0 && (off as usize) < payload.len() { Some(payload[off as usize]) } else { None }
}

fn parse_prelogin_offset(payload: &[u8], opt_type: u8) -> Option<(u16, u16)> {
    let mut i = 0;
    while i + 4 < payload.len() {
        let t = payload[i];
        if t == 0xFF { break; }
        let off = u16::from_be_bytes([payload[i+1], payload[i+2]]);
        let len = u16::from_be_bytes([payload[i+3], payload[i+4]]);
        if t == opt_type { return Some((off, len)); }
        i += 5;
    }
    None
}

pub(crate) async fn handle_client(mut socket: TcpStream, data_dir: &Path, tls: Option<Arc<TlsAcceptor>>, trace: bool) -> Result<()> {
    let peer = socket.peer_addr().map(|a| a.to_string()).unwrap_or_default();
    if trace { println!("accepted connection from {}", peer); }
    let mut buffer = [0u8; 8192];

    // --- Pre-login (always plain TCP) ---
    let n = socket.read(&mut buffer).await?;
    if n == 0 { return Ok(()); }
    if trace { hex_dump("RECV", &buffer[..n]); }

    if buffer[0] == 0x16 {
        // TDS 8.0: raw TLS ClientHello, no TDS wrapping
        if let Some(tls) = tls {
            let mut prepend = PrependStream { prefix: BytesMut::from(&buffer[..n]), inner: socket };
            let tls_stream = tls.accept(&mut prepend).await?;
            return handle_authenticated_tds8(tls_stream, data_dir, trace).await;
        }
        return Ok(());
    }

    if buffer[0] == 0x12 {
        let client_encrypt = parse_prelogin_option(&buffer[8..n], 0x01).unwrap_or(0x00);
        let do_tls = tls.is_some() && client_encrypt != 0x02; // always TLS unless client explicitly not supported
        let encrypt_byte: u8 = if do_tls { 0x01 } else { 0x00 };

        // Build pre-login response per MS-TDS spec
        // 4 options × 5 bytes + 1 terminator = 21 bytes
        let base: u16 = 21;
        let mut resp_payload = BytesMut::new();
        resp_payload.put_u8(0x00); resp_payload.put_u16(base);   resp_payload.put_u16(6); // VERSION
        resp_payload.put_u8(0x01); resp_payload.put_u16(base+6); resp_payload.put_u16(1); // ENCRYPT
        resp_payload.put_u8(0x02); resp_payload.put_u16(base+7); resp_payload.put_u16(1); // INSTOPT
        resp_payload.put_u8(0x04); resp_payload.put_u16(base+8); resp_payload.put_u16(1); // MARS
        resp_payload.put_u8(0xFF);
        resp_payload.put_slice(&[0x0E, 0x00, 0x0C, 0x00, 0x00, 0x00]); // VERSION 14.0.12.0
        resp_payload.put_u8(encrypt_byte);                               // ENCRYPT
        resp_payload.put_u8(0x00);                                       // INSTOPT
        resp_payload.put_u8(0x00);                                       // MARS
        let mut pkt = BytesMut::new();
        pkt.put_u8(0x04); pkt.put_u8(0x01); // table response, per MS-TDS spec
        pkt.put_u16((resp_payload.len() + 8) as u16);
        pkt.put_slice(&[0x00, 0x00, 0x01, 0x00]);
        pkt.put_slice(&resp_payload);
        if trace { hex_dump("SEND", &pkt); }
        socket.write_all(&pkt).await?;
        socket.flush().await?;

        if do_tls {
            if trace { println!("starting TLS handshake..."); }
            // Wait up to 5s for client to send TLS ClientHello
            let mut raw = vec![0u8; 8192];
            let nr = match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                socket.read(&mut raw)
            ).await {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => { return Err(anyhow::anyhow!("timeout waiting for TLS ClientHello")); }
            };
            if trace { hex_dump("TLS-in-TDS raw", &raw[..nr]); }
            if nr == 0 { return Err(anyhow::anyhow!("client closed before TLS")); }
            // Strip TDS headers and feed raw TLS bytes to rustls
            let mut tls_bytes = BytesMut::new();
            let mut pos = 0;
            while pos + 8 <= nr {
                let pkt_len = u16::from_be_bytes([raw[pos+2], raw[pos+3]]) as usize;
                let end = (pos + pkt_len).min(nr);
                if end > pos + 8 { tls_bytes.put_slice(&raw[pos+8..end]); }
                pos += pkt_len.max(1);
            }
            if trace { hex_dump("TLS unwrapped", &tls_bytes); }
            let mut tds_wrap = TdsWrappedStream::new(socket, trace);
            tds_wrap.read_buf = tls_bytes;
            let mut tls_stream = tls.unwrap().accept(tds_wrap).await?;
            tls_stream.get_mut().0.passthrough = true;
            return handle_authenticated(tls_stream, data_dir, trace).await;
        }
    }

    handle_authenticated(socket, data_dir, trace).await
}

use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::ReadBuf;

// During TLS negotiation, the client wraps TLS records inside TDS packets (8-byte header).
// We read TDS-framed data from the socket, strip headers, and buffer the raw TLS bytes.
// Outgoing TLS bytes are re-wrapped in TDS frames before writing.
struct TdsWrappedStream {
    inner: TcpStream,
    read_buf: BytesMut,
    write_buf: BytesMut,
    hdr_buf: [u8; 8],
    hdr_len: usize,
    need_payload: usize,
    passthrough: bool,
    trace: bool,
}

impl TdsWrappedStream {
    fn new(inner: TcpStream, trace: bool) -> Self {
        Self {
            inner,
            read_buf: BytesMut::new(),
            write_buf: BytesMut::new(),
            hdr_buf: [0u8; 8],
            hdr_len: 0,
            need_payload: 0,
            passthrough: false,
            trace,
        }
    }
}

impl Unpin for TdsWrappedStream {}

impl AsyncRead for TdsWrappedStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let me = self.get_mut();
        if me.trace { println!("TDS-UNWRAP poll_read called, read_buf={} hdr_len={} need_payload={}", me.read_buf.len(), me.hdr_len, me.need_payload); }
        loop {
            if !me.read_buf.is_empty() {
                let n = me.read_buf.len().min(buf.remaining());
                buf.put_slice(&me.read_buf[..n]);
                let _ = me.read_buf.split_to(n);
                if me.trace { println!("TDS-UNWRAP read {} bytes, first={:02x}", n, me.read_buf.first().copied().unwrap_or(0)); }
                return Poll::Ready(Ok(()));
            }

            let mut tmp = [0u8; 4096];
            let mut tmp_buf = ReadBuf::new(&mut tmp);
            match Pin::new(&mut me.inner).poll_read(cx, &mut tmp_buf) {
                Poll::Pending => { if me.trace { println!("TDS-UNWRAP inner Pending"); } return Poll::Pending; }
                Poll::Ready(Err(e)) => { if me.trace { println!("TDS-UNWRAP inner Err: {}", e); } return Poll::Ready(Err(e)); }
                Poll::Ready(Ok(())) => {
                    let data = tmp_buf.filled();
                    if me.trace { println!("TDS-UNWRAP inner read {} bytes", data.len()); }
                    if data.is_empty() { return Poll::Ready(Ok(())); }

                    if me.passthrough {
                        me.read_buf.put_slice(data);
                        continue;
                    }

                    let mut pos = 0;
                    while pos < data.len() {
                        if me.hdr_len < 8 {
                            let need = 8 - me.hdr_len;
                            let take = need.min(data.len() - pos);
                            me.hdr_buf[me.hdr_len..me.hdr_len + take].copy_from_slice(&data[pos..pos + take]);
                            me.hdr_len += take;
                            pos += take;
                            if me.hdr_len == 8 {
                                let pkt_len = u16::from_be_bytes([me.hdr_buf[2], me.hdr_buf[3]]) as usize;
                                me.need_payload = pkt_len.saturating_sub(8);
                            }
                        } else {
                            let take = me.need_payload.min(data.len() - pos);
                            me.read_buf.put_slice(&data[pos..pos + take]);
                            me.need_payload -= take;
                            pos += take;
                            if me.need_payload == 0 {
                                me.hdr_len = 0;
                            }
                        }
                    }
                }
            }
        }
    }
}

impl AsyncWrite for TdsWrappedStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let me = self.get_mut();
        let to_write = if me.passthrough {
            if me.trace { println!("TDS-PASSTHROUGH write {} bytes (tls first={:02x})", buf.len(), buf.first().copied().unwrap_or(0)); }
            BytesMut::from(buf)
        } else {
            let mut pkt = BytesMut::with_capacity(8 + buf.len());
            pkt.put_u8(0x12); pkt.put_u8(0x01);
            pkt.put_u16((8 + buf.len()) as u16);
            pkt.put_slice(&[0x00, 0x00, 0x00, 0x00]);
            pkt.put_slice(buf);
            if me.trace { println!("TDS-WRAP write {} bytes (tls first={:02x})", buf.len(), buf.first().copied().unwrap_or(0)); }
            pkt
        };
        me.write_buf.put_slice(&to_write);

        while !me.write_buf.is_empty() {
            match Pin::new(&mut me.inner).poll_write(cx, &me.write_buf) {
                Poll::Ready(Ok(n)) => { let _ = me.write_buf.split_to(n); }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => break,
            }
        }
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let me = self.get_mut();
        while !me.write_buf.is_empty() {
            match Pin::new(&mut me.inner).poll_write(cx, &me.write_buf) {
                Poll::Ready(Ok(n)) => { let _ = me.write_buf.split_to(n); }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut me.inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

struct TraceStream<S> {
    inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for TraceStream<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TraceStream<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &result { hex_dump("SEND", &buf[..*n]); }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct PrependStream {
    prefix: BytesMut,
    inner: TcpStream,
}
impl Unpin for PrependStream {}
impl AsyncRead for PrependStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let me = self.get_mut();
        if !me.prefix.is_empty() {
            let n = me.prefix.len().min(buf.remaining());
            buf.put_slice(&me.prefix[..n]);
            let _ = me.prefix.split_to(n);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut me.inner).poll_read(cx, buf)
    }
}
impl AsyncWrite for PrependStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// TDS 8.0: PRELOGIN happens inside TLS, no encryption negotiation needed
async fn handle_authenticated_tds8<S>(mut stream: S, data_dir: &Path, trace: bool) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut buffer = [0u8; 8192];
    let n = stream.read(&mut buffer).await?;
    if n == 0 { return Ok(()); }
    if trace { hex_dump("TDS8 PRELOGIN RECV", &buffer[..n]); }
    // Send PRELOGIN response with ENCRYPT=0x02 (not supported, TLS already established)
    if buffer[0] == 0x12 {
        let base: u16 = 21;
        let mut resp = BytesMut::new();
        resp.put_u8(0x00); resp.put_u16(base);   resp.put_u16(6);
        resp.put_u8(0x01); resp.put_u16(base+6); resp.put_u16(1);
        resp.put_u8(0x02); resp.put_u16(base+7); resp.put_u16(1);
        resp.put_u8(0x04); resp.put_u16(base+8); resp.put_u16(1);
        resp.put_u8(0xFF);
        resp.put_slice(&[0x0E, 0x00, 0x0C, 0x00, 0x00, 0x00]);
        resp.put_u8(0x02); // ENCRYPT_NOT_SUP — already encrypted
        resp.put_u8(0x00);
        resp.put_u8(0x00);
        let mut pkt = BytesMut::new();
        pkt.put_u8(0x04); pkt.put_u8(0x01);
        pkt.put_u16((resp.len() + 8) as u16);
        pkt.put_slice(&[0x00, 0x00, 0x01, 0x00]);
        pkt.put_slice(&resp);
        if trace { hex_dump("TDS8 PRELOGIN SEND", &pkt); }
        stream.write_all(&pkt).await?;
        stream.flush().await?;
    }
    handle_authenticated_inner(stream, data_dir, trace, false).await
}

async fn handle_authenticated<S>(stream: S, data_dir: &Path, trace: bool) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    if trace {
        handle_authenticated_inner(TraceStream { inner: stream }, data_dir, trace, true).await
    } else {
        handle_authenticated_inner(stream, data_dir, trace, true).await
    }
}

async fn handle_authenticated_inner<S>(mut stream: S, data_dir: &Path, trace: bool, send_collation: bool) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut buffer = [0u8; 8192];
    loop {
        let n = match tokio::time::timeout(std::time::Duration::from_secs(60), stream.read(&mut buffer)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                // Ignore clean disconnects (no TLS close_notify from client)
                if e.kind() == std::io::ErrorKind::UnexpectedEof { return Ok(()); }
                println!("Read error: {}", e);
                return Err(e.into());
            }
            Err(_) => { println!("Connection idle for 60s, keeping alive..."); continue; }
        };
        if n == 0 { return Ok(()); }
        if trace { hex_dump("RECV", &buffer[..n]); }
        match buffer[0] {
            0x10 | 0x62 => send_login_response(&mut stream, send_collation, send_collation, trace).await?,
            0x01 => {
                let sql = decode_utf16le(&buffer[8..n]);
                if let Err(_) = execute_mock_sql(&sql, &mut stream, data_dir).await {
                    let _ = send_done(&mut stream).await;
                }
            }
            0x03 => {
                if let Some(sql) = extract_sql_from_rpc(&buffer[8..n]) {
                    if let Err(_) = execute_mock_sql(&sql, &mut stream, data_dir).await {
                        let _ = send_done(&mut stream).await;
                    }
                } else {
                    send_done(&mut stream).await?;
                }
            }
            0x06 | 0x0E => send_done(&mut stream).await?,
            other => { let _ = other; }
        }
    }
}

fn decode_utf16le(bytes: &[u8]) -> String {
    // SQL batch packets may start with ALL_HEADERS: TotalLength(4 LE) followed by header data.
    // Skip the ALL_HEADERS block before decoding the SQL text.
    let bytes = if bytes.len() >= 4 {
        let hdr_len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        if hdr_len > 0 && hdr_len < bytes.len() { &bytes[hdr_len..] } else { bytes }
    } else { bytes };
    // Detect encoding: UTF-16LE has null bytes at ALL odd positions for ASCII SQL
    let is_utf16le = bytes.len() >= 8
        && bytes[1] == 0 && bytes[3] == 0 && bytes[5] == 0 && bytes[7] == 0;
    if is_utf16le {
        let words: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        String::from_utf16_lossy(&words).to_string()
    } else {
        String::from_utf8_lossy(bytes).to_string()
    }
}

fn extract_sql_from_rpc(payload: &[u8]) -> Option<String> {
    // sp_executesql RPC format:
    // 1. Procedure name length (u16) + UTF16-LE procedure name
    // 2. Flags (u16)
    // 3. Parameter 1 (SQL): Type (0xE7) + MaxLen(u16) + Collation(5) + ActualLen(u16) + Data
    // 4. Parameter 2 (ParamDefs): Type (0xE7) + MaxLen(u16) + Collation(5) + ActualLen(u16) + Data
    // 5. Parameter values...

    if payload.len() < 50 {
        return None;
    }

    // Skip TDS packet internal headers
    // The payload may start with ALL_HEADERS structure (ADO.NET) or directly with procedure name (test harness)
    // ALL_HEADERS: u32 length (typically 22 bytes) followed by transaction descriptors
    // Procedure name: u16 length (typically 13 for "sp_executesql") or 0xFFFF for procedure ID
    let mut pos = 0;

    // Heuristic to detect ALL_HEADERS:
    // - First u16 should be > 20 (ALL_HEADERS length like 0x16 = 22)
    // - First u16 should NOT be 0xFFFF (procedure ID marker)
    // - First u16 should NOT be typical proc name length like 0x000d (13)
    if payload.len() >= 4 {
        let first_u16 = u16::from_le_bytes([payload[0], payload[1]]);
        let all_headers_len = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;

        // If first_u16 looks like ALL_HEADERS length (> 20, < 1000) and not a proc name
        if first_u16 > 20 && first_u16 < 1000 && all_headers_len < payload.len() {
            pos = all_headers_len;
        }
    }

    // Read procedure name or ID
    if pos + 2 > payload.len() {
        return None;
    }

    let name_len_or_id = u16::from_le_bytes([payload[pos], payload[pos+1]]);

    if name_len_or_id == 0xFFFF {
        // Procedure ID follows (2 bytes)
        if pos + 4 > payload.len() {
            return None;
        }
        let proc_id = u16::from_le_bytes([payload[pos+2], payload[pos+3]]);
        pos += 4; // Skip 0xFFFF + proc_id
        // sp_executesql = ID 10 or 0x0a
        if proc_id != 10 && proc_id != 0x0a {
            return extract_sql_from_rpc_fallback(payload);
        }
    } else {
        // String procedure name
        let proc_name_len = name_len_or_id as usize * 2;
        pos += 2 + proc_name_len;
    }

    // Skip flags (2 bytes)
    if pos + 2 > payload.len() {
        return None;
    }
    pos += 2;

    // Skip option flags (2 bytes) - ADO.NET sends these but test harness doesn't
    // Try to detect: if next byte is 0xE7, don't skip; otherwise skip 2 bytes
    if pos + 1 < payload.len() && payload[pos] != 0xE7 {
        // Not immediately a type byte, might be option flags
        if pos + 2 <= payload.len() {
            pos += 2;
        }
    }

    // Read SQL parameter (NVARCHAR)
    if pos + 1 > payload.len() {
        return None;
    }
    if payload[pos] != 0xE7 {
        // Fallback to old method for non-sp_executesql calls
        return extract_sql_from_rpc_fallback(payload);
    }
    pos += 1; // Skip type

    // Skip max length (u16) and collation (5 bytes)
    if pos + 7 > payload.len() {
        return None;
    }
    pos += 7;

    // Read actual SQL length and data
    if pos + 2 > payload.len() {
        return None;
    }
    let sql_len = u16::from_le_bytes([payload[pos], payload[pos+1]]) as usize;
    pos += 2;

    if pos + sql_len > payload.len() {
        return None;
    }
    let sql_words: Vec<u16> = payload[pos..pos+sql_len]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let mut sql = String::from_utf16_lossy(&sql_words);
    pos += sql_len;

    // Check if we have parameter definitions
    if pos >= payload.len() {
        return Some(sql);
    }

    // Skip any padding/null bytes after SQL (ADO.NET sends 0x00 0x00)
    while pos < payload.len() && payload[pos] == 0x00 {
        pos += 1;
    }

    if pos >= payload.len() {
        return Some(sql);
    }

    // Read parameter definitions (NVARCHAR)
    if payload[pos] != 0xE7 {
        return Some(sql);
    }
    pos += 1;
    pos += 7; // Skip max length + collation

    if pos + 2 > payload.len() { return Some(sql); }
    let defs_len = u16::from_le_bytes([payload[pos], payload[pos+1]]) as usize;
    pos += 2;

    if defs_len == 0 || defs_len == 0xFFFF || pos + defs_len > payload.len() {
        return Some(sql);
    }

    let defs_words: Vec<u16> = payload[pos..pos+defs_len]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let param_defs = String::from_utf16_lossy(&defs_words);
    pos += defs_len;

    // Parse parameter names from definitions
    let param_names: Vec<String> = param_defs
        .split(',')
        .filter_map(|def| {
            let parts: Vec<&str> = def.trim().split_whitespace().collect();
            if parts.len() >= 2 && parts[0].starts_with('@') {
                Some(parts[0][1..].to_string())
            } else {
                None
            }
        })
        .collect();

    // Parse parameter values
    let mut param_values = Vec::new();

    for _pname in &param_names {
        if pos >= payload.len() { break; }

        // Skip parameter name
        // Structure: flag byte (often 0x0b), then UTF-16LE parameter name, then 0x00, then type ID
        // We scan forward until we find a type ID byte
        // Type IDs we recognize: 0x26 (INTN), 0xE7 (NVARCHAR), 0xA7 (VARCHAR), 0x7F (BIGINT), 0x6A (DECIMAL), 0x6C (NUMERIC), 0x32 (BIT), 0x3D (DATETIME), 0x2A (DATETIME2), 0x24 (UNIQUEIDENTIFIER), 0xA5 (VARBINARY), 0x3E (FLOAT), 0x6D (REAL), 0x34 (SMALLINT), 0x3C (MONEY)
        while pos < payload.len() {
            let b = payload[pos];
            if b == 0x26 || b == 0xE7 || b == 0xA7 || b == 0x7F || b == 0x6A || b == 0x6C || b == 0x32 || b == 0x3D || b == 0x2A || b == 0x24 || b == 0xA5 || b == 0x3E || b == 0x6D || b == 0x34 || b == 0x3C {
                break;  // Found type ID, pos is now at the type ID byte
            }
            pos += 1;  // Skip this byte and continue scanning
        }

        if pos >= payload.len() { break; }

        // Now pos points to the type ID byte
        let type_id = payload[pos];
        pos += 1;  // Move past the type ID

        match type_id {
            0x26 => { // INTN
                // Skip MaxLen (1 byte)
                if pos + 1 > payload.len() { break; }
                pos += 1;

                // Read actual length
                if pos + 1 > payload.len() { break; }
                let size = payload[pos];
                pos += 1;

                if size == 0 {
                    param_values.push("NULL".to_string());
                    continue;
                }
                if pos + size as usize > payload.len() { break; }
                let val = match size {
                    1 => payload[pos] as i32,
                    2 => i16::from_le_bytes([payload[pos], payload[pos+1]]) as i32,
                    4 => i32::from_le_bytes([payload[pos], payload[pos+1], payload[pos+2], payload[pos+3]]),
                    _ => 0,
                };
                param_values.push(val.to_string());
                pos += size as usize;
            }
            0x34 => { // SMALLINT (2 bytes, signed)
                if pos + 1 > payload.len() { break; }
                let size = payload[pos];
                pos += 1;

                if size == 0 {
                    param_values.push("NULL".to_string());
                    continue;
                }

                if pos + 2 > payload.len() { break; }
                let val = i16::from_le_bytes([payload[pos], payload[pos+1]]);
                param_values.push(val.to_string());
                pos += 2;
            }
            0x3C => { // MONEY (8 bytes, fixed-point with 4 decimal places)
                if pos + 1 > payload.len() { break; }
                let size = payload[pos];
                pos += 1;

                if size == 0 {
                    param_values.push("NULL".to_string());
                    continue;
                }

                if pos + 8 > payload.len() { break; }
                let val = i64::from_le_bytes([
                    payload[pos], payload[pos+1], payload[pos+2], payload[pos+3],
                    payload[pos+4], payload[pos+5], payload[pos+6], payload[pos+7]
                ]);

                // MONEY is stored as int64 scaled by 10000 (4 decimal places)
                let integer_part = val / 10000;
                let fractional_part = (val % 10000).abs();
                let mut money_str = format!("{}.{:04}", integer_part, fractional_part);
                // Trim trailing zeros but keep at least 2 decimal places
                while money_str.ends_with('0') && money_str.chars().rev().nth(2) != Some('.') {
                    money_str.pop();
                }
                param_values.push(money_str);
                pos += 8;
            }
            0xE7 | 0xA7 => { // NVARCHAR/VARCHAR
                if pos + 2 > payload.len() { break; }
                pos += 2; // Skip max length
                if pos + 5 > payload.len() { break; }
                pos += 5; // Skip collation
                if pos + 2 > payload.len() { break; }
                let val_len = u16::from_le_bytes([payload[pos], payload[pos+1]]) as usize;
                pos += 2;
                if val_len == 0xFFFF {
                    param_values.push("NULL".to_string());
                    continue;
                }
                if pos + val_len > payload.len() { break; }
                let words: Vec<u16> = payload[pos..pos+val_len]
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                param_values.push(String::from_utf16_lossy(&words));
                pos += val_len;
            }
            0x7F => { // BIGINT
                if pos + 1 > payload.len() { break; }
                let size = payload[pos];
                pos += 1;
                if size == 0 {
                    param_values.push("NULL".to_string());
                    continue;
                }
                if pos + 8 > payload.len() { break; }
                let val = i64::from_le_bytes([
                    payload[pos], payload[pos+1], payload[pos+2], payload[pos+3],
                    payload[pos+4], payload[pos+5], payload[pos+6], payload[pos+7]
                ]);
                param_values.push(val.to_string());
                pos += 8;
            }
            0x6A | 0x6C => { // DECIMAL/NUMERIC
                // Format: MaxLen(1), Precision(1), Scale(1), Sign(1), Data(variable)
                if pos + 1 > payload.len() { break; }
                let _max_len = payload[pos];
                pos += 1;

                // Skip precision and scale (metadata)
                if pos + 2 > payload.len() { break; }
                let _precision = payload[pos];
                let scale = payload[pos + 1];
                pos += 2;

                // Read actual length
                if pos + 1 > payload.len() { break; }
                let actual_len = payload[pos];
                pos += 1;

                if actual_len == 0 {
                    param_values.push("NULL".to_string());
                    continue;
                }

                // Read sign (1 = positive, 0 = negative)
                if pos + 1 > payload.len() { break; }
                let sign = payload[pos];
                pos += 1;

                // Read the numeric data (little-endian byte array)
                let data_len = (actual_len - 1) as usize;
                if pos + data_len > payload.len() { break; }

                // Convert bytes to u128 (maximum precision)
                let mut value: u128 = 0;
                for i in 0..data_len {
                    value |= (payload[pos + i] as u128) << (i * 8);
                }
                pos += data_len;

                // Apply scale to create decimal string
                // Cap scale at 38 (SQL Server's max DECIMAL precision)
                let safe_scale = scale.min(38);
                let scale_divisor = if safe_scale > 0 {
                    10u128.pow(safe_scale as u32)
                } else {
                    1u128
                };

                let integer_part = if scale_divisor > 0 { value / scale_divisor } else { value };
                let fractional_part = if scale_divisor > 0 { value % scale_divisor } else { 0 };

                let sign_str = if sign == 0 { "-" } else { "" };
                let decimal_str = if safe_scale > 0 {
                    format!("{}{}.{:0width$}", sign_str, integer_part, fractional_part, width = safe_scale as usize)
                } else {
                    format!("{}{}", sign_str, integer_part)
                };
                param_values.push(decimal_str);
            }
            0x32 => { // BIT
                // Format: MaxLen(1), ActualLen(1), Value(1 byte: 0 or 1)
                if pos + 1 > payload.len() { break; }
                let _max_len = payload[pos];
                pos += 1;

                // Read actual length
                if pos + 1 > payload.len() { break; }
                let actual_len = payload[pos];
                pos += 1;

                if actual_len == 0 {
                    param_values.push("NULL".to_string());
                    continue;
                }

                // Read bit value (0 or 1)
                if pos + 1 > payload.len() { break; }
                let bit_value = payload[pos];
                pos += 1;

                param_values.push(if bit_value != 0 { "1" } else { "0" }.to_string());
            }
            0x3D => { // DATETIME (legacy SQL Server datetime)
                // Format: MaxLen(1), ActualLen(1), Days(4 bytes), Time(4 bytes)
                if pos + 1 > payload.len() { break; }
                let _max_len = payload[pos];
                pos += 1;

                // Read actual length
                if pos + 1 > payload.len() { break; }
                let actual_len = payload[pos];
                pos += 1;

                if actual_len == 0 {
                    param_values.push("NULL".to_string());
                    continue;
                }

                // Read days (4 bytes, signed, days since 1900-01-01)
                if pos + 4 > payload.len() { break; }
                let days = i32::from_le_bytes([payload[pos], payload[pos+1], payload[pos+2], payload[pos+3]]);
                pos += 4;

                // Read time (4 bytes, unsigned, 1/300th of a second since midnight)
                if pos + 4 > payload.len() { break; }
                let time_ticks = u32::from_le_bytes([payload[pos], payload[pos+1], payload[pos+2], payload[pos+3]]);
                pos += 4;

                // Convert days since 1900-01-01 to date (simplified calculation)
                let total_days = days + 693595; // Days from year 1 to 1900-01-01
                let year = 1 + (total_days * 4) / 1461;
                let year_day = total_days - ((year - 1) * 365 + (year - 1) / 4 - (year - 1) / 100 + (year - 1) / 400);
                let month_days = [31, if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
                let mut month = 1;
                let mut day = year_day;
                for (m, &d) in month_days.iter().enumerate() {
                    if day <= d {
                        month = m + 1;
                        break;
                    }
                    day -= d;
                }

                // Convert time ticks (1/300 second) to time components
                let total_ms = (time_ticks as u64 * 1000) / 300;
                let hours = (total_ms / 3600000) as u32;
                let minutes = ((total_ms % 3600000) / 60000) as u32;
                let seconds = ((total_ms % 60000) / 1000) as u32;
                let millis = (total_ms % 1000) as u32;

                let datetime_str = format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
                    year, month, day, hours, minutes, seconds, millis);
                param_values.push(datetime_str);
            }
            0x2A => { // DATETIME2
                // Format: Scale(1), MaxLen(1), ActualLen(1), Time(variable), Date(3 bytes)
                if pos + 1 > payload.len() { break; }
                let scale = payload[pos];
                pos += 1;

                if pos + 1 > payload.len() { break; }
                let _max_len = payload[pos];
                pos += 1;

                // Read actual length
                if pos + 1 > payload.len() { break; }
                let actual_len = payload[pos];
                pos += 1;

                if actual_len == 0 {
                    param_values.push("NULL".to_string());
                    continue;
                }

                // Time portion length depends on scale
                let time_len = match scale {
                    0..=2 => 3,
                    3..=4 => 4,
                    5..=7 => 5,
                    _ => 5,
                };

                if pos + time_len > payload.len() { break; }
                let mut time_bytes = [0u8; 8];
                for i in 0..time_len {
                    time_bytes[i] = payload[pos + i];
                }
                let time_ticks = u64::from_le_bytes(time_bytes);
                pos += time_len;

                // Date portion (3 bytes)
                if pos + 3 > payload.len() { break; }
                let date_bytes = [payload[pos], payload[pos+1], payload[pos+2], 0];
                let days = u32::from_le_bytes(date_bytes);
                pos += 3;

                // Convert days since 0001-01-01 to date (simplified)
                let year = 1 + (days * 4) / 1461;
                let year_day = days - ((year - 1) * 365 + (year - 1) / 4 - (year - 1) / 100 + (year - 1) / 400);
                let is_leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
                let month_days = [31, if is_leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
                let mut month = 1;
                let mut day = year_day;
                for (m, &d) in month_days.iter().enumerate() {
                    if day <= d {
                        month = m + 1;
                        break;
                    }
                    day -= d;
                }

                // Convert time ticks to components (100-nanosecond units)
                let scale_factor = 10u64.pow(7 - scale as u32);
                let total_ns = time_ticks * scale_factor * 100;
                let hours = (total_ns / 3600_000_000_000) as u32;
                let minutes = ((total_ns % 3600_000_000_000) / 60_000_000_000) as u32;
                let seconds = ((total_ns % 60_000_000_000) / 1_000_000_000) as u32;
                let nanos = (total_ns % 1_000_000_000) as u32;

                let datetime_str = if scale > 0 {
                    let frac = nanos / 10u32.pow(9 - scale as u32);
                    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:0width$}",
                        year, month, day, hours, minutes, seconds, frac, width = scale as usize)
                } else {
                    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
                        year, month, day, hours, minutes, seconds)
                };
                param_values.push(datetime_str);
            }
            0x24 => { // UNIQUEIDENTIFIER (GUID)
                // Format: MaxLen(1), ActualLen(1), GUID bytes (16 bytes)
                if pos + 1 > payload.len() { break; }
                let _max_len = payload[pos];
                pos += 1;

                // Read actual length
                if pos + 1 > payload.len() { break; }
                let actual_len = payload[pos];
                pos += 1;

                if actual_len == 0 {
                    param_values.push("NULL".to_string());
                    continue;
                }

                // Read 16 bytes of GUID data
                if pos + 16 > payload.len() { break; }

                // SQL Server GUID byte order: first 3 groups are little-endian, last 2 are big-endian
                let guid = format!(
                    "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                    payload[pos+3], payload[pos+2], payload[pos+1], payload[pos],     // Data1 (little-endian)
                    payload[pos+5], payload[pos+4],                                   // Data2 (little-endian)
                    payload[pos+7], payload[pos+6],                                   // Data3 (little-endian)
                    payload[pos+8], payload[pos+9],                                   // Data4 (big-endian)
                    payload[pos+10], payload[pos+11], payload[pos+12], payload[pos+13], payload[pos+14], payload[pos+15] // Data4 cont.
                );
                pos += 16;

                param_values.push(guid);
            }
            0xA5 => { // VARBINARY
                // Format: MaxLen(2 bytes), ActualLen(2 bytes), Data(variable)
                if pos + 2 > payload.len() { break; }
                let _max_len = u16::from_le_bytes([payload[pos], payload[pos+1]]);
                pos += 2;

                if pos + 2 > payload.len() { break; }
                let actual_len = u16::from_le_bytes([payload[pos], payload[pos+1]]) as usize;
                pos += 2;

                if actual_len == 0xFFFF {
                    param_values.push("NULL".to_string());
                    continue;
                }

                if pos + actual_len > payload.len() { break; }

                // Convert binary data to hex string with 0x prefix
                let hex_str = format!("0x{}",
                    payload[pos..pos+actual_len]
                        .iter()
                        .map(|b| format!("{:02X}", b))
                        .collect::<String>()
                );
                param_values.push(hex_str);
                pos += actual_len;
            }
            0x3E => { // FLOAT (8 bytes, IEEE 754 double precision)
                if pos + 1 > payload.len() { break; }
                let size = payload[pos];
                pos += 1;

                if size == 0 {
                    param_values.push("NULL".to_string());
                    continue;
                }

                if pos + 8 > payload.len() { break; }
                let val = f64::from_le_bytes([
                    payload[pos], payload[pos+1], payload[pos+2], payload[pos+3],
                    payload[pos+4], payload[pos+5], payload[pos+6], payload[pos+7]
                ]);
                param_values.push(val.to_string());
                pos += 8;
            }
            0x6D => { // REAL (4 bytes, IEEE 754 single precision)
                if pos + 1 > payload.len() { break; }
                let size = payload[pos];
                pos += 1;

                if size == 0 {
                    param_values.push("NULL".to_string());
                    continue;
                }

                if pos + 4 > payload.len() { break; }
                let val = f32::from_le_bytes([
                    payload[pos], payload[pos+1], payload[pos+2], payload[pos+3]
                ]);
                param_values.push(val.to_string());
                pos += 4;
            }
            _ => {
                // Unsupported type - stop parsing
                break;
            }
        }
    }

    // Substitute parameters in SQL
    for (name, value) in param_names.iter().zip(param_values.iter()) {
        sql = sql.replace(&format!("@{}", name), &format!("'{}'", value));
    }

    Some(sql)
}

fn extract_sql_from_rpc_fallback(payload: &[u8]) -> Option<String> {
    // Old fallback method: scan for SELECT or UPDATE keywords
    for i in 0..payload.len().saturating_sub(20) {
        let is_select = payload[i] == 0x53 && payload[i+1] == 0x00 && // 'S'
           payload[i+2] == 0x45 && payload[i+3] == 0x00 && // 'E'
           payload[i+4] == 0x4C && payload[i+5] == 0x00 && // 'L'
           payload[i+6] == 0x45 && payload[i+7] == 0x00 && // 'E'
           payload[i+8] == 0x43 && payload[i+9] == 0x00 && // 'C'
           payload[i+10] == 0x54 && payload[i+11] == 0x00; // 'T'

        let is_update = payload[i] == 0x55 && payload[i+1] == 0x00 && // 'U'
                  payload[i+2] == 0x50 && payload[i+3] == 0x00 && // 'P'
                  payload[i+4] == 0x44 && payload[i+5] == 0x00 && // 'D'
                  payload[i+6] == 0x41 && payload[i+7] == 0x00 && // 'A'
                  payload[i+8] == 0x54 && payload[i+9] == 0x00 && // 'T'
                  payload[i+10] == 0x45 && payload[i+11] == 0x00; // 'E'

        if is_select || is_update {
            // Extract SQL statement
            let mut sql_utf16 = Vec::new();
            let mut j = i;
            while j + 1 < payload.len() {
                let c = u16::from_le_bytes([payload[j], payload[j+1]]);
                if c == 0 { break; }
                sql_utf16.push(c);
                j += 2;
            }
            return String::from_utf16(&sql_utf16).ok();
        }
    }
    None
}

/// Evaluate a WHERE expression against a row. Supports:
/// col = 'val', col != 'val', col IS NULL, col IS NOT NULL,
/// col IN (...), col IN (subquery), AND, OR, NOT
fn eval_where(expr: &Expr, row: &Value, data_dir: &Path) -> bool {
    match expr {
        Expr::BinaryOp { left, op, right } => {
            // Evaluate left side - could be a column, CAST, or other expression
            let left_val = eval_string_arg(left, row);

            match op {
                BinaryOperator::Eq => {
                    let rhs = expr_str(right);
                    left_val == rhs
                }
                BinaryOperator::NotEq => {
                    let rhs = expr_str(right);
                    left_val != rhs
                }
                BinaryOperator::Lt => {
                    let rhs = expr_str(right);
                    if let (Ok(lv), Ok(rv)) = (left_val.parse::<f64>(), rhs.parse::<f64>()) {
                        lv < rv
                    } else {
                        left_val < rhs
                    }
                }
                BinaryOperator::LtEq => {
                    let rhs = expr_str(right);
                    if let (Ok(lv), Ok(rv)) = (left_val.parse::<f64>(), rhs.parse::<f64>()) {
                        lv <= rv
                    } else {
                        left_val <= rhs
                    }
                }
                BinaryOperator::Gt => {
                    let rhs = expr_str(right);
                    if let (Ok(lv), Ok(rv)) = (left_val.parse::<f64>(), rhs.parse::<f64>()) {
                        lv > rv
                    } else {
                        left_val > rhs
                    }
                }
                BinaryOperator::GtEq => {
                    let rhs = expr_str(right);
                    if let (Ok(lv), Ok(rv)) = (left_val.parse::<f64>(), rhs.parse::<f64>()) {
                        lv >= rv
                    } else {
                        left_val >= rhs
                    }
                }
                BinaryOperator::And => eval_where(left, row, data_dir) && eval_where(right, row, data_dir),
                BinaryOperator::Or  => eval_where(left, row, data_dir) || eval_where(right, row, data_dir),
                _ => true,
            }
        }
        Expr::Like { expr, pattern, negated, escape_char } => {
            // Evaluate operands as Values to check for NULL
            let val_result = eval_scalar_expr_with_row(expr, row);
            let pat_result = eval_scalar_expr_with_row(pattern, row);

            // Check for NULL - LIKE with NULL operand returns NULL (treated as false in WHERE)
            if val_result.is_null() || pat_result.is_null() {
                return false;
            }

            let val = value_to_string(&val_result);
            let pat = value_to_string(&pat_result);

            // escape_char is Option<char>, not Option<Expr>
            let escape = escape_char.unwrap_or('\\');

            let matches = like_match(&val, &pat, escape);
            if *negated { !matches } else { matches }
        }
        Expr::IsNull(inner) => {
            let col = col_name(inner).unwrap_or_default();
            row.get(&col).map_or(true, |v| v.is_null())
        }
        Expr::IsNotNull(inner) => {
            let col = col_name(inner).unwrap_or_default();
            row.get(&col).map_or(false, |v| !v.is_null())
        }
        Expr::Between { expr, negated, low, high } => {
            let val_str = eval_string_arg(expr, row);
            let low_str = eval_string_arg(low, row);
            let high_str = eval_string_arg(high, row);

            // Try numeric comparison first
            let in_range = if let (Ok(v), Ok(l), Ok(h)) = (val_str.parse::<f64>(), low_str.parse::<f64>(), high_str.parse::<f64>()) {
                v >= l && v <= h
            } else {
                // String comparison
                val_str >= low_str && val_str <= high_str
            };
            if *negated { !in_range } else { in_range }
        }
        Expr::InList { expr, list, negated } => {
            let val_str = eval_string_arg(expr, row);
            let in_list = list.iter().any(|e| {
                let item_str = eval_string_arg(e, row);
                val_str == item_str
            });
            if *negated { !in_list } else { in_list }
        }
        Expr::InSubquery { expr, subquery, negated } => {
            let col = col_name(expr).unwrap_or_default();
            let val = row_str(row, &col);

            // Execute subquery and collect results
            let subquery_results = execute_subquery(subquery, data_dir);
            let in_list = subquery_results.iter().any(|subval| {
                val.as_deref() == Some(subval.as_str())
            });

            if *negated { !in_list } else { in_list }
        }
        Expr::Exists { subquery, negated } => {
            // Execute subquery with outer row context for correlated subqueries
            let has_rows = execute_exists_subquery(subquery, data_dir, row);
            if *negated { !has_rows } else { has_rows }
        }
        Expr::Nested(inner) => eval_where(inner, row, data_dir),
        _ => true,
    }
}

/// Execute a subquery and return a list of values from the first column
fn execute_subquery(query: &sqlparser::ast::Query, data_dir: &Path) -> Vec<String> {
    // Parse the subquery
    if let SetExpr::Select(sel) = query.body.as_ref() {
        let from = match sel.from.first() {
            Some(f) => f,
            None => return vec![],
        };

        let table_name = from.relation.to_string()
            .split('.').last().unwrap_or("").trim_matches('"').to_string();

        // Load table data
        let path = match find_table_file_insensitive(&table_name, data_dir) {
            Some(p) => p,
            None => return vec![],
        };

        let rows: Vec<Value> = match fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
        {
            Some(r) => r,
            None => return vec![],
        };

        // Apply WHERE clause if present
        let filtered: Vec<Value> = rows.into_iter()
            .filter(|row| {
                sel.selection.as_ref().map_or(true, |e| eval_where(e, row, data_dir))
            })
            .collect();

        // Get first column from projection
        if let Some(SelectItem::UnnamedExpr(Expr::Identifier(id))) = sel.projection.first() {
            let col_name = id.value.clone();
            return filtered.iter()
                .filter_map(|row| row_str(row, &col_name).map(|s| s.to_string()))
                .collect();
        } else if sel.projection.iter().any(|p| matches!(p, SelectItem::Wildcard(_))) {
            // SELECT * - use first column from data
            if let Some(first_row) = filtered.first() {
                if let Some(obj) = first_row.as_object() {
                    if let Some((key, _)) = obj.iter().next() {
                        return filtered.iter()
                            .filter_map(|row| row_str(row, key).map(|s| s.to_string()))
                            .collect();
                    }
                }
            }
        }
    }

    vec![]
}

/// Execute an EXISTS subquery and return true if it has any rows
/// Supports correlated subqueries by passing the outer row context
fn execute_exists_subquery(query: &sqlparser::ast::Query, data_dir: &Path, outer_row: &Value) -> bool {
    if let SetExpr::Select(sel) = query.body.as_ref() {
        let from = match sel.from.first() {
            Some(f) => f,
            None => return false,
        };

        // Handle derived tables (subqueries in FROM)
        let rows: Vec<Value> = if let TableFactor::Derived { subquery, alias, .. } = &from.relation {
            // Execute derived table subquery
            match subquery.body.as_ref() {
                SetExpr::Values(vals) => {
                    // Get column aliases if specified
                    let column_aliases: Option<Vec<String>> = alias.as_ref().and_then(|a| {
                        if a.columns.is_empty() { None } else {
                            Some(a.columns.iter().map(|c| c.value.clone()).collect())
                        }
                    });

                    let mut result = Vec::new();
                    for row_vals in &vals.rows {
                        let mut obj = serde_json::Map::new();
                        for (idx, val) in row_vals.iter().enumerate() {
                            let col_name = if let Some(ref aliases) = column_aliases {
                                aliases.get(idx).cloned().unwrap_or_else(|| format!("column{}", idx + 1))
                            } else {
                                format!("column{}", idx + 1)
                            };
                            obj.insert(col_name, eval_scalar_expr(val));
                        }
                        result.push(Value::Object(obj));
                    }
                    result
                }
                _ => match execute_set_expr(subquery.body.as_ref(), data_dir) {
                    Ok(r) => r,
                    Err(_) => return false,
                }
            }
        } else {
            // Regular table
            let table_name = from.relation.to_string()
                .split('.').last().unwrap_or("").trim_matches('"').to_string();

            // Load table data
            let path = match find_table_file_insensitive(&table_name, data_dir) {
                Some(p) => p,
                None => return false,
            };

            match fs::read_to_string(&path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
            {
                Some(r) => r,
                None => return false,
            }
        };

        // Apply WHERE clause with correlated subquery support
        // The WHERE clause may reference columns from both inner and outer tables
        for row in rows {
            if let Some(where_expr) = &sel.selection {
                if eval_where_correlated(where_expr, &row, outer_row, data_dir) {
                    return true; // Found at least one matching row
                }
            } else {
                // No WHERE clause means subquery has rows
                return true;
            }
        }
    }

    false
}

/// Evaluate WHERE clause for correlated subqueries
/// Checks inner row first, then falls back to outer row for missing columns
fn eval_where_correlated(expr: &Expr, inner_row: &Value, outer_row: &Value, data_dir: &Path) -> bool {
    match expr {
        Expr::BinaryOp { left, op, right } => {
            match op {
                BinaryOperator::Eq => {
                    // Get left value (may be from inner or outer row)
                    let left_col = col_name(left).unwrap_or_default();
                    let left_val = get_correlated_value(&left_col, left, inner_row, outer_row);

                    // Get right value (may be from inner or outer row)
                    let right_col = col_name(right).unwrap_or_default();
                    let right_val = get_correlated_value(&right_col, right, inner_row, outer_row);

                    left_val == right_val
                }
                BinaryOperator::NotEq => {
                    let left_col = col_name(left).unwrap_or_default();
                    let left_val = get_correlated_value(&left_col, left, inner_row, outer_row);
                    let right_col = col_name(right).unwrap_or_default();
                    let right_val = get_correlated_value(&right_col, right, inner_row, outer_row);
                    left_val != right_val
                }
                BinaryOperator::Lt => {
                    let left_col = col_name(left).unwrap_or_default();
                    let left_val = get_correlated_value(&left_col, left, inner_row, outer_row);
                    let right_col = col_name(right).unwrap_or_default();
                    let right_val = get_correlated_value(&right_col, right, inner_row, outer_row);
                    if let (Ok(l), Ok(r)) = (left_val.parse::<f64>(), right_val.parse::<f64>()) {
                        l < r
                    } else {
                        left_val < right_val
                    }
                }
                BinaryOperator::LtEq => {
                    let left_col = col_name(left).unwrap_or_default();
                    let left_val = get_correlated_value(&left_col, left, inner_row, outer_row);
                    let right_col = col_name(right).unwrap_or_default();
                    let right_val = get_correlated_value(&right_col, right, inner_row, outer_row);
                    if let (Ok(l), Ok(r)) = (left_val.parse::<f64>(), right_val.parse::<f64>()) {
                        l <= r
                    } else {
                        left_val <= right_val
                    }
                }
                BinaryOperator::Gt => {
                    let left_col = col_name(left).unwrap_or_default();
                    let left_val = get_correlated_value(&left_col, left, inner_row, outer_row);
                    let right_col = col_name(right).unwrap_or_default();
                    let right_val = get_correlated_value(&right_col, right, inner_row, outer_row);
                    if let (Ok(l), Ok(r)) = (left_val.parse::<f64>(), right_val.parse::<f64>()) {
                        l > r
                    } else {
                        left_val > right_val
                    }
                }
                BinaryOperator::GtEq => {
                    let left_col = col_name(left).unwrap_or_default();
                    let left_val = get_correlated_value(&left_col, left, inner_row, outer_row);
                    let right_col = col_name(right).unwrap_or_default();
                    let right_val = get_correlated_value(&right_col, right, inner_row, outer_row);
                    if let (Ok(l), Ok(r)) = (left_val.parse::<f64>(), right_val.parse::<f64>()) {
                        l >= r
                    } else {
                        left_val >= right_val
                    }
                }
                BinaryOperator::And => eval_where_correlated(left, inner_row, outer_row, data_dir)
                                    && eval_where_correlated(right, inner_row, outer_row, data_dir),
                BinaryOperator::Or => eval_where_correlated(left, inner_row, outer_row, data_dir)
                                   || eval_where_correlated(right, inner_row, outer_row, data_dir),
                _ => true,
            }
        }
        Expr::Nested(inner) => eval_where_correlated(inner, inner_row, outer_row, data_dir),
        _ => true,
    }
}

/// Get value from correlated subquery - checks inner row first, then outer row
/// Handles compound identifiers like "Customers.Id" by extracting table and column names
fn get_correlated_value(col: &str, expr: &Expr, inner_row: &Value, outer_row: &Value) -> String {
    // Check if this is a compound identifier (e.g., "Customers.Id")
    if let Expr::CompoundIdentifier(parts) = expr {
        if parts.len() == 2 {
            // table.column format - use the column name
            let column_name = parts[1].value.clone();
            // Try outer row first for qualified names (assume they reference outer table)
            if let Some(v) = outer_row.get(&column_name) {
                return v.as_str().unwrap_or("").to_string();
            }
            // Fall back to inner row
            if let Some(v) = inner_row.get(&column_name) {
                return v.as_str().unwrap_or("").to_string();
            }
        }
    }

    // For simple identifiers or literals
    if col.is_empty() {
        // This is a literal value
        return expr_str(expr);
    }

    // Try inner row first (unqualified column names usually refer to inner table)
    if let Some(v) = inner_row.get(col) {
        return v.as_str().unwrap_or("").to_string();
    }

    // Fall back to outer row (for unqualified references to outer columns)
    if let Some(v) = outer_row.get(col) {
        return v.as_str().unwrap_or("").to_string();
    }

    String::new()
}

/// SQL LIKE pattern matching with support for % (any chars), _ (one char), and ESCAPE
fn like_match(value: &str, pattern: &str, escape: char) -> bool {
    let val_chars: Vec<char> = value.chars().collect();
    let pat_chars: Vec<char> = pattern.chars().collect();

    // Recursive matching with backtracking
    fn matches(val: &[char], pat: &[char], escape: char) -> bool {
        let mut vi = 0;
        let mut pi = 0;

        while pi < pat.len() {
            if pi < pat.len() && pat[pi] == escape && pi + 1 < pat.len() {
                // Escaped character - match literally
                pi += 1;
                if vi >= val.len() || val[vi] != pat[pi] {
                    return false;
                }
                vi += 1;
                pi += 1;
            } else if pi < pat.len() && pat[pi] == '%' {
                // Wildcard - match zero or more characters
                pi += 1;
                if pi >= pat.len() {
                    // % at end matches everything
                    return true;
                }
                // Try matching at each position
                for i in vi..=val.len() {
                    if matches(&val[i..], &pat[pi..], escape) {
                        return true;
                    }
                }
                return false;
            } else if pi < pat.len() && pat[pi] == '_' {
                // Single character wildcard
                if vi >= val.len() {
                    return false;
                }
                vi += 1;
                pi += 1;
            } else {
                // Regular character - must match exactly
                if vi >= val.len() || val[vi] != pat[pi] {
                    return false;
                }
                vi += 1;
                pi += 1;
            }
        }

        // Both must be consumed
        vi >= val.len()
    }

    matches(&val_chars, &pat_chars, escape)
}

fn col_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Identifier(id) => Some(id.value.clone()),
        Expr::CompoundIdentifier(parts) => parts.last().map(|i| i.value.clone()),
        _ => None,
    }
}

fn row_str<'a>(row: &'a Value, col: &str) -> Option<&'a str> {
    // Try exact match first, then case-insensitive
    row.get(col)
        .or_else(|| {
            row.as_object().and_then(|obj| {
                let lower_col = col.to_lowercase();
                obj.iter()
                    .find(|(k, _)| k.to_lowercase() == lower_col)
                    .map(|(_, v)| v)
            })
        })
        .and_then(|v| v.as_str())
}

fn row_get<'a>(row: &'a Value, col: &str) -> Option<&'a Value> {
    // Try exact match first, then case-insensitive
    row.get(col)
        .or_else(|| {
            row.as_object().and_then(|obj| {
                let lower_col = col.to_lowercase();
                obj.iter()
                    .find(|(k, _)| k.to_lowercase() == lower_col)
                    .map(|(_, v)| v)
            })
        })
}

fn expr_str(expr: &Expr) -> String {
    match expr {
        Expr::Value(v) => v.to_string().trim_matches('\'').to_string(),
        Expr::Identifier(id) => id.value.clone(),
        _ => expr.to_string().trim_matches('\'').to_string(),
    }
}

/// Evaluate HAVING clause against an aggregated row
/// Supports: COUNT(*) > N, SUM(col) < N, aggregate comparisons
fn eval_having(expr: &Expr, row: &Value) -> bool {
    match expr {
        Expr::BinaryOp { left, op, right } => {
            match op {
                BinaryOperator::Gt => {
                    let left_val = extract_having_value(left, row);
                    let right_val = extract_having_value(right, row);
                    left_val > right_val
                }
                BinaryOperator::GtEq => {
                    let left_val = extract_having_value(left, row);
                    let right_val = extract_having_value(right, row);
                    left_val >= right_val
                }
                BinaryOperator::Lt => {
                    let left_val = extract_having_value(left, row);
                    let right_val = extract_having_value(right, row);
                    left_val < right_val
                }
                BinaryOperator::LtEq => {
                    let left_val = extract_having_value(left, row);
                    let right_val = extract_having_value(right, row);
                    left_val <= right_val
                }
                BinaryOperator::Eq => {
                    let left_val = extract_having_value(left, row);
                    let right_val = extract_having_value(right, row);
                    left_val == right_val
                }
                BinaryOperator::NotEq => {
                    let left_val = extract_having_value(left, row);
                    let right_val = extract_having_value(right, row);
                    left_val != right_val
                }
                BinaryOperator::And => eval_having(left, row) && eval_having(right, row),
                BinaryOperator::Or => eval_having(left, row) || eval_having(right, row),
                _ => true,
            }
        }
        Expr::Nested(inner) => eval_having(inner, row),
        _ => true,
    }
}

/// Extract numeric value from HAVING expression
/// Supports aggregate function results (COUNT, SUM, etc.) and literal numbers
fn extract_having_value(expr: &Expr, row: &Value) -> f64 {
    match expr {
        // Literal number
        Expr::Value(sqlparser::ast::Value::Number(n, _)) => {
            n.parse::<f64>().unwrap_or(0.0)
        }
        // Aggregate function reference (e.g., COUNT(*), SUM(col))
        Expr::Function(f) => {
            let func_name = f.name.to_string().to_uppercase();
            // Try to find the aggregate result in the row
            if let Some(val) = row.get(&func_name) {
                match val {
                    Value::Number(n) => n.as_f64().unwrap_or(0.0),
                    Value::String(s) => s.parse::<f64>().unwrap_or(0.0),
                    _ => 0.0,
                }
            } else {
                // Try with column reference
                0.0
            }
        }
        // Column reference (for aggregate aliases)
        Expr::Identifier(id) => {
            if let Some(val) = row.get(&id.value) {
                match val {
                    Value::Number(n) => n.as_f64().unwrap_or(0.0),
                    Value::String(s) => s.parse::<f64>().unwrap_or(0.0),
                    _ => 0.0,
                }
            } else {
                0.0
            }
        }
        _ => 0.0,
    }
}

/// Evaluate CASE expression against a row
/// Supports: CASE WHEN condition THEN result [WHEN ...] [ELSE result] END
// CASE evaluation functions removed - now handled by eval_scalar_expr_with_context
// Helper comparison functions removed - now using compare_values() which has epsilon handling

fn eval_scalar_expr(expr: &Expr) -> Value {
    // Create an empty row for scalar evaluation (no columns available)
    let empty_row = Value::Object(serde_json::Map::new());
    eval_scalar_expr_with_row(expr, &empty_row)
}

fn eval_scalar_expr_with_context(expr: &Expr, row: &Value, data_dir: &Path) -> Value {
    // Version of eval_scalar_expr_with_row that has access to data_dir for subqueries
    match expr {
        Expr::Subquery(subquery) => {
            // Execute scalar subquery and return first value from first row
            match execute_set_expr(subquery.body.as_ref(), data_dir) {
                Ok(mut rows) if !rows.is_empty() => {
                    // Apply ORDER BY if specified
                    if !subquery.order_by.is_empty() {
                        rows.sort_by(|a, b| {
                            for ord in &subquery.order_by {
                                let col = col_name(&ord.expr).unwrap_or_default();
                                let av = row_str(a, &col).unwrap_or("");
                                let bv = row_str(b, &col).unwrap_or("");
                                // Try numeric comparison first
                                let cmp = if let (Ok(an), Ok(bn)) = (av.parse::<f64>(), bv.parse::<f64>()) {
                                    an.partial_cmp(&bn).unwrap_or(std::cmp::Ordering::Equal)
                                } else {
                                    av.cmp(bv)
                                };
                                if cmp != std::cmp::Ordering::Equal {
                                    return if ord.asc.unwrap_or(true) { cmp } else { cmp.reverse() };
                                }
                            }
                            std::cmp::Ordering::Equal
                        });
                    }

                    // Get first value from first row
                    if let Some(first_row) = rows.first() {
                        if let Some(obj) = first_row.as_object() {
                            if let Some((_key, val)) = obj.iter().next() {
                                return val.clone();
                            }
                        }
                    }
                    Value::Null
                }
                _ => Value::Null,
            }
        }
        Expr::Case { operand: _, conditions, results, else_result } => {
            // CASE expression - recursively evaluate with context
            for (cond, result) in conditions.iter().zip(results.iter()) {
                let cond_val = eval_scalar_expr_with_context(cond, row, data_dir);
                if is_truthy(&cond_val) {
                    return eval_scalar_expr_with_context(result, row, data_dir);
                }
            }
            // Else clause
            if let Some(else_expr) = else_result {
                eval_scalar_expr_with_context(else_expr, row, data_dir)
            } else {
                Value::Null
            }
        }
        Expr::BinaryOp { left, op, right } => {
            // Binary operations - recursively evaluate operands with context
            let lval = eval_scalar_expr_with_context(left, row, data_dir);
            let rval = eval_scalar_expr_with_context(right, row, data_dir);

            use BinaryOperator::*;
            match op {
                Eq => Value::String(if compare_values(&lval, &rval) == 0 { "1".to_string() } else { "0".to_string() }),
                NotEq => Value::String(if compare_values(&lval, &rval) != 0 { "1".to_string() } else { "0".to_string() }),
                Lt => Value::String(if compare_values(&lval, &rval) < 0 { "1".to_string() } else { "0".to_string() }),
                LtEq => Value::String(if compare_values(&lval, &rval) <= 0 { "1".to_string() } else { "0".to_string() }),
                Gt => Value::String(if compare_values(&lval, &rval) > 0 { "1".to_string() } else { "0".to_string() }),
                GtEq => Value::String(if compare_values(&lval, &rval) >= 0 { "1".to_string() } else { "0".to_string() }),
                And => {
                    if lval.is_null() && rval.is_null() {
                        Value::Null
                    } else if lval.is_null() {
                        if is_truthy(&rval) { Value::Null } else { Value::String("0".to_string()) }
                    } else if rval.is_null() {
                        if is_truthy(&lval) { Value::Null } else { Value::String("0".to_string()) }
                    } else {
                        let l = is_truthy(&lval);
                        let r = is_truthy(&rval);
                        Value::String(if l && r { "1".to_string() } else { "0".to_string() })
                    }
                }
                _ => eval_scalar_expr_with_row(expr, row),
            }
        }
        Expr::Nested(inner) => {
            // Recursively evaluate nested expressions with context
            eval_scalar_expr_with_context(inner, row, data_dir)
        }
        // For all other expressions, delegate to regular eval
        _ => eval_scalar_expr_with_row(expr, row),
    }
}

fn eval_scalar_expr_with_row(expr: &Expr, row: &Value) -> Value {
    match expr {
        Expr::Value(v) => match v {
            sqlparser::ast::Value::SingleQuotedString(s) => Value::String(s.clone()),
            sqlparser::ast::Value::Number(n, _) => Value::String(n.clone()),
            sqlparser::ast::Value::Null => Value::Null,
            sqlparser::ast::Value::Boolean(b) => Value::String(if *b { "1".to_string() } else { "0".to_string() }),
            _ => Value::String(v.to_string().trim_matches('\'').to_string()),
        },
        Expr::Identifier(id) => {
            // Check for boolean literals first
            let upper_id = id.value.to_uppercase();
            if upper_id == "TRUE" {
                return Value::String("1".to_string());
            } else if upper_id == "FALSE" {
                return Value::String("0".to_string());
            }
            // Try to get from row (case-insensitive), otherwise treat as literal
            if let Some(v) = row.get(&id.value) {
                v.clone()
            } else {
                // Try case-insensitive lookup
                row.as_object()
                    .and_then(|obj| {
                        let lower_id = id.value.to_lowercase();
                        obj.iter()
                            .find(|(k, _)| k.to_lowercase() == lower_id)
                            .map(|(_, v)| v.clone())
                    })
                    .unwrap_or_else(|| Value::String(id.value.clone()))
            }
        },
        Expr::CompoundIdentifier(parts) => {
            // Handle table.column references - just use the last part (column name)
            if let Some(col) = parts.last() {
                // Reuse Identifier logic
                eval_scalar_expr_with_row(&Expr::Identifier(col.clone()), row)
            } else {
                Value::Null
            }
        },
        Expr::BinaryOp { left, op, right } => {
            let lval = eval_scalar_expr_with_row(left, row);
            let rval = eval_scalar_expr_with_row(right, row);

            use BinaryOperator::*;
            match op {
                // String concatenation
                StringConcat => {
                    let l = lval.as_str().unwrap_or("").to_string();
                    let r = rval.as_str().unwrap_or("").to_string();
                    Value::String(format!("{}{}", l, r))
                }
                // Arithmetic
                Plus => eval_arithmetic(&lval, &rval, |a, b| a + b),
                Minus => eval_arithmetic(&lval, &rval, |a, b| a - b),
                Multiply => eval_arithmetic(&lval, &rval, |a, b| a * b),
                Divide => eval_arithmetic(&lval, &rval, |a, b| if b != 0.0 { a / b } else { 0.0 }),
                Modulo => eval_arithmetic(&lval, &rval, |a, b| if b != 0.0 { a % b } else { 0.0 }),
                // Comparisons
                Eq => Value::String(if lval == rval { "1".to_string() } else { "0".to_string() }),
                NotEq => Value::String(if lval != rval { "1".to_string() } else { "0".to_string() }),
                Lt => Value::String(if compare_values(&lval, &rval) < 0 { "1".to_string() } else { "0".to_string() }),
                LtEq => Value::String(if compare_values(&lval, &rval) <= 0 { "1".to_string() } else { "0".to_string() }),
                Gt => Value::String(if compare_values(&lval, &rval) > 0 { "1".to_string() } else { "0".to_string() }),
                GtEq => Value::String(if compare_values(&lval, &rval) >= 0 { "1".to_string() } else { "0".to_string() }),
                // Logical - implement 3-valued logic for NULL handling
                And => {
                    // SQL AND truth table:
                    // TRUE AND TRUE = TRUE
                    // TRUE AND FALSE = FALSE
                    // TRUE AND NULL = NULL
                    // FALSE AND anything = FALSE
                    // NULL AND TRUE = NULL
                    // NULL AND FALSE = FALSE
                    // NULL AND NULL = NULL
                    if lval.is_null() && rval.is_null() {
                        Value::Null
                    } else if lval.is_null() {
                        if is_truthy(&rval) {
                            Value::Null
                        } else {
                            Value::String("0".to_string())
                        }
                    } else if rval.is_null() {
                        if is_truthy(&lval) {
                            Value::Null
                        } else {
                            Value::String("0".to_string())
                        }
                    } else {
                        let l = is_truthy(&lval);
                        let r = is_truthy(&rval);
                        Value::String(if l && r { "1".to_string() } else { "0".to_string() })
                    }
                }
                Or => {
                    // SQL OR truth table:
                    // TRUE OR anything = TRUE
                    // FALSE OR TRUE = TRUE
                    // FALSE OR FALSE = FALSE
                    // FALSE OR NULL = NULL
                    // NULL OR TRUE = TRUE
                    // NULL OR FALSE = NULL
                    // NULL OR NULL = NULL
                    if lval.is_null() && rval.is_null() {
                        Value::Null
                    } else if lval.is_null() {
                        if is_truthy(&rval) {
                            Value::String("1".to_string())
                        } else {
                            Value::Null
                        }
                    } else if rval.is_null() {
                        if is_truthy(&lval) {
                            Value::String("1".to_string())
                        } else {
                            Value::Null
                        }
                    } else {
                        let l = is_truthy(&lval);
                        let r = is_truthy(&rval);
                        Value::String(if l || r { "1".to_string() } else { "0".to_string() })
                    }
                }
                _ => Value::String(format!("{} {} {}", value_to_string(&lval), op, value_to_string(&rval))),
            }
        }
        Expr::UnaryOp { op, expr } => {
            let val = eval_scalar_expr_with_row(expr, row);
            match op {
                sqlparser::ast::UnaryOperator::Not => {
                    Value::String(if is_truthy(&val) { "0".to_string() } else { "1".to_string() })
                }
                sqlparser::ast::UnaryOperator::Minus => {
                    if let Ok(n) = value_to_string(&val).parse::<f64>() {
                        Value::String((-n).to_string())
                    } else {
                        val
                    }
                }
                _ => val,
            }
        }
        Expr::Case { operand: _, conditions, results, else_result } => {
            // Evaluate CASE expression
            for (cond, result) in conditions.iter().zip(results.iter()) {
                let cond_val = eval_scalar_expr_with_row(cond, row);
                if is_truthy(&cond_val) {
                    return eval_scalar_expr_with_row(result, row);
                }
            }
            // Else clause
            if let Some(else_expr) = else_result {
                eval_scalar_expr_with_row(else_expr, row)
            } else {
                Value::Null
            }
        }
        Expr::IsNull(inner) => {
            let val = eval_scalar_expr_with_row(inner, row);
            Value::String(if val.is_null() { "1".to_string() } else { "0".to_string() })
        }
        Expr::IsNotNull(inner) => {
            let val = eval_scalar_expr_with_row(inner, row);
            Value::String(if !val.is_null() { "1".to_string() } else { "0".to_string() })
        }
        Expr::IsTrue(inner) => {
            let val = eval_scalar_expr_with_row(inner, row);
            // IS TRUE: returns TRUE only if value is TRUE (not NULL, not FALSE)
            Value::String(if !val.is_null() && is_truthy(&val) { "1".to_string() } else { "0".to_string() })
        }
        Expr::IsNotTrue(inner) => {
            let val = eval_scalar_expr_with_row(inner, row);
            // IS NOT TRUE: returns TRUE if value is FALSE or NULL
            Value::String(if val.is_null() || !is_truthy(&val) { "1".to_string() } else { "0".to_string() })
        }
        Expr::IsFalse(inner) => {
            let val = eval_scalar_expr_with_row(inner, row);
            // IS FALSE: returns TRUE only if value is FALSE (not NULL, not TRUE)
            Value::String(if !val.is_null() && !is_truthy(&val) { "1".to_string() } else { "0".to_string() })
        }
        Expr::IsNotFalse(inner) => {
            let val = eval_scalar_expr_with_row(inner, row);
            // IS NOT FALSE: returns TRUE if value is TRUE or NULL
            Value::String(if val.is_null() || is_truthy(&val) { "1".to_string() } else { "0".to_string() })
        }
        Expr::IsUnknown(inner) => {
            let val = eval_scalar_expr_with_row(inner, row);
            // IS UNKNOWN: same as IS NULL
            Value::String(if val.is_null() { "1".to_string() } else { "0".to_string() })
        }
        Expr::IsNotUnknown(inner) => {
            let val = eval_scalar_expr_with_row(inner, row);
            // IS NOT UNKNOWN: same as IS NOT NULL
            Value::String(if !val.is_null() { "1".to_string() } else { "0".to_string() })
        }
        Expr::Between { expr, negated, low, high } => {
            let val = eval_scalar_expr_with_row(expr, row);
            let low_val = eval_scalar_expr_with_row(low, row);
            let high_val = eval_scalar_expr_with_row(high, row);

            // If any operand is NULL, BETWEEN returns NULL
            if val.is_null() || low_val.is_null() || high_val.is_null() {
                return Value::Null;
            }

            let in_range = compare_values(&val, &low_val) >= 0 && compare_values(&val, &high_val) <= 0;
            let result = if *negated { !in_range } else { in_range };
            Value::String(if result { "1".to_string() } else { "0".to_string() })
        }
        Expr::InList { expr, list, negated } => {
            let val = eval_scalar_expr_with_row(expr, row);
            let in_list = list.iter().any(|item| {
                let item_val = eval_scalar_expr_with_row(item, row);
                val == item_val
            });
            let result = if *negated { !in_list } else { in_list };
            Value::String(if result { "1".to_string() } else { "0".to_string() })
        }
        Expr::Cast { expr: inner, data_type, .. } => {
            let result = eval_cast(inner, data_type, row);
            if result.is_empty() {
                Value::Null
            } else {
                Value::String(result)
            }
        }
        Expr::Function(f) => {
            let name = f.name.to_string().to_uppercase();
            match name.as_str() {
                "GETDATE" | "SYSDATETIME" | "GETUTCDATE" => Value::String(chrono_now()),
                "DB_NAME" => Value::String("FakeDb".to_string()),
                "SCHEMA_NAME" => Value::String("dbo".to_string()),
                "ORIGINAL_LOGIN" | "SUSER_SNAME" | "USER_NAME" | "SYSTEM_USER" => Value::String("sa".to_string()),
                _ => Value::Null,
            }
        }
        Expr::Nested(inner) => eval_scalar_expr_with_row(inner, row),
        Expr::Subquery(_subquery) => {
            // Scalar subquery - execute and return first value from first row
            // For now, we'll need to pass data_dir, but since we don't have it here,
            // we'll return a placeholder. This needs proper implementation.
            // TODO: Refactor to pass data_dir through the call chain
            Value::Null
        }
        Expr::Like { expr, pattern, negated, escape_char } => {
            let val_result = eval_scalar_expr_with_row(expr, row);
            let pat_result = eval_scalar_expr_with_row(pattern, row);

            // NULL handling - LIKE with NULL returns NULL
            if val_result.is_null() || pat_result.is_null() {
                return Value::Null;
            }

            let val = value_to_string(&val_result);
            let pat = value_to_string(&pat_result);
            // escape_char is Option<char>, not Option<Expr>
            let escape = escape_char.unwrap_or('\\');

            let matches = like_match(&val, &pat, escape);
            Value::String(if matches != *negated { "1".to_string() } else { "0".to_string() })
        }
        _ => {
            // For @@variables and other expressions, stringify
            let s = expr.to_string();
            Value::String(s)
        }
    }
}

fn eval_arithmetic(lval: &Value, rval: &Value, op: fn(f64, f64) -> f64) -> Value {
    let l = value_to_string(lval).parse::<f64>().unwrap_or(0.0);
    let r = value_to_string(rval).parse::<f64>().unwrap_or(0.0);
    let result = op(l, r);
    // Return integer if result is whole number
    if result.fract() == 0.0 {
        Value::String((result as i64).to_string())
    } else {
        Value::String(result.to_string())
    }
}

fn compare_values(lval: &Value, rval: &Value) -> i32 {
    let l = value_to_string(lval);
    let r = value_to_string(rval);

    // Try numeric comparison first
    if let (Ok(ln), Ok(rn)) = (l.parse::<f64>(), r.parse::<f64>()) {
        // Use epsilon for floating point comparison to handle precision issues
        let epsilon = 1e-10;
        let diff = ln - rn;
        if diff.abs() < epsilon { return 0; }
        if diff < 0.0 { return -1; }
        return 1;
    }

    // Fall back to string comparison
    l.cmp(&r) as i32
}

fn is_truthy(val: &Value) -> bool {
    if val.is_null() {
        return false;
    }
    let s = value_to_string(val);
    !s.is_empty() && s != "0" && !s.eq_ignore_ascii_case("false") && !s.eq_ignore_ascii_case("f")
}

fn value_to_string(val: &Value) -> String {
    match val {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => if *b { "1".to_string() } else { "0".to_string() },
        Value::Null => String::new(),
        _ => val.to_string().trim_matches('"').to_string(),
    }
}

fn chrono_now() -> String {
    // Return a fixed placeholder — no chrono dep needed
    "2026-01-01 00:00:00.000".to_string()
}

/// Evaluate date functions (GETDATE, DATEADD, DATEDIFF)
fn eval_date_func(expr: &Expr, row: &Value) -> Value {
    if let Expr::Function(f) = expr {
        let func_name = f.name.to_string().to_uppercase();
        match func_name.as_str() {
            "GETDATE" | "SYSDATETIME" | "GETUTCDATE" => {
                Value::String(chrono_now())
            }
            "DATEADD" => {
                // DATEADD(datepart, number, date)
                if f.args.len() >= 3 {
                    if let (
                        Some(FunctionArg::Unnamed(FunctionArgExpr::Expr(part_expr))),
                        Some(FunctionArg::Unnamed(FunctionArgExpr::Expr(num_expr))),
                        Some(FunctionArg::Unnamed(FunctionArgExpr::Expr(date_expr))),
                    ) = (f.args.get(0), f.args.get(1), f.args.get(2)) {
                        // For datepart, use the identifier value directly (not a column lookup)
                        let datepart = match part_expr {
                            Expr::Identifier(id) => id.value.clone().to_lowercase(),
                            _ => expr_str(part_expr).to_lowercase(),
                        };
                        let number = eval_string_arg(num_expr, row).parse::<i32>().unwrap_or(0);
                        let date_str = eval_string_arg(date_expr, row);

                        return Value::String(date_add(&date_str, &datepart, number));
                    }
                }
                Value::Null
            }
            "DATEDIFF" => {
                // DATEDIFF(datepart, startdate, enddate)
                if f.args.len() >= 3 {
                    if let (
                        Some(FunctionArg::Unnamed(FunctionArgExpr::Expr(part_expr))),
                        Some(FunctionArg::Unnamed(FunctionArgExpr::Expr(start_expr))),
                        Some(FunctionArg::Unnamed(FunctionArgExpr::Expr(end_expr))),
                    ) = (f.args.get(0), f.args.get(1), f.args.get(2)) {
                        // For datepart, use the identifier value directly (not a column lookup)
                        let datepart = match part_expr {
                            Expr::Identifier(id) => id.value.clone().to_lowercase(),
                            _ => expr_str(part_expr).to_lowercase(),
                        };
                        let start_str = eval_string_arg(start_expr, row);
                        let end_str = eval_string_arg(end_expr, row);

                        let diff = date_diff(&start_str, &end_str, &datepart);
                        return Value::String(diff.to_string());
                    }
                }
                Value::Null
            }
            _ => Value::Null,
        }
    } else {
        Value::Null
    }
}

/// Helper function to get days in a month
fn days_in_month(year: i32, month: i32) -> i32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            // Leap year check
            if (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0) {
                29
            } else {
                28
            }
        }
        _ => 30, // Fallback
    }
}

/// Add days/months/years to a date string
fn date_add(date_str: &str, datepart: &str, number: i32) -> String {
    // Parse date in format "YYYY-MM-DD" or "YYYY-MM-DD HH:MM:SS"
    let parts: Vec<&str> = date_str.split(|c| c == '-' || c == ' ' || c == ':').collect();
    if parts.len() < 3 {
        return date_str.to_string(); // Invalid format, return as-is
    }

    let year = parts[0].parse::<i32>().unwrap_or(2026);
    let month = parts[1].parse::<i32>().unwrap_or(1);
    let day = parts[2].parse::<i32>().unwrap_or(1);

    let (new_year, new_month, new_day) = match datepart {
        "day" | "dd" | "d" => {
            // Convert to total days and back
            // Simplified: doesn't handle all edge cases but works for common scenarios
            let mut new_day = day + number;
            let mut new_month = month;
            let mut new_year = year;

            // Handle forward overflow (adding days)
            while new_day > days_in_month(new_year, new_month) {
                new_day -= days_in_month(new_year, new_month);
                new_month += 1;
                if new_month > 12 {
                    new_month = 1;
                    new_year += 1;
                }
            }

            // Handle backward overflow (subtracting days)
            while new_day < 1 {
                new_month -= 1;
                if new_month < 1 {
                    new_month = 12;
                    new_year -= 1;
                }
                new_day += days_in_month(new_year, new_month);
            }

            (new_year, new_month, new_day)
        }
        "month" | "mm" | "m" => {
            let new_month = month + number;
            let years_add = (new_month - 1) / 12;
            let final_month = ((new_month - 1) % 12) + 1;
            (year + years_add, final_month, day)
        }
        "year" | "yy" | "yyyy" => {
            (year + number, month, day)
        }
        _ => (year, month, day), // Unknown datepart, no change
    };

    // Reconstruct date string
    if parts.len() > 3 {
        // Has time component
        format!("{:04}-{:02}-{:02} {}:{}:{}",
            new_year, new_month.max(1).min(12), new_day.max(1).min(31),
            parts.get(3).unwrap_or(&"00"),
            parts.get(4).unwrap_or(&"00"),
            parts.get(5).unwrap_or(&"00"))
    } else {
        format!("{:04}-{:02}-{:02}", new_year, new_month.max(1).min(12), new_day.max(1).min(31))
    }
}

/// Calculate difference between two dates
fn date_diff(start_str: &str, end_str: &str, datepart: &str) -> i32 {
    // Parse dates
    let start_parts: Vec<&str> = start_str.split(|c| c == '-' || c == ' ' || c == ':').collect();
    let end_parts: Vec<&str> = end_str.split(|c| c == '-' || c == ' ' || c == ':').collect();

    if start_parts.len() < 3 || end_parts.len() < 3 {
        return 0; // Invalid format
    }

    let start_year = start_parts[0].parse::<i32>().unwrap_or(0);
    let start_month = start_parts[1].parse::<i32>().unwrap_or(0);
    let start_day = start_parts[2].parse::<i32>().unwrap_or(0);

    let end_year = end_parts[0].parse::<i32>().unwrap_or(0);
    let end_month = end_parts[1].parse::<i32>().unwrap_or(0);
    let end_day = end_parts[2].parse::<i32>().unwrap_or(0);

    match datepart {
        "day" | "dd" | "d" => {
            // Approximate day difference
            let year_diff = (end_year - start_year) * 365;
            let month_diff = (end_month - start_month) * 30;
            let day_diff = end_day - start_day;
            year_diff + month_diff + day_diff
        }
        "month" | "mm" | "m" => {
            (end_year - start_year) * 12 + (end_month - start_month)
        }
        "year" | "yy" | "yyyy" => {
            end_year - start_year
        }
        _ => 0, // Unknown datepart
    }
}

/// Evaluate NULL-handling functions (COALESCE, ISNULL)
fn eval_null_func(expr: &Expr, row: &Value) -> Value {
    if let Expr::Function(f) = expr {
        let func_name = f.name.to_string().to_uppercase();

        match func_name.as_str() {
            "COALESCE" => {
                // COALESCE(val1, val2, ...) - Returns first non-NULL value
                for arg in &f.args {
                    if let FunctionArg::Unnamed(FunctionArgExpr::Expr(arg_expr)) = arg {
                        let val = eval_null_arg(arg_expr, row);
                        if !val.is_null() {
                            return val;
                        }
                    }
                }
                // All values were NULL
                Value::Null
            }
            "ISNULL" => {
                // ISNULL(val, default) - Returns default if val is NULL
                if f.args.len() >= 2 {
                    if let FunctionArg::Unnamed(FunctionArgExpr::Expr(val_expr)) = &f.args[0] {
                        let val = eval_null_arg(val_expr, row);
                        if !val.is_null() {
                            return val;
                        }
                        // Value is NULL, return default
                        if let FunctionArg::Unnamed(FunctionArgExpr::Expr(default_expr)) = &f.args[1] {
                            return eval_null_arg(default_expr, row);
                        }
                    }
                }
                Value::Null
            }
            _ => Value::String(format!("UNKNOWN_NULL_FUNC:{}", func_name)),
        }
    } else {
        Value::String("INVALID_NULL_FUNC_EXPR".to_string())
    }
}

/// Helper to evaluate an argument for NULL functions
fn eval_null_arg(expr: &Expr, row: &Value) -> Value {
    match expr {
        Expr::Identifier(id) => {
            row.get(&id.value).cloned().unwrap_or(Value::Null)
        }
        Expr::Value(sqlparser::ast::Value::Number(n, _)) => {
            if let Ok(i) = n.parse::<i64>() {
                Value::Number(serde_json::Number::from(i))
            } else if let Ok(f) = n.parse::<f64>() {
                Value::Number(serde_json::Number::from_f64(f).unwrap_or(serde_json::Number::from(0)))
            } else {
                Value::String(n.to_string())
            }
        }
        Expr::Value(sqlparser::ast::Value::SingleQuotedString(s)) => {
            Value::String(s.clone())
        }
        Expr::Value(sqlparser::ast::Value::Null) => {
            Value::Null
        }
        _ => Value::String(expr.to_string()),
    }
}

/// Evaluate string functions (CONCAT, UPPER, LOWER, TRIM, SUBSTRING)
fn eval_string_func(expr: &Expr, row: &Value) -> Value {
    // Handle Expr::Trim (sqlparser special node)
    if let Expr::Trim { expr: inner_expr, .. } = expr {
        let val = eval_string_arg(inner_expr, row);
        return Value::String(val.trim().to_string());
    }

    // Handle Expr::Substring (sqlparser special node)
    if let Expr::Substring { expr: str_expr, substring_from, substring_for, .. } = expr {
        let string = eval_string_arg(str_expr, row);
        let start = substring_from.as_ref()
            .and_then(|e| eval_string_arg(e, row).parse::<usize>().ok())
            .unwrap_or(1);
        let length = substring_for.as_ref()
            .and_then(|e| eval_string_arg(e, row).parse::<usize>().ok())
            .unwrap_or(0);

        // SQL SUBSTRING is 1-indexed
        let start_idx = if start > 0 { start - 1 } else { 0 };
        let chars: Vec<char> = string.chars().collect();
        let end_idx = (start_idx + length).min(chars.len());

        if start_idx < chars.len() {
            let substr: String = chars[start_idx..end_idx].iter().collect();
            return Value::String(substr);
        } else {
            return Value::String(String::new());
        }
    }

    // Handle Expr::Function (regular function call)
    if let Expr::Function(f) = expr {
        let func_name = f.name.to_string().to_uppercase();
        match func_name.as_str() {
            "CONCAT" => {
                // CONCAT(arg1, arg2, ...)
                let mut result = String::new();
                for arg in &f.args {
                    if let FunctionArg::Unnamed(FunctionArgExpr::Expr(e)) = arg {
                        let val = eval_string_arg(e, row);
                        result.push_str(&val);
                    }
                }
                Value::String(result)
            }
            "UPPER" => {
                // UPPER(string)
                if let Some(FunctionArg::Unnamed(FunctionArgExpr::Expr(e))) = f.args.first() {
                    let val = eval_string_arg(e, row);
                    Value::String(val.to_uppercase())
                } else {
                    Value::Null
                }
            }
            "LOWER" => {
                // LOWER(string)
                if let Some(FunctionArg::Unnamed(FunctionArgExpr::Expr(e))) = f.args.first() {
                    let val = eval_string_arg(e, row);
                    Value::String(val.to_lowercase())
                } else {
                    Value::Null
                }
            }
            "TRIM" => {
                // TRIM(string)
                if let Some(FunctionArg::Unnamed(FunctionArgExpr::Expr(e))) = f.args.first() {
                    let val = eval_string_arg(e, row);
                    Value::String(val.trim().to_string())
                } else {
                    Value::Null
                }
            }
            "SUBSTRING" => {
                // SUBSTRING(string, start, length)
                if f.args.len() >= 3 {
                    if let (
                        Some(FunctionArg::Unnamed(FunctionArgExpr::Expr(str_expr))),
                        Some(FunctionArg::Unnamed(FunctionArgExpr::Expr(start_expr))),
                        Some(FunctionArg::Unnamed(FunctionArgExpr::Expr(len_expr))),
                    ) = (f.args.get(0), f.args.get(1), f.args.get(2)) {
                        let string = eval_string_arg(str_expr, row);
                        let start = eval_string_arg(start_expr, row).parse::<usize>().unwrap_or(1);
                        let length = eval_string_arg(len_expr, row).parse::<usize>().unwrap_or(0);

                        // SQL SUBSTRING is 1-indexed
                        let start_idx = if start > 0 { start - 1 } else { 0 };
                        let chars: Vec<char> = string.chars().collect();
                        let end_idx = (start_idx + length).min(chars.len());

                        if start_idx < chars.len() {
                            let substr: String = chars[start_idx..end_idx].iter().collect();
                            Value::String(substr)
                        } else {
                            Value::String(String::new())
                        }
                    } else {
                        Value::Null
                    }
                } else {
                    Value::Null
                }
            }
            _ => Value::Null,
        }
    } else {
        Value::Null
    }
}

/// Evaluate an argument to a string function (can be column reference, literal, or nested function)
/// Evaluate CAST expression
fn eval_cast(expr: &Expr, data_type: &sqlparser::ast::DataType, row: &Value) -> String {
    use sqlparser::ast::DataType;

    // First evaluate the inner expression to get the value
    let value_str = eval_string_arg(expr, row);

    // Check if value is NULL (empty string or "NULL" literal)
    if value_str.is_empty() || value_str.eq_ignore_ascii_case("NULL") {
        return String::new(); // Return empty string for NULL
    }

    // Convert to target data type
    match data_type {
        DataType::Int(_) | DataType::Integer(_) | DataType::TinyInt(_) |
        DataType::SmallInt(_) | DataType::BigInt(_) => {
            // Parse as float first, then round to integer (SQL standard behavior)
            value_str.trim().parse::<f64>()
                .map(|n| n.round() as i64)
                .map(|n| n.to_string())
                .unwrap_or_else(|_| "0".to_string())
        }
        DataType::Float(_) | DataType::Real | DataType::Double | DataType::DoublePrecision => {
            // Parse as float
            value_str.trim().parse::<f64>().map(|n| n.to_string()).unwrap_or_else(|_| "0.0".to_string())
        }
        DataType::Decimal(_) | DataType::Numeric(_) => {
            // Parse as decimal/numeric
            value_str.trim().parse::<f64>().map(|n| n.to_string()).unwrap_or_else(|_| "0".to_string())
        }
        DataType::Varchar(_) | DataType::Char(_) | DataType::Text |
        DataType::String(_) | DataType::Nvarchar(_) | DataType::Character(_) => {
            // Return as string
            value_str
        }
        DataType::Date | DataType::Datetime(_) | DataType::Timestamp(_, _) => {
            // Return date/time as-is (string representation)
            value_str
        }
        DataType::Boolean | DataType::Bool => {
            // Parse as boolean
            let trimmed = value_str.trim().to_lowercase();
            if trimmed == "1" || trimmed == "true" || trimmed == "t" || trimmed == "yes" {
                "1".to_string()
            } else {
                "0".to_string()
            }
        }
        _ => {
            // Default: return as string
            value_str
        }
    }
}

fn eval_string_arg(expr: &Expr, row: &Value) -> String {
    match expr {
        Expr::Identifier(id) => {
            // Column reference - get value from row (case-insensitive)
            let value = if let Some(v) = row.get(&id.value) {
                Some(v)
            } else {
                // Try case-insensitive lookup
                row.as_object()
                    .and_then(|obj| {
                        let lower_id = id.value.to_lowercase();
                        obj.iter()
                            .find(|(k, _)| k.to_lowercase() == lower_id)
                            .map(|(_, v)| v)
                    })
            };

            if let Some(v) = value {
                // Handle both string and non-string JSON values
                match v {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => n.to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => String::new(),
                    _ => v.to_string().trim_matches('"').to_string(),
                }
            } else {
                String::new()
            }
        }
        Expr::Value(sqlparser::ast::Value::SingleQuotedString(s)) => s.clone(),
        Expr::Value(sqlparser::ast::Value::Number(n, _)) => n.clone(),
        Expr::Function(_) => {
            // Nested function call - evaluate it
            let result = eval_string_func(expr, row);
            match result {
                Value::String(s) => s,
                _ => result.to_string().trim_matches('"').to_string(),
            }
        }
        Expr::Cast { expr: inner_expr, data_type, .. } => {
            // CAST expression - evaluate inner expression and convert to target type
            eval_cast(inner_expr, data_type, row)
        }
        Expr::CompoundIdentifier(parts) => {
            // Handle table.column references - just use the last part (column name)
            if let Some(col) = parts.last() {
                eval_string_arg(&Expr::Identifier(col.clone()), row)
            } else {
                String::new()
            }
        }
        _ => expr.to_string().trim_matches('\'').to_string(),
    }
}

/// Execute a CTE SELECT and return the result rows
/// Execute a SetExpr and return the result rows
/// Used for UNION operations and subqueries
fn execute_set_expr(set_expr: &SetExpr, data_dir: &Path) -> Result<Vec<Value>> {
    execute_set_expr_with_ctes(set_expr, data_dir, &std::collections::HashMap::new())
}

fn execute_set_expr_with_ctes(set_expr: &SetExpr, data_dir: &Path, cte_data: &std::collections::HashMap<String, Vec<Value>>) -> Result<Vec<Value>> {
    match set_expr {
        SetExpr::Select(sel) => {
            // Simple SELECT execution
            let from = sel.from.first().ok_or_else(|| anyhow::anyhow!("no FROM clause"))?;

            // Check if it's a derived table (subquery)
            let base_rows: Vec<Value> = if let TableFactor::Derived { subquery, alias, .. } = &from.relation {
                // Get column aliases if specified: (VALUES ...) AS t(col1, col2)
                let column_aliases: Option<Vec<String>> = alias.as_ref().and_then(|a| {
                    if a.columns.is_empty() {
                        None
                    } else {
                        Some(a.columns.iter().map(|c| c.value.clone()).collect())
                    }
                });

                // Recursively execute the subquery
                let mut rows = match subquery.body.as_ref() {
                    SetExpr::Values(vals) => {
                        let mut rows = Vec::new();
                        for row_vals in &vals.rows {
                            let mut obj = serde_json::Map::new();
                            for (idx, val) in row_vals.iter().enumerate() {
                                let col_name = if let Some(ref aliases) = column_aliases {
                                    aliases.get(idx).cloned().unwrap_or_else(|| format!("column{}", idx + 1))
                                } else {
                                    format!("column{}", idx + 1)
                                };
                                obj.insert(col_name, eval_scalar_expr(val));
                            }
                            rows.push(Value::Object(obj));
                        }
                        rows
                    }
                    _ => execute_set_expr_with_ctes(subquery.body.as_ref(), data_dir, cte_data)?,
                };

                // If we have column aliases but they weren't applied yet (from non-VALUES subquery),
                // rename the columns now
                if let Some(ref aliases) = column_aliases {
                    rows = rows.into_iter().map(|row| {
                        if let Value::Object(mut obj) = row {
                            let keys: Vec<String> = obj.keys().cloned().collect();
                            let mut new_obj = serde_json::Map::new();
                            for (idx, old_key) in keys.iter().enumerate() {
                                if let Some(val) = obj.remove(old_key) {
                                    let new_key = aliases.get(idx).cloned().unwrap_or_else(|| old_key.clone());
                                    new_obj.insert(new_key, val);
                                }
                            }
                            Value::Object(new_obj)
                        } else {
                            row
                        }
                    }).collect();
                }

                rows
            } else {
                // Regular table or CTE reference
                let table_name = from.relation.to_string()
                    .split('.').last().unwrap_or("").trim_matches('"').to_string();

                // Check if this is a CTE reference
                if let Some(cte_rows) = cte_data.get(&table_name.to_lowercase()) {
                    cte_rows.clone()
                } else {
                    // Load table data from file
                    let path = find_table_file_insensitive(&table_name, data_dir)
                        .ok_or_else(|| anyhow::anyhow!("table not found"))?;
                    let file = File::open(&path)?;
                    let mmap = unsafe { Mmap::map(&file)? };
                    serde_json::from_slice::<Value>(&mmap)?
                        .as_array().cloned().unwrap_or_default()
                }
            };

            // Apply WHERE clause
            let filtered: Vec<Value> = base_rows.iter().filter(|row| {
                sel.selection.as_ref().map_or(true, |e| eval_where(e, row, data_dir))
            }).cloned().collect();

            // Check if we have aggregate functions in projection
            let has_aggregates = sel.projection.iter().any(|item| {
                matches!(item, SelectItem::UnnamedExpr(Expr::Function(_)) | SelectItem::ExprWithAlias { expr: Expr::Function(_), .. })
            });

            // Apply projection
            let all_wildcard = sel.projection.iter().all(|p| matches!(p, SelectItem::Wildcard(_)));
            let result: Vec<Value> = if all_wildcard {
                filtered
            } else if has_aggregates {
                // Handle aggregate functions
                let mut obj = serde_json::Map::new();
                for item in &sel.projection {
                    match item {
                        SelectItem::UnnamedExpr(Expr::Function(f)) | SelectItem::ExprWithAlias { expr: Expr::Function(f), .. } => {
                            let func = f.name.to_string().to_uppercase();
                            let alias = match item {
                                SelectItem::ExprWithAlias { alias, .. } => alias.value.clone(),
                                _ => func.clone(),
                            };

                            // Get column name from function argument
                            let col = f.args.iter().find_map(|a| {
                                if let FunctionArg::Unnamed(FunctionArgExpr::Expr(Expr::Identifier(id))) = a {
                                    Some(id.value.clone())
                                } else {
                                    None
                                }
                            });

                            // Check if COUNT(*) - special=true or Wildcard arg
                            let is_count_star = f.special || f.args.iter().any(|a| {
                                matches!(a, FunctionArg::Unnamed(FunctionArgExpr::Wildcard))
                            });

                            // Compute aggregate
                            let val = match func.as_str() {
                                "COUNT" => {
                                    if is_count_star {
                                        // COUNT(*) - count all rows including NULLs
                                        Value::String(filtered.len().to_string())
                                    } else if let Some(ref c) = col {
                                        // COUNT(column) - exclude NULLs
                                        let mut vals: Vec<String> = filtered.iter()
                                            .filter_map(|r| row_get(r, c))
                                            .filter(|v| !v.is_null())
                                            .filter_map(|v| {
                                                if let Some(s) = v.as_str() {
                                                    Some(s.to_string())
                                                } else if let Some(n) = v.as_number() {
                                                    Some(n.to_string())
                                                } else {
                                                    None
                                                }
                                            })
                                            .collect();
                                        if f.distinct {
                                            vals.sort();
                                            vals.dedup();
                                        }
                                        Value::String(vals.len().to_string())
                                    } else {
                                        Value::String(filtered.len().to_string())
                                    }
                                }
                                "SUM" => {
                                    let mut vals: Vec<f64> = filtered.iter()
                                        .filter_map(|r| col.as_ref().and_then(|c| row_get(r, c)))
                                        .filter(|v| !v.is_null())
                                        .filter_map(|v| {
                                            if let Some(s) = v.as_str() {
                                                Some(s.to_string())
                                            } else if let Some(n) = v.as_number() {
                                                Some(n.to_string())
                                            } else {
                                                None
                                            }
                                        })
                                        .filter_map(|s| s.parse::<f64>().ok())
                                        .collect();
                                    if f.distinct {
                                        vals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                                        vals.dedup();
                                    }
                                    Value::String(vals.iter().sum::<f64>().to_string())
                                }
                                "AVG" => {
                                    let mut vals: Vec<f64> = filtered.iter()
                                        .filter_map(|r| col.as_ref().and_then(|c| row_get(r, c)))
                                        .filter(|v| !v.is_null())
                                        .filter_map(|v| {
                                            if let Some(s) = v.as_str() {
                                                Some(s.to_string())
                                            } else if let Some(n) = v.as_number() {
                                                Some(n.to_string())
                                            } else {
                                                None
                                            }
                                        })
                                        .filter_map(|s| s.parse::<f64>().ok())
                                        .collect();
                                    if f.distinct {
                                        vals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                                        vals.dedup();
                                    }
                                    if vals.is_empty() {
                                        Value::String("0".to_string())
                                    } else {
                                        Value::String((vals.iter().sum::<f64>() / vals.len() as f64).to_string())
                                    }
                                }
                                "MIN" | "MAX" => {
                                    let vals: Vec<&str> = filtered.iter()
                                        .filter_map(|r| col.as_ref().and_then(|c| row_get(r, c)))
                                        .filter(|v| !v.is_null())
                                        .filter_map(|v| v.as_str())
                                        .collect();
                                    if vals.is_empty() {
                                        Value::Null
                                    } else {
                                        // Try numeric comparison
                                        let nums: Vec<f64> = vals.iter().filter_map(|s| s.parse::<f64>().ok()).collect();
                                        if nums.len() == vals.len() {
                                            let result = if func == "MIN" {
                                                nums.iter().fold(f64::INFINITY, |a, &b| a.min(b))
                                            } else {
                                                nums.iter().fold(f64::NEG_INFINITY, |a, &b| a.max(b))
                                            };
                                            Value::String(result.to_string())
                                        } else {
                                            // String comparison
                                            let result = if func == "MIN" {
                                                vals.iter().min()
                                            } else {
                                                vals.iter().max()
                                            };
                                            Value::String(result.unwrap_or(&"").to_string())
                                        }
                                    }
                                }
                                _ => Value::Null,
                            };
                            obj.insert(alias, val);
                        }
                        _ => {}
                    }
                }
                vec![Value::Object(obj)]
            } else {
                filtered.iter().map(|row| {
                    let mut obj = serde_json::Map::new();
                    for item in &sel.projection {
                        match item {
                            SelectItem::UnnamedExpr(Expr::Identifier(id)) => {
                                if let Some(v) = row_get(row, &id.value) {
                                    obj.insert(id.value.clone(), v.clone());
                                }
                            }
                            SelectItem::ExprWithAlias { expr: Expr::Identifier(id), alias } => {
                                if let Some(v) = row_get(row, &id.value) {
                                    obj.insert(alias.value.clone(), v.clone());
                                }
                            }
                            _ => {}
                        }
                    }
                    Value::Object(obj)
                }).collect()
            };

            Ok(result)
        }
        SetExpr::Values(vals) => {
            // Handle VALUES clause
            let mut result = Vec::new();
            for row_vals in &vals.rows {
                let mut obj = serde_json::Map::new();
                for (idx, val) in row_vals.iter().enumerate() {
                    // Use column names like "column1", "column2", etc.
                    let col_name = format!("column{}", idx + 1);
                    obj.insert(col_name, eval_scalar_expr(val));
                }
                result.push(Value::Object(obj));
            }
            Ok(result)
        }
        _ => Err(anyhow::anyhow!("unsupported set expression in UNION")),
    }
}

pub(crate) async fn execute_mock_sql<S>(sql: &str, socket: &mut S, data_dir: &Path) -> Result<()>
where S: AsyncRead + AsyncWrite + Unpin {
    let trimmed = sql.trim().trim_end_matches('\0');

    // SET statements — acknowledge silently
    if trimmed.to_uppercase().starts_with("SET ") {
        return send_done(socket).await;
    }

    // SELECT 1 — connection check
    if trimmed.eq_ignore_ascii_case("select 1") {
        let rows = vec![serde_json::json!({"": "1"})];
        return send_tds_response(&rows, socket).await;
    }

    // SELECT @@VERSION
    if trimmed.to_uppercase().starts_with("SELECT @@VERSION") {
        let rows = vec![serde_json::json!({"": "Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64) mocksql"})];
        return send_tds_response(&rows, socket).await;
    }

    // SELECT @@<any variable> — return 0 for numeric variables, empty string for others
    if trimmed.to_uppercase().starts_with("SELECT @@") {
        let upper = trimmed.to_uppercase();
        let val = if upper.contains("TRANCOUNT") || upper.contains("ROWCOUNT") || upper.contains("ERROR") || upper.contains("NESTLEVEL") {
            serde_json::json!({"": "0"})
        } else {
            serde_json::json!({"": ""})
        };
        let rows = vec![val];
        return send_tds_response(&rows, socket).await;
    }

    // SELECT db_name(), schema_name(), original_login() — DBeaver connection info query
    {
        let u = trimmed.to_uppercase();
        if u.contains("DB_NAME") && u.contains("SCHEMA_NAME") && u.contains("ORIGINAL_LOGIN") {
            let mut map = serde_json::Map::new();
            map.insert("db_name()".to_string(), serde_json::Value::String("FakeDb".to_string()));
            map.insert("schema_name()".to_string(), serde_json::Value::String("dbo".to_string()));
            map.insert("original_login()".to_string(), serde_json::Value::String("sa".to_string()));
            let rows = vec![serde_json::Value::Object(map)];
            return send_tds_response(&rows, socket).await;
        }
    }

    if trimmed.to_uppercase().starts_with("SELECT OBJECT_ID(") {
        // Return NULL (table doesn't exist yet) so EF creates it
        let rows = vec![serde_json::json!({"": null})];
        return send_tds_response(&rows, socket).await;
    }

    let dialect = MsSqlDialect {};
    let ast = match Parser::parse_sql(&dialect, sql) {
        Ok(a) => a,
        Err(_) => {
            send_done(socket).await?;
            return Ok(());
        }
    };

    for statement in ast {
        match statement {
            Statement::Query(query) => {
                // Handle CTEs (WITH clause)
                let mut cte_data: std::collections::HashMap<String, Vec<Value>> = std::collections::HashMap::new();
                if let Some(with) = &query.with {
                    for cte in &with.cte_tables {
                        let cte_name = cte.alias.name.value.clone();
                        // Execute the CTE query (can reference previously defined CTEs)
                        let cte_results = execute_set_expr_with_ctes(cte.query.body.as_ref(), data_dir, &cte_data)?;
                        cte_data.insert(cte_name.to_lowercase(), cte_results);
                    }
                }

                // LIMIT (standard) — used by some dialects
                let limit_n: Option<usize> = query.limit.as_ref().and_then(|e| expr_str(e).parse().ok());
                // OFFSET / FETCH (pagination)
                let offset_n: usize = query.offset.as_ref()
                    .and_then(|o| expr_str(&o.value).parse().ok()).unwrap_or(0);
                let fetch_n: Option<usize> = query.fetch.as_ref()
                    .and_then(|f| f.quantity.as_ref()).and_then(|e| expr_str(e).parse().ok());
                // ORDER BY
                let order_by: Vec<OrderByExpr> = query.order_by.clone();

                // Handle query body (UNION or SELECT)
                match *query.body {
                    SetExpr::SetOperation { op, set_quantifier, left, right } => {
                        use sqlparser::ast::{SetOperator, SetQuantifier};

                        if matches!(op, SetOperator::Union) {
                            let is_union_all = matches!(set_quantifier, SetQuantifier::All);

                            // Execute left query
                            let left_results = execute_set_expr(&left, data_dir)?;

                            // Execute right query
                            let right_results = execute_set_expr(&right, data_dir)?;

                            // Combine results
                            let mut result = left_results;
                            result.extend(right_results);

                            // Remove duplicates for UNION (not UNION ALL)
                            if !is_union_all {
                                let mut seen = std::collections::HashSet::new();
                                result.retain(|row| {
                                    let key = serde_json::to_string(row).unwrap_or_default();
                                    seen.insert(key)
                                });
                            }

                            // Apply ORDER BY if specified
                            if !order_by.is_empty() {
                                result.sort_by(|a, b| {
                                    for ord in &order_by {
                                        let col = col_name(&ord.expr).unwrap_or_default();
                                        let av = row_str(a, &col).unwrap_or("");
                                        let bv = row_str(b, &col).unwrap_or("");
                                        let cmp = av.cmp(bv);
                                        if cmp != std::cmp::Ordering::Equal {
                                            return if ord.asc.unwrap_or(true) { cmp } else { cmp.reverse() };
                                        }
                                    }
                                    std::cmp::Ordering::Equal
                                });
                            }

                            // Apply LIMIT/TOP
                            if let Some(n) = limit_n {
                                result.truncate(n);
                            }

                            send_tds_response(&result, socket).await?;
                            continue;
                        } else {
                            // Unsupported set operation
                            send_done(socket).await?;
                            continue;
                        }
                    }
                    SetExpr::Select(sel) => {
                    // TOP N (MSSQL SELECT TOP N)
                    let top_n: Option<usize> = sel.top.as_ref().and_then(|t| t.quantity.as_ref()).and_then(|q| {
                        match q {
                            sqlparser::ast::TopQuantity::Expr(e) => expr_str(e).parse().ok(),
                            sqlparser::ast::TopQuantity::Constant(n) => Some(*n as usize),
                        }
                    });
                    // Handle SELECT with no FROM (scalar expressions)
                    if sel.from.is_empty() {
                        let empty_row = Value::Object(serde_json::Map::new());
                        let mut obj = serde_json::Map::new();
                        for item in &sel.projection {
                            let (key, val) = match item {
                                SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. } => {
                                    let alias = match item {
                                        SelectItem::ExprWithAlias { alias, .. } => alias.value.clone(),
                                        _ => expr.to_string(),
                                    };
                                    (alias, eval_scalar_expr_with_context(expr, &empty_row, data_dir))
                                }
                                _ => continue,
                            };
                            obj.insert(key, val);
                        }
                        let rows = vec![Value::Object(obj)];
                        send_tds_response(&rows, socket).await?;
                        continue;
                    }

                    let from = sel.from.first().ok_or_else(|| anyhow::anyhow!("no FROM clause"))?;

                    // Load base rows - either from derived table or regular table
                    let (loaded_rows, table_name_opt): (Vec<Value>, Option<String>) = if let TableFactor::Derived { subquery, alias, .. } = &from.relation {
                        // Get column aliases if specified: (VALUES ...) AS t(col1, col2)
                        let column_aliases: Option<Vec<String>> = alias.as_ref().and_then(|a| {
                            if a.columns.is_empty() {
                                None
                            } else {
                                Some(a.columns.iter().map(|c| c.value.clone()).collect())
                            }
                        });

                        // Execute the subquery (could be VALUES or SELECT)
                        let rows = match subquery.body.as_ref() {
                            SetExpr::Values(vals) => {
                                let mut rows = Vec::new();
                                for row_vals in &vals.rows {
                                    let mut obj = serde_json::Map::new();
                                    for (idx, val) in row_vals.iter().enumerate() {
                                        let col_name = if let Some(ref aliases) = column_aliases {
                                            aliases.get(idx).cloned().unwrap_or_else(|| format!("column{}", idx + 1))
                                        } else {
                                            format!("column{}", idx + 1)
                                        };
                                        obj.insert(col_name, eval_scalar_expr(val));
                                    }
                                    rows.push(Value::Object(obj));
                                }
                                rows
                            }
                            SetExpr::Select(_) => {
                                // Execute the SELECT subquery
                                let mut rows = execute_set_expr(subquery.body.as_ref(), data_dir)?;

                                // Apply column aliases if specified
                                if let Some(ref aliases) = column_aliases {
                                    rows = rows.into_iter().map(|row| {
                                        if let Value::Object(mut obj) = row {
                                            let keys: Vec<String> = obj.keys().cloned().collect();
                                            let mut new_obj = serde_json::Map::new();
                                            for (idx, old_key) in keys.iter().enumerate() {
                                                if let Some(val) = obj.remove(old_key) {
                                                    let new_key = aliases.get(idx).cloned().unwrap_or_else(|| old_key.clone());
                                                    new_obj.insert(new_key, val);
                                                }
                                            }
                                            Value::Object(new_obj)
                                        } else {
                                            row
                                        }
                                    }).collect();
                                }

                                rows
                            }
                            _ => {
                                send_done(socket).await?;
                                continue;
                            }
                        };

                        (rows, None)
                    } else {
                        // Regular table or CTE reference
                        let table_name = from.relation.to_string()
                            .split('.').last().unwrap_or("").trim_matches('"').to_string();

                        // Check if this is a CTE reference first
                        if let Some(cte_rows) = cte_data.get(&table_name.to_lowercase()) {
                            (cte_rows.clone(), Some(table_name))
                        } else {
                            // Load from file
                            let path = match find_table_file_insensitive(&table_name, data_dir) {
                                Some(p) => p,
                                None => {
                                    send_done(socket).await?;
                                    continue;
                                }
                            };

                            let rows = match fs::read_to_string(&path)
                                .ok()
                                .and_then(|s| serde_json::from_str::<Vec<Value>>(&s).ok())
                            {
                                Some(rows) => rows,
                                None => {
                                    send_done(socket).await?;
                                    continue;
                                }
                            };

                            (rows, Some(table_name))
                        }
                    };

                    // JOIN (INNER and LEFT)
                    let join_rows: Option<Vec<Value>> = from.joins.first().and_then(|join| {
                        let right_table = join.relation.to_string()
                            .split('.').last().unwrap_or("").trim_matches('"').to_string();

                        // Extract join type and constraint
                        let (is_left_join, join_constraint) = match &join.join_operator {
                            JoinOperator::Inner(constraint) => (false, Some(constraint)),
                            JoinOperator::LeftOuter(constraint) => (true, Some(constraint)),
                            _ => return None,
                        };

                        // Extract column names from ON clause
                        let (lc, rc) = match join_constraint? {
                            JoinConstraint::On(expr) => {
                                if let Expr::BinaryOp { left, op: BinaryOperator::Eq, right } = expr {
                                    Some((
                                        match left.as_ref() {
                                            Expr::CompoundIdentifier(p) => p.last().map(|i| i.value.clone()),
                                            Expr::Identifier(i) => Some(i.value.clone()),
                                            _ => None,
                                        }?,
                                        match right.as_ref() {
                                            Expr::CompoundIdentifier(p) => p.last().map(|i| i.value.clone()),
                                            Expr::Identifier(i) => Some(i.value.clone()),
                                            _ => None,
                                        }?,
                                    ))
                                } else { None }
                            }
                            _ => None,
                        }?;

                        let rrows: Vec<Value> = serde_json::from_str(&fs::read_to_string(find_table_file_insensitive(&right_table, data_dir)?).ok()?).ok()?;
                        let mut result = Vec::new();

                        for lr in &loaded_rows {
                            let lval = row_str(lr, &lc).unwrap_or("");
                            let mut matched = false;

                            for rr in &rrows {
                                if row_str(rr, &rc).unwrap_or("") == lval {
                                    matched = true;
                                    let mut merged = lr.as_object().cloned().unwrap_or_default();
                                    if let Some(robj) = rr.as_object() {
                                        for (k, v) in robj { merged.entry(k.clone()).or_insert(v.clone()); }
                                    }
                                    result.push(Value::Object(merged));
                                }
                            }

                            // For LEFT JOIN, include left row even if no match (with NULL values for right columns)
                            if is_left_join && !matched {
                                let mut merged = lr.as_object().cloned().unwrap_or_default();
                                // Add NULL values for right table columns
                                if let Some(sample_right) = rrows.first() {
                                    if let Some(robj) = sample_right.as_object() {
                                        for k in robj.keys() {
                                            merged.entry(k.clone()).or_insert(Value::Null);
                                        }
                                    }
                                }
                                result.push(Value::Object(merged));
                            }
                        }
                        Some(result)
                    });

                    // Projections
                    #[derive(Clone)]
                    enum Proj {
                        Col(String),
                        ColAlias { col: String, alias: String },
                        Agg { func: String, col: Option<String>, arg_expr: Option<Box<Expr>>, alias: String, distinct: bool, special: bool },
                        Case { expr: Box<Expr>, alias: String },
                        StringFunc { func: Box<Expr>, alias: String },
                        DateFunc { func: Box<Expr>, alias: String },
                        NullFunc { func: Box<Expr>, alias: String },
                        Cast { expr: Box<Expr>, alias: String },
                        ScalarExpr { expr: Box<Expr>, alias: String },
                    }

                    let projections: Vec<Proj> = sel.projection.iter().filter_map(|p| match p {
                        SelectItem::Wildcard(_) => None,
                        SelectItem::UnnamedExpr(Expr::Identifier(id)) => Some(Proj::Col(id.value.clone())),
                        SelectItem::ExprWithAlias { expr: Expr::Identifier(id), alias } => Some(Proj::ColAlias { col: id.value.clone(), alias: alias.value.clone() }),
                        SelectItem::UnnamedExpr(expr @ Expr::Function(f)) => {
                            let func = f.name.to_string().to_uppercase();
                            let alias = func.clone();

                            // Check if this is a NULL-handling function
                            if matches!(func.as_str(), "COALESCE" | "ISNULL") {
                                return Some(Proj::NullFunc { func: Box::new(expr.clone()), alias });
                            }

                            // Check if this is a string function
                            if matches!(func.as_str(), "CONCAT" | "UPPER" | "LOWER" | "TRIM" | "SUBSTRING") {
                                return Some(Proj::StringFunc { func: Box::new(expr.clone()), alias });
                            }

                            // Check if this is a date function
                            if matches!(func.as_str(), "GETDATE" | "SYSDATETIME" | "GETUTCDATE" | "DATEADD" | "DATEDIFF") {
                                return Some(Proj::DateFunc { func: Box::new(expr.clone()), alias });
                            }

                            // Otherwise, treat as aggregate function
                            let col = f.args.iter().find_map(|a| {
                                if let FunctionArg::Unnamed(FunctionArgExpr::Expr(Expr::Identifier(id))) = a { Some(id.value.clone()) } else { None }
                            });
                            let arg_expr = f.args.iter().find_map(|a| {
                                if let FunctionArg::Unnamed(FunctionArgExpr::Expr(e)) = a { Some(Box::new(e.clone())) } else { None }
                            });
                            Some(Proj::Agg { func, col, arg_expr, alias, distinct: f.distinct, special: f.special })
                        }
                        SelectItem::ExprWithAlias { expr: expr @ Expr::Function(f), alias } => {
                            let func = f.name.to_string().to_uppercase();
                            let alias_str = alias.value.clone();

                            // Check if this is a NULL-handling function
                            if matches!(func.as_str(), "COALESCE" | "ISNULL") {
                                return Some(Proj::NullFunc { func: Box::new(expr.clone()), alias: alias_str });
                            }

                            // Check if this is a string function
                            if matches!(func.as_str(), "CONCAT" | "UPPER" | "LOWER" | "TRIM" | "SUBSTRING") {
                                return Some(Proj::StringFunc { func: Box::new(expr.clone()), alias: alias_str });
                            }

                            // Check if this is a date function
                            if matches!(func.as_str(), "GETDATE" | "SYSDATETIME" | "GETUTCDATE" | "DATEADD" | "DATEDIFF") {
                                return Some(Proj::DateFunc { func: Box::new(expr.clone()), alias: alias_str });
                            }

                            // Otherwise, treat as aggregate function
                            let col = f.args.iter().find_map(|a| {
                                if let FunctionArg::Unnamed(FunctionArgExpr::Expr(Expr::Identifier(id))) = a { Some(id.value.clone()) } else { None }
                            });
                            let arg_expr = f.args.iter().find_map(|a| {
                                if let FunctionArg::Unnamed(FunctionArgExpr::Expr(e)) = a { Some(Box::new(e.clone())) } else { None }
                            });
                            Some(Proj::Agg { func, col, arg_expr, alias: alias_str, distinct: f.distinct, special: f.special })
                        }
                        SelectItem::ExprWithAlias { expr, alias } if matches!(expr, Expr::Case { .. }) => {
                            Some(Proj::Case { expr: Box::new(expr.clone()), alias: alias.value.clone() })
                        }
                        SelectItem::UnnamedExpr(expr) if matches!(expr, Expr::Case { .. }) => {
                            Some(Proj::Case { expr: Box::new(expr.clone()), alias: "case".to_string() })
                        }
                        SelectItem::ExprWithAlias { expr: expr @ Expr::Trim { .. }, alias } => {
                            Some(Proj::StringFunc { func: Box::new(expr.clone()), alias: alias.value.clone() })
                        }
                        SelectItem::UnnamedExpr(expr @ Expr::Trim { .. }) => {
                            Some(Proj::StringFunc { func: Box::new(expr.clone()), alias: "TRIM".to_string() })
                        }
                        SelectItem::ExprWithAlias { expr: expr @ Expr::Substring { .. }, alias } => {
                            Some(Proj::StringFunc { func: Box::new(expr.clone()), alias: alias.value.clone() })
                        }
                        SelectItem::UnnamedExpr(expr @ Expr::Substring { .. }) => {
                            Some(Proj::StringFunc { func: Box::new(expr.clone()), alias: "SUBSTRING".to_string() })
                        }
                        SelectItem::ExprWithAlias { expr: expr @ Expr::Cast { .. }, alias } => {
                            Some(Proj::Cast { expr: Box::new(expr.clone()), alias: alias.value.clone() })
                        }
                        SelectItem::UnnamedExpr(expr @ Expr::Cast { .. }) => {
                            Some(Proj::Cast { expr: Box::new(expr.clone()), alias: "cast".to_string() })
                        }
                        SelectItem::UnnamedExpr(expr @ Expr::Subquery(_)) => {
                            Some(Proj::ScalarExpr { expr: Box::new(expr.clone()), alias: "subquery".to_string() })
                        }
                        SelectItem::ExprWithAlias { expr: expr @ Expr::Subquery(_), alias } => {
                            Some(Proj::ScalarExpr { expr: Box::new(expr.clone()), alias: alias.value.clone() })
                        }
                        _ => None,
                    }).collect();

                    let is_agg = projections.iter().any(|p| matches!(p, Proj::Agg { .. }));
                    let group_by: Vec<String> = match &sel.group_by {
                        GroupByExpr::Expressions(exprs) => exprs.iter().filter_map(|e| {
                            if let Expr::Identifier(id) = e { Some(id.value.clone()) } else { None }
                        }).collect(),
                        _ => vec![],
                    };
                    let all_wildcard = sel.projection.iter().all(|p| matches!(p, SelectItem::Wildcard(_)));

                    let project = |row: &Value| -> Value {
                        if all_wildcard { return row.clone(); }
                        let mut obj = serde_json::Map::new();
                        for p in &projections {
                            match p {
                                Proj::Col(col) => {
                                    if let Some(v) = row.get(col) { obj.insert(col.clone(), v.clone()); }
                                }
                                Proj::ColAlias { col, alias } => {
                                    if let Some(v) = row.get(col) { obj.insert(alias.clone(), v.clone()); }
                                }
                                Proj::Case { expr, alias } => {
                                    let val = eval_scalar_expr_with_context(expr, row, data_dir);
                                    obj.insert(alias.clone(), val);
                                }
                                Proj::StringFunc { func, alias } => {
                                    let val = eval_string_func(func, row);
                                    obj.insert(alias.clone(), val);
                                }
                                Proj::DateFunc { func, alias } => {
                                    let val = eval_date_func(func, row);
                                    obj.insert(alias.clone(), val);
                                }
                                Proj::NullFunc { func, alias } => {
                                    let val = eval_null_func(func, row);
                                    obj.insert(alias.clone(), val);
                                }
                                Proj::Cast { expr, alias } => {
                                    if let Expr::Cast { expr: inner_expr, data_type, .. } = expr.as_ref() {
                                        let val = eval_cast(inner_expr, data_type, row);
                                        obj.insert(alias.clone(), Value::String(val));
                                    }
                                }
                                Proj::ScalarExpr { expr, alias } => {
                                    let val = eval_scalar_expr_with_context(expr, row, data_dir);
                                    obj.insert(alias.clone(), val);
                                }
                                _ => {}
                            }
                        }
                        Value::Object(obj)
                    };

                    let base_rows: Vec<Value> = if let Some(joined) = join_rows {
                        joined
                    } else if let Some(ref tn) = table_name_opt {
                        // Check if this is a CTE reference
                        if let Some(cte_rows) = cte_data.get(&tn.to_lowercase()) {
                            cte_rows.clone()
                        } else {
                            loaded_rows
                        }
                    } else {
                        // Derived table - use loaded rows directly
                        loaded_rows
                    };

                    // WHERE
                    let mut result: Vec<Value> = base_rows.iter().filter(|row| {
                        sel.selection.as_ref().map_or(true, |e| eval_where(e, row, data_dir))
                    }).cloned().collect();

                    // Aggregation
                    if is_agg {
                        let mut groups: Vec<(String, Vec<Value>)> = Vec::new();
                        for row in result {
                            let key = group_by.iter().map(|c| row_str(&row, c).unwrap_or("")).collect::<Vec<_>>().join("|");
                            if let Some(g) = groups.iter_mut().find(|(k, _)| k == &key) { g.1.push(row); }
                            else { groups.push((key, vec![row])); }
                        }
                        result = groups.into_iter().map(|(_, group)| {
                            let mut obj = serde_json::Map::new();
                            for col in &group_by {
                                if let Some(v) = group[0].get(col) { obj.insert(col.clone(), v.clone()); }
                            }
                            for p in &projections {
                                if let Proj::Agg { func, col, arg_expr, alias, distinct, special } = p {
                                    let val = match func.as_str() {
                                        "COUNT" => {
                                            if *special {
                                                // COUNT(*) - count all rows including NULLs
                                                Value::Number(group.len().into())
                                            } else if let Some(ref c) = col {
                                                // COUNT(column) - exclude NULLs
                                                let mut vals: Vec<String> = group.iter()
                                                    .filter_map(|r| row_str(r, c))
                                                    .map(|s| s.to_string())
                                                    .collect();
                                                if *distinct {
                                                    vals.sort();
                                                    vals.dedup();
                                                }
                                                Value::Number(vals.len().into())
                                            } else {
                                                Value::Number(group.len().into())
                                            }
                                        }
                                        "SUM" => {
                                            let mut vals: Vec<f64> = group.iter()
                                                .filter_map(|r| col.as_ref().and_then(|c| row_str(r, c)).and_then(|s| s.parse::<f64>().ok()))
                                                .collect();
                                            if *distinct {
                                                vals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                                                vals.dedup();
                                            }
                                            let s: f64 = vals.iter().sum();
                                            // Round to avoid floating point precision issues
                                            let rounded = (s * 1e15).round() / 1e15;
                                            Value::String(rounded.to_string())
                                        }
                                        "MIN"  => {
                                            // Check if this is CAST to VARCHAR/CHAR - if so, force string comparison
                                            let force_string = if let Some(ref expr) = arg_expr {
                                                matches!(expr.as_ref(), Expr::Cast { data_type, .. }
                                                    if matches!(data_type, sqlparser::ast::DataType::Varchar(_) | sqlparser::ast::DataType::Char(_) | sqlparser::ast::DataType::String(_)))
                                            } else {
                                                false
                                            };

                                            let values: Vec<String> = if let Some(ref expr) = arg_expr {
                                                // Evaluate expression for each row (handles CAST, etc.)
                                                group.iter().filter_map(|r| {
                                                    let val = eval_scalar_expr_with_row(expr, r);
                                                    if val.is_null() { None }
                                                    else { Some(value_to_string(&val)) }
                                                }).collect()
                                            } else if let Some(ref c) = col {
                                                group.iter().filter_map(|r| row_str(r, c)).map(|s| s.to_string()).collect()
                                            } else {
                                                vec![]
                                            };
                                            if values.is_empty() { Value::Null }
                                            else if force_string {
                                                // Force string comparison for CAST to VARCHAR/CHAR
                                                Value::String(values.iter().min().unwrap().to_string())
                                            } else {
                                                // Try numeric comparison first
                                                let nums: Vec<f64> = values.iter().filter_map(|s| s.parse::<f64>().ok()).collect();
                                                if nums.len() == values.len() {
                                                    // All values are numeric
                                                    Value::String(nums.iter().fold(f64::INFINITY, |a, &b| a.min(b)).to_string())
                                                } else {
                                                    // String comparison
                                                    Value::String(values.iter().min().unwrap().to_string())
                                                }
                                            }
                                        }
                                        "MAX"  => {
                                            // Check if this is CAST to VARCHAR/CHAR - if so, force string comparison
                                            let force_string = if let Some(ref expr) = arg_expr {
                                                matches!(expr.as_ref(), Expr::Cast { data_type, .. }
                                                    if matches!(data_type, sqlparser::ast::DataType::Varchar(_) | sqlparser::ast::DataType::Char(_) | sqlparser::ast::DataType::String(_)))
                                            } else {
                                                false
                                            };

                                            let values: Vec<String> = if let Some(ref expr) = arg_expr {
                                                // Evaluate expression for each row (handles CAST, etc.)
                                                group.iter().filter_map(|r| {
                                                    let val = eval_scalar_expr_with_row(expr, r);
                                                    if val.is_null() { None }
                                                    else { Some(value_to_string(&val)) }
                                                }).collect()
                                            } else if let Some(ref c) = col {
                                                group.iter().filter_map(|r| row_str(r, c)).map(|s| s.to_string()).collect()
                                            } else {
                                                vec![]
                                            };
                                            if values.is_empty() { Value::Null }
                                            else if force_string {
                                                // Force string comparison for CAST to VARCHAR/CHAR
                                                Value::String(values.iter().max().unwrap().to_string())
                                            } else {
                                                // Try numeric comparison first
                                                let nums: Vec<f64> = values.iter().filter_map(|s| s.parse::<f64>().ok()).collect();
                                                if nums.len() == values.len() {
                                                    // All values are numeric
                                                    Value::String(nums.iter().fold(f64::NEG_INFINITY, |a, &b| a.max(b)).to_string())
                                                } else {
                                                    // String comparison
                                                    Value::String(values.iter().max().unwrap().to_string())
                                                }
                                            }
                                        }
                                        "AVG"  => {
                                            let mut v: Vec<f64> = group.iter()
                                                .filter_map(|r| col.as_ref().and_then(|c| row_str(r, c)).and_then(|s| s.parse::<f64>().ok()))
                                                .collect();
                                            if *distinct {
                                                v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                                                v.dedup();
                                            }
                                            Value::String((if v.is_empty() { 0.0 } else { v.iter().sum::<f64>() / v.len() as f64 }).to_string())
                                        }
                                        _ => Value::Null,
                                    };
                                    obj.insert(alias.clone(), val);
                                }
                            }
                            Value::Object(obj)
                        }).collect();

                        // HAVING - filter aggregated results
                        if let Some(having_expr) = &sel.having {
                            result.retain(|row| eval_having(having_expr, row));
                        }
                    } else {
                        result = result.iter().map(|r| project(r)).collect();
                    }

                    // ORDER BY
                    if !order_by.is_empty() {
                        result.sort_by(|a, b| {
                            for ord in &order_by {
                                let col = col_name(&ord.expr).unwrap_or_default();
                                let av = row_str(a, &col).unwrap_or("");
                                let bv = row_str(b, &col).unwrap_or("");
                                // Try numeric comparison first
                                let cmp = if let (Ok(an), Ok(bn)) = (av.parse::<f64>(), bv.parse::<f64>()) {
                                    an.partial_cmp(&bn).unwrap_or(std::cmp::Ordering::Equal)
                                } else {
                                    av.cmp(bv)
                                };
                                if cmp != std::cmp::Ordering::Equal {
                                    return if ord.asc.unwrap_or(true) { cmp } else { cmp.reverse() };
                                }
                            }
                            std::cmp::Ordering::Equal
                        });
                    }

                    // DISTINCT - remove duplicate rows
                    if sel.distinct.is_some() {
                        let mut seen = std::collections::HashSet::new();
                        result.retain(|row| {
                            let key = serde_json::to_string(row).unwrap_or_default();
                            seen.insert(key)
                        });
                    }

                    // OFFSET / FETCH
                    if offset_n > 0 || fetch_n.is_some() {
                        let end = fetch_n.map_or(result.len(), |f| (offset_n + f).min(result.len()));
                        result = result.into_iter().skip(offset_n).take(end.saturating_sub(offset_n)).collect();
                    }

                    // TOP N (MSSQL) or LIMIT
                    if let Some(n) = top_n.or(limit_n) {
                        result.truncate(n);
                    }

                    send_tds_response(&result, socket).await?;
                    }
                    SetExpr::Values(vals) => {
                        // Handle standalone VALUES clause
                        let mut result = Vec::new();
                        for row_vals in &vals.rows {
                            let mut obj = serde_json::Map::new();
                            for (idx, val) in row_vals.iter().enumerate() {
                                // Use column names like "column1", "column2", etc.
                                let col_name = format!("column{}", idx + 1);
                                obj.insert(col_name, eval_scalar_expr(val));
                            }
                            result.push(Value::Object(obj));
                        }

                        // Apply ORDER BY if specified
                        if !order_by.is_empty() {
                            result.sort_by(|a, b| {
                                for ord in &order_by {
                                    let col = col_name(&ord.expr).unwrap_or_default();
                                    let av = row_str(a, &col).unwrap_or("");
                                    let bv = row_str(b, &col).unwrap_or("");
                                    let cmp = av.cmp(bv);
                                    if cmp != std::cmp::Ordering::Equal {
                                        return if ord.asc.unwrap_or(true) { cmp } else { cmp.reverse() };
                                    }
                                }
                                std::cmp::Ordering::Equal
                            });
                        }

                        // Apply OFFSET / FETCH
                        if offset_n > 0 || fetch_n.is_some() {
                            let end = fetch_n.map_or(result.len(), |f| (offset_n + f).min(result.len()));
                            result = result.into_iter().skip(offset_n).take(end.saturating_sub(offset_n)).collect();
                        }

                        // Apply LIMIT
                        if let Some(n) = limit_n {
                            result.truncate(n);
                        }

                        send_tds_response(&result, socket).await?;
                    }
                    _ => {
                        // Unsupported SetExpr type
                        send_done(socket).await?;
                    }
                }
            }

            Statement::Insert { table_name, columns, source, .. } => {
                let tname = table_name.to_string().split('.').last().unwrap_or("").trim_matches('"').to_string();
                if let Some(path) = find_table_file_insensitive(&tname, data_dir) {
                    let _lock = WRITE_LOCK.lock().unwrap();
                    let mut rows: Vec<Value> = serde_json::from_str(&fs::read_to_string(&path)?)?;
                    let cols: Vec<String> = columns.iter().map(|c| c.value.clone()).collect();
                    if let SetExpr::Values(vals) = *source.unwrap().body {
                        for row_vals in &vals.rows {
                            let mut obj = serde_json::Map::new();
                            for (col, val) in cols.iter().zip(row_vals.iter()) {
                                obj.insert(col.clone(), Value::String(expr_str(val)));
                            }
                            rows.push(Value::Object(obj));
                        }
                    }
                    fs::write(&path, serde_json::to_string(&rows)?)?;
                }
                send_done(socket).await?;
            }

            Statement::Update { table, assignments, selection, .. } => {
                let tname = table.relation.to_string().split('.').last().unwrap_or("").trim_matches('"').to_string();
                let mut affected = 0u64;
                if let Some(path) = find_table_file_insensitive(&tname, data_dir) {
                    let _lock = WRITE_LOCK.lock().unwrap();
                    let mut rows: Vec<Value> = serde_json::from_str(&fs::read_to_string(&path)?)?;
                    for row in rows.iter_mut() {
                        let matches = selection.as_ref().map_or(true, |e| eval_where(e, row, data_dir));
                        if matches {
                            affected += 1;
                            for a in &assignments {
                                let col = a.id.iter().map(|i| i.value.clone()).collect::<Vec<_>>().join(".");
                                if let Some(obj) = row.as_object_mut() {
                                    obj.insert(col, Value::String(expr_str(&a.value)));
                                }
                            }
                        }
                    }
                    fs::write(&path, serde_json::to_string(&rows)?)?;
                }
                send_done_with_count(socket, affected).await?;
            }

            Statement::Delete { from, selection, .. } => {
                let tname = from.first()
                    .map(|t| t.relation.to_string())
                    .unwrap_or_default()
                    .split('.').last().unwrap_or("").trim_matches('"').to_string();
                let mut deleted = 0u64;
                if let Some(path) = find_table_file_insensitive(&tname, data_dir) {
                    let _lock = WRITE_LOCK.lock().unwrap();
                    let rows: Vec<Value> = serde_json::from_str(&fs::read_to_string(&path)?)?;
                    let initial_count = rows.len() as u64;
                    let kept: Vec<Value> = rows.into_iter().filter(|row| {
                        selection.as_ref().map_or(false, |e| !eval_where(e, row, data_dir))
                    }).collect();
                    deleted = initial_count - kept.len() as u64;
                    fs::write(&path, serde_json::to_string(&kept)?)?;
                }
                send_done_with_count(socket, deleted).await?;
            }

            Statement::CreateTable { name, columns, constraints, .. } => {
                let tname = name.to_string()
                    .split('.').last().unwrap_or("").trim_matches('"').to_string();
                let path = data_dir.join(format!("{}.json", tname.to_lowercase()));
                if !path.exists() {
                    let _lock = WRITE_LOCK.lock().unwrap();
                    // Check again after acquiring lock (double-check pattern)
                    if !path.exists() {
                        fs::write(&path, "[]")?;

                        // Update tables.json
                        let tables_path = data_dir.join("tables.json");
                        let mut tables: Vec<Value> = serde_json::from_str(&fs::read_to_string(&tables_path)?)?;
                        let object_id = (tables.len() + 1000) as i64;
                        tables.push(serde_json::json!({
                            "name": tname,
                            "object_id": object_id.to_string(),
                            "schema_id": "1",
                            "type": "U",
                            "type_desc": "USER_TABLE"
                        }));
                        fs::write(&tables_path, serde_json::to_string(&tables)?)?;

                        // Update objects.json
                        let objects_path = data_dir.join("objects.json");
                        let mut objects: Vec<Value> = serde_json::from_str(&fs::read_to_string(&objects_path)?)?;
                        objects.push(serde_json::json!({
                            "name": tname,
                            "object_id": object_id.to_string(),
                            "schema_id": "1",
                            "type": "U",
                            "type_desc": "USER_TABLE",
                            "create_date": chrono_now(),
                            "modify_date": chrono_now()
                        }));
                        fs::write(&objects_path, serde_json::to_string(&objects)?)?;

                        // Update columns.json
                        let columns_path = data_dir.join("columns.json");
                        let mut cols: Vec<Value> = serde_json::from_str(&fs::read_to_string(&columns_path)?)?;
                        for (idx, col) in columns.iter().enumerate() {
                            let col_name = col.name.value.clone();
                            let data_type = col.data_type.to_string().to_uppercase();
                            let (system_type_id, max_length) = match data_type.as_str() {
                                t if t.starts_with("INT") => ("56", "4"),
                                t if t.starts_with("SMALLINT") => ("52", "2"),
                                t if t.starts_with("BIGINT") => ("127", "8"),
                                t if t.starts_with("MONEY") => ("60", "8"),
                                t if t.starts_with("NVARCHAR") => ("231", "100"),
                                t if t.starts_with("VARCHAR") => ("167", "50"),
                                t if t.starts_with("DECIMAL") => ("106", "9"),
                                t if t.starts_with("NUMERIC") => ("108", "9"),
                                t if t.starts_with("BIT") => ("104", "1"),
                                t if t.starts_with("DATETIME2") => ("42", "8"),
                                t if t.starts_with("DATETIME") => ("61", "8"),
                                t if t.starts_with("UNIQUEIDENTIFIER") => ("36", "16"),
                                t if t.starts_with("VARBINARY") => ("165", "8000"),
                                t if t.starts_with("BINARY") => ("173", "8000"),
                                t if t.starts_with("FLOAT") => ("62", "8"),
                                t if t.starts_with("REAL") => ("109", "4"),
                                _ => ("231", "50"),
                            };
                            cols.push(serde_json::json!({
                                "object_id": object_id.to_string(),
                                "name": col_name,
                                "column_id": (idx + 1).to_string(),
                                "system_type_id": system_type_id,
                                "max_length": max_length,
                                "is_nullable": "1"
                            }));
                        }
                        fs::write(&columns_path, serde_json::to_string(&cols)?)?;

                        // Update indexes.json for PRIMARY KEY constraints
                        let indexes_path = data_dir.join("indexes.json");
                        let mut indexes: Vec<Value> = serde_json::from_str(&fs::read_to_string(&indexes_path)?)?;

                        // Check for PRIMARY KEY in column constraints
                        for (_idx, col) in columns.iter().enumerate() {
                            use sqlparser::ast::ColumnOption;
                            let has_pk = col.options.iter().any(|opt| matches!(opt.option, ColumnOption::Unique { is_primary: true, .. }));
                            if has_pk {
                                let index_id = (indexes.len() + 1) as i64;
                                indexes.push(serde_json::json!({
                                    "object_id": object_id.to_string(),
                                    "name": format!("PK_{}", tname),
                                    "index_id": index_id.to_string(),
                                    "type": "1",
                                    "type_desc": "CLUSTERED",
                                    "is_unique": "1",
                                    "is_primary_key": "1"
                                }));
                            }
                        }

                        // Check for PRIMARY KEY in table constraints
                        for constraint in constraints {
                            use sqlparser::ast::TableConstraint;
                            if matches!(constraint, TableConstraint::Unique { is_primary: true, .. }) {
                                let index_id = (indexes.len() + 1) as i64;
                                indexes.push(serde_json::json!({
                                    "object_id": object_id.to_string(),
                                    "name": format!("PK_{}", tname),
                                    "index_id": index_id.to_string(),
                                    "type": "1",
                                    "type_desc": "CLUSTERED",
                                    "is_unique": "1",
                                    "is_primary_key": "1"
                                }));
                                break; // Only one PK per table
                            }
                        }

                        fs::write(&indexes_path, serde_json::to_string(&indexes)?)?;
                    }
                }
                send_done(socket).await?;
            }

            Statement::Drop { names, object_type, if_exists, .. } => {
                use sqlparser::ast::ObjectType;
                if matches!(object_type, ObjectType::Table) {
                    let _lock = WRITE_LOCK.lock().unwrap();
                    for name in names {
                        let tname = name.to_string()
                            .split('.').last().unwrap_or("").trim_matches('"').to_string();
                        if let Some(path) = find_table_file_insensitive(&tname, data_dir) {
                            fs::remove_file(&path)?;

                            // Update tables.json
                            let tables_path = data_dir.join("tables.json");
                            if tables_path.exists() {
                                let mut tables: Vec<Value> = serde_json::from_str(&fs::read_to_string(&tables_path)?)?;
                                let object_id_opt = tables.iter()
                                    .find(|t| t["name"].as_str().map_or(false, |n| n.eq_ignore_ascii_case(&tname)))
                                    .and_then(|t| t["object_id"].as_str())
                                    .map(|s| s.to_string());
                                tables.retain(|t| !t["name"].as_str().map_or(false, |n| n.eq_ignore_ascii_case(&tname)));
                                fs::write(&tables_path, serde_json::to_string(&tables)?)?;

                                // Update objects.json, columns.json, and indexes.json
                                if let Some(object_id) = object_id_opt {
                                    let objects_path = data_dir.join("objects.json");
                                    if objects_path.exists() {
                                        let mut objects: Vec<Value> = serde_json::from_str(&fs::read_to_string(&objects_path)?)?;
                                        objects.retain(|o| o["object_id"].as_str() != Some(object_id.as_str()));
                                        fs::write(&objects_path, serde_json::to_string(&objects)?)?;
                                    }

                                    let columns_path = data_dir.join("columns.json");
                                    if columns_path.exists() {
                                        let mut cols: Vec<Value> = serde_json::from_str(&fs::read_to_string(&columns_path)?)?;
                                        cols.retain(|c| c["object_id"].as_str() != Some(object_id.as_str()));
                                        fs::write(&columns_path, serde_json::to_string(&cols)?)?;
                                    }

                                    let indexes_path = data_dir.join("indexes.json");
                                    if indexes_path.exists() {
                                        let mut indexes: Vec<Value> = serde_json::from_str(&fs::read_to_string(&indexes_path)?)?;
                                        indexes.retain(|i| i["object_id"].as_str() != Some(object_id.as_str()));
                                        fs::write(&indexes_path, serde_json::to_string(&indexes)?)?;
                                    }
                                }
                            }
                        } else if !if_exists {
                            // Table doesn't exist and IF EXISTS wasn't specified
                            // In a real DB this would be an error, but we'll just continue
                        }
                    }
                }
                send_done(socket).await?;
            }

            Statement::AlterTable { name, .. } => {
                // ALTER TABLE is a no-op in mocksql since we don't enforce schema
                // Just verify the table exists (optional) and send DONE
                let _tname = name.to_string()
                    .split('.').last().unwrap_or("").trim_matches('"').to_string();
                send_done(socket).await?;
            }

            Statement::Truncate { table_name, .. } => {
                let tname = table_name.to_string()
                    .split('.').last().unwrap_or("").trim_matches('"').to_string();
                if let Some(path) = find_table_file_insensitive(&tname, data_dir) {
                    let _lock = WRITE_LOCK.lock().unwrap();
                    // Keep the file but empty its contents
                    fs::write(&path, "[]")?;
                }
                send_done(socket).await?;
            }

            Statement::Grant { .. } => {
                // GRANT is a no-op in mocksql - no permission enforcement
                // Just send DONE to keep clients happy
                send_done(socket).await?;
            }

            Statement::Revoke { .. } => {
                // REVOKE is a no-op in mocksql - no permission enforcement
                // Just send DONE to keep clients happy
                send_done(socket).await?;
            }

            Statement::StartTransaction { .. } => {
                // BEGIN TRANSACTION is a no-op in mocksql - no transaction support
                // All operations are auto-committed
                send_done(socket).await?;
            }

            Statement::Commit { .. } => {
                // COMMIT is a no-op in mocksql - all operations are auto-committed
                send_done(socket).await?;
            }

            Statement::Rollback { .. } => {
                // ROLLBACK is a no-op in mocksql - no transaction support
                // Changes are already persisted immediately
                send_done(socket).await?;
            }

            Statement::Savepoint { .. } => {
                // SAVEPOINT is a no-op in mocksql - no transaction support
                send_done(socket).await?;
            }

            Statement::ReleaseSavepoint { .. } => {
                // RELEASE SAVEPOINT is a no-op in mocksql
                send_done(socket).await?;
            }

            Statement::SetTransaction { .. } => {
                // SET TRANSACTION is a no-op in mocksql - no isolation levels
                send_done(socket).await?;
            }

            _ => {
                // Unhandled statement — send DONE so client doesn't hang
                send_done(socket).await?;
            }
        }
    }
    Ok(())
}

async fn send_login_response<S: AsyncWrite + Unpin>(socket: &mut S, send_collation: bool, ack_utf8: bool, trace: bool) -> Result<()> {
    send_login_response_inner(socket, send_collation, ack_utf8, trace).await
}

async fn send_login_response_inner<S: AsyncWrite + Unpin>(socket: &mut S, send_collation: bool, ack_utf8: bool, trace: bool) -> Result<()> {
    let mut payload = BytesMut::new();

    // ENVCHANGE: database context change (type=1, new=FakeDb, old=master)
    let new_db = b"F\0a\0k\0e\0D\0b\0"; // 6 chars * 2 = 12 bytes
    let old_db = b"m\0a\0s\0t\0e\0r\0"; // 6 chars * 2 = 12 bytes
    let env_len = 1u16 + 1 + new_db.len() as u16 + 1 + old_db.len() as u16;
    payload.put_u8(0xE3);
    payload.put_u16_le(env_len);
    payload.put_u8(0x01); // type: database
    payload.put_u8(6);    // new db name length in chars
    payload.put_slice(new_db);
    payload.put_u8(6);    // old db name length in chars
    payload.put_slice(old_db);

    // ENVCHANGE: collation (type=13) — needed by JDBC driver for PreparedStatement encoding
    // Only send for TDS 7.x; TDS 8.0 (ODBC 18) rejects it
    if send_collation {
        payload.put_u8(0xE3);
        payload.put_u16_le(8); // 1(type) + 1(newlen) + 5(collation) + 1(oldlen)
        payload.put_u8(0x07); // type: collation (ENVCHANGE_SQLCOLLATION = 7)
        payload.put_u8(0x05); // new value length = 5
        payload.put_slice(&[0x09, 0x04, 0xD0, 0x00, 0x34]); // SQL_Latin1_General_CP1_CI_AS
        payload.put_u8(0x00); // old value length = 0
    }

    // LOGINACK
    let server_name = b"m\0o\0c\0k\0s\0q\0l\0"; // 7 chars * 2 = 14 bytes
    let loginack_len = 1u16 + 4 + 1 + server_name.len() as u16 + 1 + 1 + 1 + 1;
    payload.put_u8(0xAD);
    payload.put_u16_le(loginack_len);
    payload.put_u8(0x01);           // interface: SQL_DFLT
    payload.put_u32_le(0x04000074); // TDS version 7.4
    payload.put_u8(7);              // server name length in chars
    payload.put_slice(server_name);
    payload.put_u8(0x0F); payload.put_u8(0x00); payload.put_u8(0x07); payload.put_u8(0xD0); // 15.0.2000 = SQL Server 2019

    // FEATUREEXTACK: acknowledge UTF8_SUPPORT (0x0A) and SESSIONRECOVERY (0x01)
    if ack_utf8 {
        payload.put_u8(0xAE);   // FEATUREEXTACK token
        payload.put_u8(0x01);   // feature id: SESSIONRECOVERY
        payload.put_u32_le(0);  // data length = 0 (not supported, but ack'd)
        payload.put_u8(0x0A);   // feature id: UTF8_SUPPORT
        payload.put_u32_le(1);  // data length = 1
        payload.put_u8(0x01);   // enabled
        payload.put_u8(0xFF);   // terminator
    }

    // DONE
    payload.put_u8(0xFD);
    payload.put_u16_le(0x00); // status
    payload.put_u16_le(0x00); // curCmd
    payload.put_u64_le(0);    // rowCount

    let mut pkt = BytesMut::new();
    pkt.put_u8(0x04); pkt.put_u8(0x01);
    pkt.put_u16((payload.len() + 8) as u16);
    pkt.put_u16(0x00); pkt.put_u8(0x01); pkt.put_u8(0x00);
    pkt.put_slice(&payload);
    if trace { hex_dump("LOGIN RESP SEND", &pkt); }
    socket.write_all(&pkt).await?;
    socket.flush().await?;
    Ok(())
}

async fn send_done<S: AsyncWrite + Unpin>(socket: &mut S) -> Result<()> {
    send_done_with_count(socket, 0).await
}

async fn send_done_with_count<S: AsyncWrite + Unpin>(socket: &mut S, row_count: u64) -> Result<()> {
    let mut pkt = BytesMut::new();
    pkt.put_u8(0x04); pkt.put_u8(0x01);
    pkt.put_u16(8 + 13); // header(8) + done(13)
    pkt.put_slice(&[0x00, 0x00, 0x01, 0x00]);
    pkt.put_u8(0xFD);
    pkt.put_u16_le(0x10); // status: DONE_COUNT flag (0x0010)
    pkt.put_u16_le(0x00); // curCmd
    pkt.put_u64_le(row_count);
    socket.write_all(&pkt).await?;
    socket.flush().await?;
    Ok(())
}

pub(crate) fn find_table_file_insensitive(table_name: &str, data_dir: &Path) -> Option<PathBuf> {
    let target = format!("{}.json", table_name.to_lowercase());
    fs::read_dir(data_dir).ok()?.flatten().find(|e| {
        e.file_name().to_string_lossy().to_lowercase() == target
    }).map(|e| e.path())
}

pub(crate) async fn send_tds_response<S: AsyncWrite + Unpin>(rows: &Vec<Value>, socket: &mut S) -> Result<()> {
    if rows.is_empty() {
        return send_done(socket).await;
    }

    let mut payload = BytesMut::new();
    let first_row = rows[0].as_object().ok_or_else(|| anyhow::anyhow!("JSON must be array of objects"))?;

    // COLMETADATA token (0x81)
    payload.put_u8(0x81);
    payload.put_u16_le(first_row.len() as u16);

    // Compute max byte-length per column across all rows for accurate MaxLength
    let col_keys: Vec<&String> = first_row.keys().collect();
    let max_lens: Vec<u16> = col_keys.iter().map(|key| {
        rows.iter().filter_map(|r| r.get(*key))
            .filter(|v| !v.is_null())
            .map(|v| v.to_string().trim_matches('"').encode_utf16().count() * 2)
            .max().unwrap_or(2) as u16
    }).collect();

    for (i, key) in col_keys.iter().enumerate() {
        payload.put_slice(&[0x00, 0x00, 0x00, 0x00]); // UserType
        payload.put_slice(&[0x09, 0x00]); // Flags: nullable
        // Detect if all non-null values in this column are integers
        let is_int = rows.iter().filter_map(|r| r.get(*key))
            .filter(|v| !v.is_null())
            .all(|v| v.to_string().trim_matches('"').parse::<i64>().is_ok());
        if is_int {
            payload.put_u8(0x26); // INTN
            payload.put_u8(0x04); // length=4 (INT)
        } else {
            payload.put_u8(0xE7); // NVARCHAR
            payload.put_u16_le(max_lens[i]);
            payload.put_slice(&[0x09, 0x04, 0xD0, 0x00, 0x34]); // Collation
        }
        let name_utf16: Vec<u8> = key.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        payload.put_u8(key.chars().count() as u8);
        payload.put_slice(&name_utf16);
    }

    // ROW tokens (0xD1)
    for row in rows {
        payload.put_u8(0xD1);
        for (key, val) in row.as_object().unwrap() {
            let is_int = rows.iter().filter_map(|r| r.get(key))
                .filter(|v| !v.is_null())
                .all(|v| v.to_string().trim_matches('"').parse::<i64>().is_ok());
            if val.is_null() {
                if is_int { payload.put_u8(0x00); } else { payload.put_u16_le(0xFFFF); }
            } else if is_int {
                let n: i32 = val.to_string().trim_matches('"').parse().unwrap_or(0);
                payload.put_u8(0x04);
                payload.put_i32_le(n);
            } else {
                let s = val.to_string().trim_matches('"').to_string();
                let utf16: Vec<u8> = s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
                payload.put_u16_le(utf16.len() as u16);
                payload.put_slice(&utf16);
            }
        }
    }

    // DONE token: 13 bytes
    payload.put_u8(0xFD);
    payload.put_u16_le(0x00); // status
    payload.put_u16_le(0x00); // curCmd
    payload.put_u64_le(0);    // rowCount

    let mut header = BytesMut::with_capacity(8);
    header.put_u8(0x04); header.put_u8(0x01);
    header.put_u16((payload.len() + 8) as u16);
    header.put_slice(&[0x00, 0x00, 0x01, 0x00]);
    socket.write_all(&header).await?;
    socket.write_all(&payload).await?;
    socket.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;
    use tokio::net::TcpListener;

    #[test]
    fn find_existing_table() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("users.json"), "[]").unwrap();
        assert!(find_table_file_insensitive("users", dir.path()).is_some());
    }

    #[test]
    fn find_table_case_insensitive() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("Users.json"), "[]").unwrap();
        assert!(find_table_file_insensitive("USERS", dir.path()).is_some());
    }

    #[test]
    fn find_missing_table_returns_none() {
        let dir = TempDir::new().unwrap();
        assert!(find_table_file_insensitive("nonexistent", dir.path()).is_none());
    }

    #[tokio::test]
    async fn send_tds_empty_rows_writes_nothing() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        send_tds_response(&vec![], &mut server).await.unwrap();
        drop(server);
        let mut buf = vec![];
        client.read_to_end(&mut buf).await.unwrap();
        // empty rows now sends a DONE token
        assert!(!buf.is_empty() && buf[0] == 0x04);
    }

    #[tokio::test]
    async fn send_tds_response_packet_structure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        let rows: Vec<Value> = serde_json::from_str(r#"[{"id":"1","name":"Alice"}]"#).unwrap();
        send_tds_response(&rows, &mut server).await.unwrap();
        drop(server);
        let mut buf = vec![];
        client.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf[0], 0x04); assert_eq!(buf[1], 0x01);
        assert_eq!(u16::from_be_bytes([buf[2], buf[3]]) as usize, buf.len());
        assert_eq!(buf[8], 0x81); assert_eq!(buf[buf.len() - 13], 0xFD);
    }

    #[tokio::test]
    async fn execute_mock_sql_returns_rows() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("users.json"), r#"[{"id":"1","name":"Alice"}]"#).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        execute_mock_sql("SELECT * FROM users", &mut server, dir.path()).await.unwrap();
        drop(server);
        let mut buf = vec![]; client.read_to_end(&mut buf).await.unwrap();
        assert!(!buf.is_empty() && buf[0] == 0x04);
    }

    #[tokio::test]
    async fn execute_mock_sql_missing_table_writes_nothing() {
        let dir = TempDir::new().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        execute_mock_sql("SELECT * FROM ghost", &mut server, dir.path()).await.unwrap();
        drop(server);
        let mut buf = vec![]; client.read_to_end(&mut buf).await.unwrap();
        // missing table now sends a DONE token
        assert!(!buf.is_empty() && buf[0] == 0x04);
    }

    // ========================================================================
    // Unit tests for complex pure functions (recommended by TESTING_ANALYSIS.md)
    // ========================================================================

    // 1. LIKE pattern matching tests
    #[test]
    fn like_match_percent_wildcard_at_end() {
        assert!(like_match("hello", "h%", '\\'));
        assert!(like_match("hello", "he%", '\\'));
        assert!(like_match("hello", "hello%", '\\'));
        assert!(!like_match("hello", "x%", '\\'));
    }

    #[test]
    fn like_match_percent_wildcard_at_start() {
        assert!(like_match("hello", "%o", '\\'));
        assert!(like_match("hello", "%lo", '\\'));
        assert!(like_match("hello", "%hello", '\\'));
        assert!(!like_match("hello", "%x", '\\'));
    }

    #[test]
    fn like_match_percent_wildcard_middle() {
        assert!(like_match("hello", "h%o", '\\'));
        assert!(like_match("hello", "he%lo", '\\'));
        assert!(like_match("hello world", "hello%world", '\\'));
        assert!(!like_match("hello", "h%x", '\\'));
    }

    #[test]
    fn like_match_multiple_percent_wildcards() {
        assert!(like_match("hello", "%e%", '\\'));
        assert!(like_match("hello", "h%l%o", '\\'));
        assert!(like_match("hello world", "%o%o%", '\\'));
        assert!(!like_match("hello", "%x%y%", '\\'));
    }

    #[test]
    fn like_match_underscore_wildcard() {
        assert!(like_match("hello", "h_llo", '\\'));
        assert!(like_match("hello", "_ello", '\\'));
        assert!(like_match("hello", "hell_", '\\'));
        assert!(like_match("hello", "_____", '\\'));
        assert!(!like_match("hello", "h_o", '\\'));
        assert!(!like_match("hello", "______", '\\'));
    }

    #[test]
    fn like_match_underscore_and_percent() {
        assert!(like_match("hello", "h_l%", '\\'));
        assert!(like_match("hello", "%_llo", '\\'));
        assert!(like_match("hello", "h%_o", '\\'));
    }

    #[test]
    fn like_match_escape_percent() {
        assert!(like_match("100%", "100\\%", '\\'));
        assert!(like_match("50%off", "50\\%off", '\\'));
        assert!(!like_match("100", "100\\%", '\\'));
        // Without escape, % is wildcard
        assert!(like_match("100", "100%", '\\'));
        assert!(like_match("100xyz", "100%", '\\'));
    }

    #[test]
    fn like_match_escape_underscore() {
        assert!(like_match("a_b", "a\\_b", '\\'));
        assert!(like_match("test_file", "test\\_file", '\\'));
        assert!(!like_match("axb", "a\\_b", '\\'));
        // Without escape, _ matches single char
        assert!(like_match("axb", "a_b", '\\'));
    }

    #[test]
    fn like_match_escape_backslash() {
        assert!(like_match("a\\b", "a\\\\b", '\\'));
        assert!(like_match("\\", "\\\\", '\\'));
    }

    #[test]
    fn like_match_empty_pattern() {
        assert!(like_match("", "", '\\'));
        assert!(!like_match("hello", "", '\\'));
    }

    #[test]
    fn like_match_empty_value() {
        assert!(like_match("", "", '\\'));
        assert!(like_match("", "%", '\\'));
        assert!(!like_match("", "_", '\\'));
        assert!(!like_match("", "a", '\\'));
    }

    #[test]
    fn like_match_only_wildcards() {
        assert!(like_match("anything", "%", '\\'));
        assert!(like_match("", "%", '\\'));
        assert!(like_match("hello", "%%", '\\'));
        assert!(like_match("hello", "%%%", '\\'));
    }

    #[test]
    fn like_match_complex_patterns() {
        // SQL Server documentation examples
        assert!(like_match("abc", "abc", '\\'));
        assert!(like_match("abc", "a%c", '\\'));
        assert!(like_match("abc", "a_c", '\\'));
        assert!(like_match("abc", "_bc", '\\'));
        assert!(like_match("abc", "ab_", '\\'));
        assert!(like_match("abc", "a__", '\\'));   // "a" + 2 chars = "abc"
        assert!(!like_match("ab", "a__", '\\'));   // Too short
        assert!(like_match("abcd", "a__d", '\\'));
    }

    // 2. Date arithmetic tests
    #[test]
    fn days_in_month_31_day_months() {
        assert_eq!(days_in_month(2024, 1), 31);  // January
        assert_eq!(days_in_month(2024, 3), 31);  // March
        assert_eq!(days_in_month(2024, 5), 31);  // May
        assert_eq!(days_in_month(2024, 7), 31);  // July
        assert_eq!(days_in_month(2024, 8), 31);  // August
        assert_eq!(days_in_month(2024, 10), 31); // October
        assert_eq!(days_in_month(2024, 12), 31); // December
    }

    #[test]
    fn days_in_month_30_day_months() {
        assert_eq!(days_in_month(2024, 4), 30);  // April
        assert_eq!(days_in_month(2024, 6), 30);  // June
        assert_eq!(days_in_month(2024, 9), 30);  // September
        assert_eq!(days_in_month(2024, 11), 30); // November
    }

    #[test]
    fn days_in_month_february_leap_years() {
        assert_eq!(days_in_month(2024, 2), 29); // Leap year
        assert_eq!(days_in_month(2020, 2), 29); // Leap year
        assert_eq!(days_in_month(2000, 2), 29); // Century leap year (divisible by 400)
        assert_eq!(days_in_month(1600, 2), 29); // Century leap year
    }

    #[test]
    fn days_in_month_february_non_leap_years() {
        assert_eq!(days_in_month(2023, 2), 28); // Not a leap year
        assert_eq!(days_in_month(2025, 2), 28); // Not a leap year
        assert_eq!(days_in_month(1900, 2), 28); // Century non-leap year (divisible by 100, not 400)
        assert_eq!(days_in_month(2100, 2), 28); // Century non-leap year
    }

    #[test]
    fn date_add_days_simple() {
        assert_eq!(date_add("2024-01-15", "day", 10), "2024-01-25");
        assert_eq!(date_add("2024-06-20", "day", 5), "2024-06-25");
    }

    #[test]
    fn date_add_days_month_boundary() {
        assert_eq!(date_add("2024-01-25", "day", 10), "2024-02-04");
        assert_eq!(date_add("2024-03-28", "day", 5), "2024-04-02");
    }

    #[test]
    fn date_add_days_year_boundary() {
        assert_eq!(date_add("2024-12-28", "day", 5), "2025-01-02");
    }

    #[test]
    fn date_add_days_leap_year_boundary() {
        assert_eq!(date_add("2024-02-27", "day", 3), "2024-03-01"); // Feb 29 exists
        assert_eq!(date_add("2023-02-27", "day", 3), "2023-03-02"); // Feb 29 doesn't exist
    }

    #[test]
    fn date_add_months_simple() {
        assert_eq!(date_add("2024-01-15", "month", 3), "2024-04-15");
        assert_eq!(date_add("2024-06-10", "month", 2), "2024-08-10");
    }

    #[test]
    fn date_add_months_year_boundary() {
        assert_eq!(date_add("2024-11-15", "month", 3), "2025-02-15");
    }

    #[test]
    fn date_add_months_negative() {
        assert_eq!(date_add("2024-03-15", "month", -2), "2024-01-15");
    }

    #[test]
    fn date_add_years_simple() {
        assert_eq!(date_add("2024-06-15", "year", 1), "2025-06-15");
        assert_eq!(date_add("2024-06-15", "year", 5), "2029-06-15");
    }

    #[test]
    fn date_add_years_negative() {
        assert_eq!(date_add("2024-06-15", "year", -1), "2023-06-15");
    }

    #[test]
    fn date_diff_days_simple() {
        assert_eq!(date_diff("2024-01-01", "2024-01-10", "day"), 9);
    }

    #[test]
    fn date_diff_years() {
        assert_eq!(date_diff("2020-01-01", "2024-01-01", "year"), 4);
    }

    #[test]
    fn date_diff_months() {
        assert_eq!(date_diff("2024-01-01", "2024-06-01", "month"), 5);
    }

    // 3. Arithmetic with NULL tests
    #[test]
    fn eval_arithmetic_basic_operations() {
        let five = json!(5);
        let three = json!(3);

        assert_eq!(eval_arithmetic(&five, &three, |a, b| a + b), json!("8"));
        assert_eq!(eval_arithmetic(&five, &three, |a, b| a - b), json!("2"));
        assert_eq!(eval_arithmetic(&five, &three, |a, b| a * b), json!("15"));

        let result = eval_arithmetic(&json!(10), &json!(2), |a, b| a / b);
        assert_eq!(result, json!("5"));
    }

    #[test]
    fn eval_arithmetic_floating_point() {
        let result = eval_arithmetic(&json!("5.5"), &json!("2.5"), |a, b| a + b);
        assert_eq!(result, json!("8"));

        let result = eval_arithmetic(&json!("10.5"), &json!("2"), |a, b| a / b);
        // Should return decimal string
        assert!(result.as_str().unwrap().starts_with("5.25"));
    }

    #[test]
    fn eval_arithmetic_string_numbers() {
        // Should parse strings as numbers
        let result = eval_arithmetic(&json!("100"), &json!("50"), |a, b| a + b);
        assert_eq!(result, json!("150"));
    }

    // 4. Value comparison tests
    #[test]
    fn compare_values_integers() {
        assert_eq!(compare_values(&json!(5), &json!(3)), 1);
        assert_eq!(compare_values(&json!(3), &json!(5)), -1);
        assert_eq!(compare_values(&json!(5), &json!(5)), 0);
    }

    #[test]
    fn compare_values_floats() {
        assert_eq!(compare_values(&json!(5.5), &json!(3.2)), 1);
        assert_eq!(compare_values(&json!(3.2), &json!(5.5)), -1);
        assert_eq!(compare_values(&json!(5.5), &json!(5.5)), 0);
    }

    #[test]
    fn compare_values_float_equality_epsilon() {
        // Should handle floating point precision
        assert_eq!(compare_values(&json!(0.1 + 0.2), &json!(0.3)), 0);
    }

    #[test]
    fn compare_values_numeric_strings() {
        assert_eq!(compare_values(&json!("100"), &json!("20")), 1);
        assert_eq!(compare_values(&json!("5"), &json!("10")), -1);
        assert_eq!(compare_values(&json!("42"), &json!("42")), 0);
    }

    #[test]
    fn compare_values_string_comparison_fallback() {
        // Non-numeric strings should use lexicographic comparison
        assert_eq!(compare_values(&json!("hello"), &json!("world")), -1);
        assert_eq!(compare_values(&json!("zebra"), &json!("apple")), 1);
        assert_eq!(compare_values(&json!("same"), &json!("same")), 0);
    }

    #[test]
    fn compare_values_mixed_numeric_string() {
        // "10" vs 10 - both should be treated as numeric
        assert_eq!(compare_values(&json!("10"), &json!(10)), 0);
        assert_eq!(compare_values(&json!(10), &json!("10")), 0);
    }

    #[test]
    fn compare_values_negative_numbers() {
        assert_eq!(compare_values(&json!(-5), &json!(3)), -1);
        assert_eq!(compare_values(&json!(3), &json!(-5)), 1);
        assert_eq!(compare_values(&json!(-10), &json!(-20)), 1);
    }

    // 5. Days in month edge cases
    #[test]
    fn days_in_month_invalid_month() {
        // Fallback for invalid months
        assert_eq!(days_in_month(2024, 0), 30);
        assert_eq!(days_in_month(2024, 13), 30);
        assert_eq!(days_in_month(2024, 99), 30);
    }

    #[test]
    fn days_in_month_leap_year_rules() {
        // Year divisible by 4: leap year
        assert_eq!(days_in_month(2024, 2), 29);
        assert_eq!(days_in_month(2028, 2), 29);

        // Year divisible by 100: not a leap year
        assert_eq!(days_in_month(1900, 2), 28);
        assert_eq!(days_in_month(2100, 2), 28);

        // Year divisible by 400: leap year
        assert_eq!(days_in_month(2000, 2), 29);
        assert_eq!(days_in_month(2400, 2), 29);
    }
}
