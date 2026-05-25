use rcgen::generate_simple_self_signed;
use rustls::ServerConfig;
use socket2::{Domain, Protocol, Socket, Type};
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

fn daemonize(log: &str) {
    unsafe {
        match libc::fork() {
            -1 => { eprintln!("fork failed"); std::process::exit(1); }
            0 => {}
            _ => std::process::exit(0),
        }
        libc::setsid();
        match libc::fork() {
            -1 => { eprintln!("fork2 failed"); std::process::exit(1); }
            0 => {}
            _ => std::process::exit(0),
        }
        let devnull = libc::open(b"/dev/null\0".as_ptr() as *const libc::c_char, libc::O_RDWR);
        libc::dup2(devnull, 0);
        libc::close(devnull);
        // stdout/stderr -> log file
        let path = std::ffi::CString::new(log).unwrap();
        let fd = libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND, 0o644);
        libc::dup2(fd, 1);
        libc::dup2(fd, 2);
        libc::close(fd);
    }
}

fn print_usage() {
    println!("mocksql - A mock SQL Server for testing");
    println!();
    println!("USAGE:");
    println!("    mocksql [OPTIONS] [DATA_DIR]");
    println!();
    println!("OPTIONS:");
    println!("    -h, --help        Show this help message");
    println!("    --trace           Enable trace logging (implies --no-daemon)");
    println!("    --no-daemon       Run in foreground instead of daemonizing");
    println!();
    println!("ARGUMENTS:");
    println!("    DATA_DIR          Directory for database files (default: ./data)");
    println!();
    println!("DESCRIPTION:");
    println!("    Starts a mock SQL Server on port 1433 with TLS support.");
    println!("    The server will generate self-signed certificates if not present.");
    println!("    Data is stored as JSON files in the specified data directory.");
    println!();
    println!("EXAMPLES:");
    println!("    mocksql                    # Run with default data directory (./data)");
    println!("    mocksql /tmp/mydata        # Use custom data directory");
    println!("    mocksql --trace            # Run with trace logging in foreground");
    println!("    mocksql --no-daemon /data  # Run in foreground with custom directory");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "-h" || a == "--help") {
        print_usage();
        std::process::exit(0);
    }

    let trace = args.iter().any(|a| a == "-trace" || a == "--trace");
    let no_daemon = trace || args.iter().any(|a| a == "--no-daemon");
    let data_dir = PathBuf::from(
        args.iter().skip(1).find(|a| !a.starts_with('-'))
            .cloned().unwrap_or_else(|| "./data".to_string())
    );

    if !no_daemon {
        daemonize("/tmp/mocksql.log");
    }

    // Build tokio runtime AFTER fork
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async_main(data_dir, trace))
        .unwrap();
}

async fn async_main(data_dir: PathBuf, trace: bool) -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    if !data_dir.exists() {
        fs::create_dir_all(&data_dir)?;
    }

    // Create default sys view JSON files if missing
    let sys_defaults: &[(&str, &str)] = &[
        ("schemas.json",  r#"[{"name":"dbo","schema_id":"1","principal_id":"1"}]"#),
        ("tables.json",   r#"[]"#),
        ("columns.json",  r#"[]"#),
        ("indexes.json",  r#"[]"#),
        ("objects.json",  r#"[]"#),
        ("types.json",    r#"[]"#),
    ];
    for (name, content) in sys_defaults {
        let path = data_dir.join(name);
        if !path.exists() { fs::write(&path, content)?; }
    }

    let cert_path = data_dir.join("server.crt");
    let key_path  = data_dir.join("server.key");

    let (cert_der, key_der) = if cert_path.exists() && key_path.exists() {
        let cert_pem = fs::read(&cert_path)?;
        let key_pem  = fs::read(&key_path)?;
        let cert_der = rustls_pemfile::certs(&mut cert_pem.as_slice())
            .next().ok_or("no cert")??.to_vec();
        let key_der  = rustls_pemfile::private_key(&mut key_pem.as_slice())?
            .ok_or("no key")?;
        (cert_der, key_der)
    } else {
        let cert = generate_simple_self_signed(vec!["localhost".to_string()])?;
        let cert_der = cert.cert.der().to_vec();
        let key_der_bytes = cert.key_pair.serialize_der();
        // Save PEM files
        fs::write(&cert_path, cert.cert.pem())?;
        fs::write(&key_path,  cert.key_pair.serialize_pem())?;
        println!("Generated TLS cert: {}", cert_path.display());
        println!("Install in container: cp {} /usr/local/share/ca-certificates/mocksql.crt && update-ca-certificates", cert_path.display());
        let key_der = rustls::pki_types::PrivateKeyDer::try_from(key_der_bytes)
            .map_err(|e| format!("key error: {e}"))?;
        (cert_der, key_der)
    };

    let cert_der = rustls::pki_types::CertificateDer::from(cert_der);
    let mut tls_config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)?;
    tls_config.alpn_protocols = vec![b"tds/8.0".to_vec()];
    let acceptor = Arc::new(TlsAcceptor::from(Arc::new(tls_config)));

    let addr: SocketAddr = "0.0.0.0:1433".parse()?;
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(128)?;
    socket.set_nonblocking(true)?;
    let listener = TcpListener::from_std(socket.into())?;
    println!("mocksql listening on :1433 (TLS), data dir: {}", data_dir.display());

    loop {
        let (stream, _) = listener.accept().await?;
        let dir = data_dir.clone();
        let acc = acceptor.clone();
        tokio::spawn(async move {
            if let Err(e) = mocksql::handle_client_tls(stream, &dir, acc, trace).await {
                eprintln!("Connection dropped: {}", e);
            }
        });
    }
}
