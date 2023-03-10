#![cfg(feature = "server")]

use std::{
    convert::Infallible,
    env,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

use hyper::{
    server::conn::AddrIncoming,
    service::{make_service_fn, service_fn},
    Body, Request, Response, Server,
};
use tokio::{
    process::Command,
    time::{self, Duration},
};

use hyper_rustls::server::{acceptor::TlsAcceptor, config::TlsConfigBuilder};

const TLS_CERTIFICATE: &[u8] = include_bytes!("cert.pem");
const TLS_KEY: &[u8] = include_bytes!("key.pem");

fn target_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

const fn ip_addr() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

async fn handle(_req: Request<Body>) -> Result<Response<Body>, Infallible> {
    Ok(Response::new(Body::from("https server")))
}

#[tokio::test]
async fn tls_server() {
    let addr = SocketAddr::from((ip_addr(), 8080));

    tokio::spawn(async move {
        let incoming = AddrIncoming::bind(&addr).unwrap();

        let make_service =
            make_service_fn(|_conn| async { Ok::<_, Infallible>(service_fn(handle)) });

        let config = TlsConfigBuilder::default()
            .cert_key(TLS_CERTIFICATE, TLS_KEY)
            .alpn_protocols(vec!["h2", "http/1.1", "http/1.0"])
            .build()
            .expect("failed to build tls config");
        let incoming = TlsAcceptor::new(Arc::new(config), incoming);

        let server = Server::builder(incoming).serve(make_service);

        if let Err(e) = server.await {
            panic!("failed to start server: {e}");
        }
    });

    time::sleep(Duration::from_millis(500)).await;

    let output = Command::new("curl")
        .arg("--silent")
        .arg("--cacert")
        .arg(format!(
            "{}",
            target_dir().join("tests/ca.pem").to_string_lossy()
        ))
        .arg(format!("https://{addr}"))
        .output()
        .await
        .expect("cannot run curl");

    if !output.status.success() {
        panic!(
            "curl command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    assert_eq!(String::from_utf8_lossy(&output.stdout), "https server");
}
