use iroh::{Endpoint, EndpointAddr, RelayMode, endpoint::presets};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 2 {
        return Err("expected endpoint id and socket address".into());
    }
    let endpoint = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .bind().await?;
    let addr = EndpointAddr::new(args[0].parse()?).with_ip_addr(args[1].parse()?);
    let conn = endpoint.connect(addr, b"go-iroh/no-sni/1").await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(b"no-sni round trip").await?;
    send.finish()?;
    let reply = recv.read_to_end(1024).await?;
    if reply != b"no-sni round trip" {
        return Err("unexpected echo".into());
    }
    println!("echo verified");
    endpoint.close().await;
    Ok(())
}
