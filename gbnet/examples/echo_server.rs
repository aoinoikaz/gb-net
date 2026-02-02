//! Echo server example — reflects all received messages back to the sender.
//!
//! Run with: `cargo run --example echo_server`

use gbnet::prelude::*;

fn main() {
    let addr: SocketAddr = "127.0.0.1:7777".parse().unwrap();
    let mut server = NetServer::bind(addr, NetworkConfig::default()).expect("Failed to bind");
    println!("Echo server listening on {}", addr);

    loop {
        for event in server.update() {
            match event {
                ServerEvent::ClientConnected(addr) => {
                    println!("[+] Client connected: {}", addr);
                }
                ServerEvent::ClientDisconnected(addr, reason) => {
                    println!("[-] Client disconnected: {} ({:?})", addr, reason);
                }
                ServerEvent::Message {
                    addr,
                    channel,
                    data,
                } => {
                    println!(
                        "[<] Received {} bytes on channel {} from {}",
                        data.len(),
                        channel,
                        addr
                    );
                    // Echo it back
                    if let Err(e) = server.send(addr, channel, &data) {
                        eprintln!("Send error: {}", e);
                    }
                }
                ServerEvent::ClientMigrated { old_addr, new_addr } => {
                    println!("[~] Client migrated: {} -> {}", old_addr, new_addr);
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(16));
    }
}
