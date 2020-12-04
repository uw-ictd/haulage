use git_version::git_version;

use slog::*;

use tokio::net::TcpListener;
use tokio::prelude::*;

mod packet_parser;

#[tokio::main]
async fn main() {
    // Find and store build version information
    const GIT_VERSION: &str = git_version!(
        args = ["--long", "--all", "--always", "--dirty=-modified"],
        fallback = "unknown"
    );

    // Setup slog terminal logging
    let log_decorator = slog_term::PlainDecorator::new(std::io::stdout());
    let drain = slog_term::CompactFormat::new(log_decorator).build().fuse();
    // TODO(matt9j) Set the log level based on command line flags.
    let drain = slog::LevelFilter::new(drain, Level::Debug).fuse();
    let drain = slog_async::Async::new(drain).build().fuse();

    let root_log = slog::Logger::root(
        drain.fuse(),
        slog::o!("build" => GIT_VERSION,
        "pkg-version" => env!("CARGO_PKG_VERSION"),
        ),
    );

    let interface_name: &str = "wlp1s0";

    // This is a lambda closure to do a match in the filter function! Cool...
    let interface_name_match =
        |iface: &pnet_datalink::NetworkInterface| iface.name == interface_name;

    let interface = pnet_datalink::interfaces()
        .into_iter()
        .filter(interface_name_match)
        .next()
        .unwrap(); // Consider adding better error logging here with unwrap_or_else

    // Create the receive channel
    let (_, mut rx) = match pnet_datalink::channel(&interface, Default::default()) {
        Ok(pnet_datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            slog::error!(root_log, "Unable to match a valid channel type");
            panic!("Unhandled channel type!");
        }
        Err(e) => panic!("Error when creating channel: {}", e),
    };

    let interface_log = root_log.new(o!("interface" => String::from(&interface.name[..])));

    for _ in 0..100 {
        match rx.next() {
            Ok(packet) => {
                match packet_parser::parse_ethernet(
                    packet_parser::EthernetPacketKind::new(packet).unwrap(),
                    &interface_log,
                ) {
                    Ok(fivetuple) => {
                        slog::debug!(interface_log, "Received fivetuple {:?}", fivetuple);
                    }
                    Err(e) => match e {
                        packet_parser::PacketParseError::IsArp => {
                            slog::debug!(interface_log, "Got an arp top level!");
                        }
                        _ => {
                            slog::debug! {interface_log, "Some other error {}", e};
                        }
                    },
                }
            }
            Err(e) => {
                slog::error!(interface_log, "packetdump unable to receive packet: {}", e);
            }
        }
    }

    slog::error!(root_log, "Uh oh got far!");

    let addr = "127.0.0.1:4567";
    // let mut socket_listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    //
    // let server = async move {
    //     let mut incoming = socket_listener.incoming();
    //     while let Some(socket_connection) = incoming.next().await {
    //         match socket_connection {
    //             Err(e) => {
    //                 // Handle an error by printing like a boss.
    //                 eprintln!("accept error = {:?}", e);
    //             }
    //             Ok(mut socket) => {
    //                 println!("Accepted a connection from {:?}", socket.peer_addr());
    //                 // One day we'll do something here...
    //                 tokio::spawn(async move {
    //                     let (mut reader, mut writer) = socket.split();
    //                     match tokio::io::copy(&mut reader, &mut writer).await {
    //                         Ok(amount_copied) => {
    //                             println!("We wrote {} bytes", amount_copied);
    //                         }
    //                         Err(e) => eprintln!("IO copy error {:?}", e),
    //                     }
    //                 });
    //             }
    //         }
    //     }
    // };

    slog::info!(root_log, "Server running on {:?}", addr);

    // server.await;
}
