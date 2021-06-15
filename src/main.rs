use git_version::git_version;
use slog::*;
use structopt::StructOpt;

mod async_aggregator;
mod packet_parser;

#[derive(Debug, StructOpt)]
#[structopt(name = "haulage", about = "A small-scale traffic monitor.")]
struct Opt {
    /// The path of the configuration file.
    #[structopt(short = "c", long = "config", default_value = "/etc/haulage/config.yml")]
    config: std::path::PathBuf,

    /// Show debug log information
    #[structopt(short = "v", long = "verebose")]
    verbose: bool,
}

#[tokio::main]
async fn main() {
    // Find and store build version information
    const GIT_VERSION: &str = git_version!(
        args = ["--long", "--all", "--always", "--dirty=-modified"],
        fallback = "unknown"
    );

    // Parse input arguments
    let opt = Opt::from_args();

    // Setup slog terminal logging
    let log_decorator = slog_term::PlainDecorator::new(std::io::stdout());
    let drain = slog_term::CompactFormat::new(log_decorator).build().fuse();

    let mut log_level = Level::Info;
    if opt.verbose {
        log_level = Level::Debug;
    }

    let drain = slog::LevelFilter::new(drain, log_level).fuse();
    let drain = slog_async::Async::new(drain).build().fuse();

    let root_log = slog::Logger::root(
        drain.fuse(),
        slog::o!("build" => GIT_VERSION,
        "pkg-version" => env!("CARGO_PKG_VERSION"),
        ),
    );

    slog::info!(root_log, "Arguments {:?}", opt);

    // Create the main user aggregator
    let user_aggregator = async_aggregator::AsyncAggregator::new(root_log.new(o!("aggregator" => "user")));
    println!("user_aggreagator {:?}", user_aggregator);

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

    loop {
        match rx.next() {
            Ok(packet) => {
                let packet_data_copy = bytes::Bytes::copy_from_slice(packet);
                let packet_log =interface_log.new(o!());
                let channel = user_aggregator.clone_input_channel();
                tokio::task::spawn(async move {
                    handle_packet(packet_data_copy, channel, packet_log).await;
                });
            }
            Err(e) => {
                slog::error!(interface_log, "packetdump unable to receive packet: {}", e);
            }
        }
    }
}

async fn handle_packet<'a>(packet: bytes::Bytes, user_agg_channel: tokio::sync::mpsc::Sender<async_aggregator::Message>, log: Logger) -> () {
    match packet_parser::parse_ethernet(
        packet_parser::EthernetPacketKind::new(&packet).unwrap(),
        &log,
    ) {
        Ok(packet_info) => {
            user_agg_channel.send(async_aggregator::Message::Report{id: packet_info.fivetuple.src, amount: packet_info.ip_payload_length as u64}).await.unwrap_or_else(
                |e| slog::error!(log, "Failed to send to dispatcher"; "error" => e.to_string())
            );
            slog::debug!(log, "Received packet info {:?}", packet_info);
        }
        Err(e) => match e {
            packet_parser::PacketParseError::IsArp => {
                slog::debug!(log, "Got an arp top level!");
            }
            _ => {
                slog::debug! {log, "Some other error {}", e};
            }
        },
    }
}
