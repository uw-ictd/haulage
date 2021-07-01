use git_version::git_version;
use reporter::UserReporter;
use slog::*;
use sqlx::prelude::*;
use structopt::StructOpt;

mod async_aggregator;
mod packet_parser;
mod reporter;

#[derive(Debug, StructOpt)]
#[structopt(name = "haulage", about = "A small-scale traffic monitor.")]
struct Opt {
    /// The path of the configuration file.
    #[structopt(
        short = "c",
        long = "config",
        default_value = "/etc/haulage/config.yml"
    )]
    config: std::path::PathBuf,

    /// Show debug log information
    #[structopt(short = "v", long = "verbose")]
    verbose: bool,
}

mod config {
    #[derive(Debug, serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Version {
        pub version: Option<i16>,
    }

    #[derive(Debug, serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct V1 {
        #[serde(with = "humantime_serde")]
        pub flow_log_interval: std::time::Duration,
        #[serde(with = "humantime_serde")]
        pub user_log_interval: std::time::Duration,
        pub interface: String,
        pub user_subnet: String,
        pub ignored_user_addresses: Vec<String>,
        pub custom: V1Custom,
    }

    #[derive(Debug, serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct V1Custom {
        #[serde(with = "humantime_serde")]
        pub reenable_poll_interval: std::time::Duration,
        pub db_location: String,
        pub db_user: String,
        pub db_pass: String,
    }

    // An internal configuration structure used by the rest of the program that can
    // be updated without breaking compatibility with existing configuration files.
    #[derive(Debug)]
    pub struct Internal {
        pub db_name: String,
        pub db_user: String,
        pub db_pass: String,
        pub flow_log_interval: std::time::Duration,
        pub user_log_interval: std::time::Duration,
        pub interface: String,
        pub user_subnet: String,
        pub ignored_user_addresses: Vec<String>,
    }
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

    // Read the configuration file
    let config_string = std::fs::read_to_string(opt.config).expect("Failed to read config file");
    let parsed_config_version: config::Version =
        serde_yaml::from_str(&config_string).expect("Failed to extract version from config file");
    slog::debug!(
        root_log,
        "Parsed the config version {:?}",
        parsed_config_version
    );
    let config_version = parsed_config_version.version.unwrap_or(1);

    let config = match config_version {
        1 => {
            let parsed_config: config::V1 =
                serde_yaml::from_str(&config_string).expect("Failed to parse config");
            slog::debug!(root_log, "Parsed config {:?}", parsed_config);
            config::Internal {
                db_name: parsed_config.custom.db_location,
                db_user: parsed_config.custom.db_user,
                db_pass: parsed_config.custom.db_pass,
                flow_log_interval: parsed_config.flow_log_interval,
                user_log_interval: parsed_config.user_log_interval,
                interface: parsed_config.interface,
                user_subnet: parsed_config.user_subnet,
                ignored_user_addresses: parsed_config.ignored_user_addresses,
            }
        }
        _ => {
            slog::error!(
                root_log,
                "Unsupported configuration version '{}' specified",
                config_version
            );
            panic!("Unsupported configuration version specified");
        }
    };

    // Connect to backing storage database
    let db_string = format!(
        "postgres://{}:{}@localhost/{}",
        config.db_user, config.db_pass, config.db_name
    );

    // TODO(matt9j) Temporary workaround to set all transactions to serializable
    // until sqlx supports per-transaction isolation settings.
    let db_pool = sqlx::postgres::PgPoolOptions::new()
        .after_connect(|conn| {
            Box::pin(async move {
                conn.execute("SET default_transaction_isolation TO 'serializable'")
                    .await?;
                Ok(())
            })
        })
        .connect(&db_string);

    let db_pool = tokio::time::timeout(std::time::Duration::from_secs(5), db_pool)
        .await
        .expect("DB connection timed out")
        .unwrap();
    slog::info!(
        root_log,
        "Connected to database db={} user={}",
        config.db_name,
        config.db_user
    );
    let db_pool = std::sync::Arc::new(db_pool);

    // Create the main user aggregator
    let user_aggregator = async_aggregator::AsyncAggregator::new::<UserReporter>(
        config.user_log_interval,
        db_pool.clone(),
        root_log.new(o!("aggregator" => "user")),
    );

    // This is a lambda closure to do a match in the filter function! Cool...
    let interface_name_match =
        |iface: &pnet_datalink::NetworkInterface| iface.name == config.interface;

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
                let packet_log = interface_log.new(o!());
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

async fn handle_packet<'a>(
    packet: bytes::Bytes,
    user_agg_channel: tokio::sync::mpsc::Sender<async_aggregator::Message>,
    log: Logger,
) -> () {
    match packet_parser::parse_ethernet(packet, &log) {
        Ok(packet_info) => {
            user_agg_channel
                .send(async_aggregator::Message::Report {
                    id: packet_info.fivetuple.src,
                    amount: packet_info.ip_payload_length as u64,
                })
                .await
                .unwrap_or_else(
                    |e| slog::error!(log, "Failed to send to dispatcher"; "error" => e.to_string()),
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
