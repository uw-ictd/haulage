use std::collections::HashSet;
use std::iter::FromIterator;
use std::str::FromStr;

use git_version::git_version;
use reporter::UserReporter;
use slog::*;
use sqlx::migrate::Migrate;
use sqlx::prelude::*;
use structopt::StructOpt;

mod accounter;
mod async_aggregator;
mod enforcer;
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

    /// Run pending schema migrations agains the local database
    #[structopt(long = "db-upgrade")]
    migrate: bool,

    /// The path of the directory containing database migration files.
    #[structopt(
        long = "db-migration-directory",
        default_value = "/usr/share/haulage/migrations"
    )]
    migration_directory: std::path::PathBuf,

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
        pub reenable_poll_interval: std::time::Duration,
        pub interface: String,
        pub user_subnet: ipnetwork::IpNetwork,
        pub ignored_user_addresses: std::collections::HashSet<std::net::IpAddr>,
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
                reenable_poll_interval: parsed_config.custom.reenable_poll_interval,
                interface: parsed_config.interface,
                user_subnet: ipnetwork::IpNetwork::from_str(&parsed_config.user_subnet).unwrap(),
                ignored_user_addresses: HashSet::from_iter(
                    parsed_config.ignored_user_addresses.iter().map(|a| {
                        std::net::IpAddr::from_str(a).expect("Failed to parse configued IP address")
                    }),
                ),
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

    let config = std::sync::Arc::new(config);

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

    let mut migrator = sqlx::migrate::Migrator::new(opt.migration_directory)
        .await
        .expect("Unable to read available database schema migrations");

    // If requested, run any necessary database migrations
    if opt.migrate {
        slog::warn!(
            root_log,
            "Running database migrations, this process can not be easily undone!"
        );
        migrator.set_ignore_missing(true);
        migrator.run(db_pool.as_ref()).await.unwrap();
        slog::info!(root_log, "Migrations complete, exiting haulage.");

        return;
    }

    // Get a set of available migrations and a set of applied migrations
    let available_migrations: HashSet<_> = migrator.iter().map(|x| x.version).collect();
    let applied_migrations: HashSet<_> = db_pool
        .as_ref()
        .acquire()
        .await
        .expect("Unable to acquire DB connection")
        .list_applied_migrations()
        .await
        .expect("Unable to query the applied DB schema migrations")
        .iter()
        .map(|x| x.version)
        .collect();

    if available_migrations != applied_migrations {
        slog::error!(
            root_log,
            "There is a difference between the expected set of DB schema migrations for this version of haulage \
            and the migrations applied to the configured database."
        );
        let unapplied_migrations: HashSet<_> = available_migrations
            .difference(&applied_migrations)
            .collect();
        let extra_migrations: HashSet<_> = applied_migrations
            .difference(&available_migrations)
            .collect();

        if unapplied_migrations.len() != 0 {
            slog::error!(
                root_log,
                "The following migrations are expected by this version of haulage, but not applied to the local database";
                "unapplied_migrations" => format!("{:?}", unapplied_migrations)
            );
            if extra_migrations.len() == 0 {
                slog::error!(
                    root_log,
                    "You can upgrade your database schema to be compatible with this version of haulage by manually running `haulage --db-upgrade`"
                );
                slog::error!(
                    root_log,
                    "***BE SURE TO BACK UP YOUR DATABASE BEFORE UPGRADING*** The upgrade operation cannot be easily undone."
                );
            }
        }

        if extra_migrations.len() != 0 {
            slog::error!(
                root_log,
                "The following migrations are present in your database but unknown to this version of haulage!\n\
                This cannot be fixed automatically, and you may need to re-create your database from scratch :/";
                "extra_migrations" => format!("{:?}", extra_migrations)
            );
        }
        panic!("Cannot proceed without correcting the database schema.");
    }

    // Create the main user aggregation, accounting, and enforcement subsystems.
    let user_enforcer = enforcer::Iptables::new(
        config.reenable_poll_interval,
        std::sync::Arc::clone(&db_pool),
        root_log.new(o!("subsystem" => "user_enforcer")),
    );
    let user_enforcer = std::sync::Arc::new(user_enforcer);

    let user_aggregator = async_aggregator::AsyncAggregator::new::<UserReporter>(
        config.user_log_interval,
        db_pool.clone(),
        root_log.new(o!("aggregator" => "user")),
    );

    let user_accounter = accounter::UserAccounter::new(
        config.user_log_interval,
        db_pool.clone(),
        std::sync::Arc::clone(&user_enforcer),
        root_log.new(o!("accounter" => "user")),
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
                let enforcer_channel = user_accounter.clone_input_channel();
                let config = config.clone();

                let packet_kind = match interface.mac {
                    Some(_) => PacketKind::Ethernet(packet_data_copy),
                    None => {
                        // TODO Distinguish between IPv4 and IPv6... maybe by checking the checksums?
                        PacketKind::IPv4(packet_data_copy)
                    }
                };

                tokio::task::spawn(async move {
                    handle_packet(packet_kind, channel, enforcer_channel, config, packet_log).await;
                });
            }
            Err(e) => {
                slog::error!(interface_log, "packetdump unable to receive packet: {}", e);
            }
        }
    }
}

async fn handle_packet<'a>(
    packet: PacketKind,
    user_agg_channel: tokio::sync::mpsc::Sender<async_aggregator::Message>,
    user_enforcer_channel: tokio::sync::mpsc::Sender<accounter::Message>,
    config: std::sync::Arc<config::Internal>,
    log: Logger,
) -> () {
    let parsed_packet = match packet {
        PacketKind::Ethernet(packet_bytes) => packet_parser::parse_ethernet(&packet_bytes, &log),
        PacketKind::IPv4(packet_bytes) => packet_parser::parse_ipv4(&packet_bytes, &log),
        PacketKind::IPv6(packet_bytes) => packet_parser::parse_ipv6(&packet_bytes, &log),
    };

    match parsed_packet {
        Ok(packet_info) => {
            slog::debug!(log, "Received packet info {:?}", packet_info);
            let normalized_flow = normalize_address(
                &packet_info.fivetuple,
                packet_info.ip_payload_length as u64,
                &config.user_subnet,
                &config.ignored_user_addresses,
            );
            slog::debug!(log, "Normalized to {:?}", normalized_flow);

            match normalized_flow {
                NormalizedFlow::UserRemote(flow) => {
                    user_agg_channel
                        .send(async_aggregator::Message::Report {
                            id: flow.user_addr,
                            amount: NetResourceBundle {
                                ran_bytes_down: flow.bytes_down as i64,
                                ran_bytes_up: flow.bytes_up as i64,
                                wan_bytes_down: flow.bytes_down as i64,
                                wan_bytes_up: flow.bytes_up as i64,
                            }
                        })
                        .await
                        .unwrap_or_else(
                            |e| slog::error!(log, "Failed to send to dispatcher"; "error" => e.to_string()),
                        );
                    user_enforcer_channel
                        .send(accounter::Message::Report {
                            ip: flow.user_addr,
                            amount: flow.bytes_down + flow.bytes_up,
                        })
                        .await
                        .unwrap_or_else(
                            |e| slog::error!(log, "Failed to send to dispatcher"; "error" => e.to_string()),
                        );
                }
                NormalizedFlow::UserUser(flow) => {
                    user_agg_channel
                        .send(async_aggregator::Message::Report {
                            id: flow.a_addr,
                            amount: NetResourceBundle {
                                ran_bytes_down: flow.bytes_b_to_a as i64,
                                ran_bytes_up: flow.bytes_a_to_b as i64,
                                wan_bytes_down: 0,
                                wan_bytes_up: 0,
                            }
                        })
                        .await
                        .unwrap_or_else(
                            |e| slog::error!(log, "Failed to send to dispatcher"; "error" => e.to_string()),
                        );
                    user_agg_channel
                        .send(async_aggregator::Message::Report {
                            id: flow.b_addr,
                            amount: NetResourceBundle {
                                ran_bytes_down: flow.bytes_a_to_b as i64,
                                ran_bytes_up: flow.bytes_b_to_a as i64,
                                wan_bytes_down: 0,
                                wan_bytes_up: 0,
                            }
                        })
                        .await
                        .unwrap_or_else(
                            |e| slog::error!(log, "Failed to send to dispatcher"; "error" => e.to_string()),
                        );
                }
                NormalizedFlow::Other(fivetuple, bytes) => {
                    slog::info!(log, "Recevied unnormalizable flow"; "flow" => std::format!("{:?}", fivetuple), "size" => bytes);
                }
            }
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

#[derive(Debug)]
pub enum NormalizedFlow {
    UserRemote(UserRemote),
    UserUser(UserUser),
    Other(packet_parser::FiveTuple, u64),
}

#[derive(Debug)]
pub struct UserRemote {
    pub user_addr: std::net::IpAddr,
    pub remote_addr: std::net::IpAddr,
    pub user_port: u16,
    pub remote_port: u16,
    pub protocol: u8,
    pub bytes_up: u64,
    pub bytes_down: u64,
}

#[derive(Debug)]
pub struct UserUser {
    pub a_addr: std::net::IpAddr,
    pub b_addr: std::net::IpAddr,
    pub a_port: u16,
    pub b_port: u16,
    pub protocol: u8,
    pub bytes_a_to_b: u64,
    pub bytes_b_to_a: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NetResourceBundle {
    pub ran_bytes_up: i64,
    pub ran_bytes_down: i64,
    pub wan_bytes_up: i64,
    pub wan_bytes_down: i64,
}
impl std::ops::Add for NetResourceBundle {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        NetResourceBundle {
            ran_bytes_up: self.ran_bytes_up + other.ran_bytes_up,
            ran_bytes_down: self.ran_bytes_down + other.ran_bytes_down,
            wan_bytes_up: self.wan_bytes_up + other.wan_bytes_up,
            wan_bytes_down: self.wan_bytes_down + other.wan_bytes_down,
        }
    }
}
impl std::ops::AddAssign for NetResourceBundle {
    fn add_assign(&mut self, rhs: Self) {
        self.ran_bytes_up = self.ran_bytes_up + rhs.ran_bytes_up;
        self.ran_bytes_down = self.ran_bytes_down + rhs.ran_bytes_down;
        self.wan_bytes_up = self.wan_bytes_up + rhs.wan_bytes_up;
        self.wan_bytes_down = self.wan_bytes_down + rhs.wan_bytes_down;
    }
}
impl NetResourceBundle {
    fn zeroed() -> Self {
        NetResourceBundle {
            ran_bytes_up: 0,
            ran_bytes_down: 0,
            wan_bytes_up: 0,
            wan_bytes_down: 0,
        }
    }
}

fn normalize_address(
    flow_fivetuple: &packet_parser::FiveTuple,
    bytes: u64,
    user_subnet: &ipnetwork::IpNetwork,
    non_user_addrs: &HashSet<std::net::IpAddr>,
) -> NormalizedFlow {
    let mut src_is_user = false;
    let mut dst_is_user = false;

    if user_subnet.contains(flow_fivetuple.src) && !non_user_addrs.contains(&flow_fivetuple.src) {
        src_is_user = true;
    }
    if user_subnet.contains(flow_fivetuple.dst) && !non_user_addrs.contains(&flow_fivetuple.dst) {
        dst_is_user = true;
    }

    if src_is_user && !dst_is_user {
        return NormalizedFlow::UserRemote(UserRemote {
            user_addr: flow_fivetuple.src,
            remote_addr: flow_fivetuple.dst,
            user_port: flow_fivetuple.src_port,
            remote_port: flow_fivetuple.dst_port,
            protocol: flow_fivetuple.protocol,
            bytes_up: bytes,
            bytes_down: 0,
        });
    } else if !src_is_user && dst_is_user {
        return NormalizedFlow::UserRemote(UserRemote {
            user_addr: flow_fivetuple.dst,
            remote_addr: flow_fivetuple.src,
            user_port: flow_fivetuple.dst_port,
            remote_port: flow_fivetuple.src_port,
            protocol: flow_fivetuple.protocol,
            bytes_up: 0,
            bytes_down: bytes,
        });
    } else if src_is_user && dst_is_user {
        // Normalize all user-user flows to assign endpoint a to the lower IP address.
        if flow_fivetuple.src < flow_fivetuple.dst {
            return NormalizedFlow::UserUser(UserUser {
                a_addr: flow_fivetuple.src,
                b_addr: flow_fivetuple.dst,
                a_port: flow_fivetuple.src_port,
                b_port: flow_fivetuple.dst_port,
                protocol: flow_fivetuple.protocol,
                bytes_a_to_b: bytes,
                bytes_b_to_a: 0,
            });
        } else {
            return NormalizedFlow::UserUser(UserUser {
                a_addr: flow_fivetuple.dst,
                b_addr: flow_fivetuple.src,
                a_port: flow_fivetuple.dst_port,
                b_port: flow_fivetuple.src_port,
                protocol: flow_fivetuple.protocol,
                bytes_a_to_b: 0,
                bytes_b_to_a: bytes,
            });
        }
    } else {
        return NormalizedFlow::Other(flow_fivetuple.clone(), bytes);
    }
}

enum PacketKind {
    Ethernet(bytes::Bytes),
    IPv4(bytes::Bytes),
    IPv6(bytes::Bytes),
}
