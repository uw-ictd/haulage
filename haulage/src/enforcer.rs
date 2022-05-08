use serde::Deserialize;
use std::collections::HashMap;
use thiserror::Error;

pub use i32 as UserId;

#[derive(Error, Debug)]
pub enum EnforcementError {
    #[error("Database operation failed: {0}")]
    DatabaseError(#[from] sqlx::error::Error),
    #[error("User ID is not uniquely present")]
    UserIdError,
    #[error("Failed to update iptables: {0}")]
    IptablesError(#[from] std::io::Error),
    #[error("Lost communication with policy enforcer")]
    CommunicationError,
    #[error("Unknown Rate Limit policy id {0}")]
    RateLimitPolicyError(i32),
    #[error("Rate limit policy parameter error {0}")]
    RateLimitParameterError(String),
    #[error("The tc queuing discipline management function returned an error")]
    TcCommandError,
    #[error("Failed to parse json: {0}")]
    SerdeJsonError(#[from] serde_json::Error),
}

#[derive(Debug)]
pub struct Iptables {
    dispatch_channel: tokio::sync::mpsc::Sender<PolicyUpdateMessage>,
    log: slog::Logger,
}
impl Iptables {
    pub fn new(
        poll_period: std::time::Duration,
        subscriber_interface: &str,
        upstream_interface: &Option<String>,
        db_pool: std::sync::Arc<sqlx::PgPool>,
        log: slog::Logger,
    ) -> Iptables {
        let (sender, receiver) = tokio::sync::mpsc::channel(64);
        let local_logger = log.clone();
        let subscriber_interface = subscriber_interface.to_owned();
        let upstream_interface = upstream_interface.to_owned();
        tokio::task::spawn(async move {
            enforce_via_iptables(
                receiver,
                poll_period,
                subscriber_interface,
                upstream_interface,
                db_pool,
                log,
            )
            .await;
        });
        Iptables {
            dispatch_channel: sender,
            log: local_logger,
        }
    }
    pub async fn update_policy(
        &self,
        target: UserId,
        new_policy: SubscriberCondition,
    ) -> Result<(), EnforcementError> {
        let (result_channel_tx, result_channel_rx) =
            tokio::sync::oneshot::channel::<Result<(), EnforcementError>>();
        self.dispatch_channel
            .send(PolicyUpdateMessage {
                new_state: new_policy,
                target: target,
                out_channel: result_channel_tx,
            })
            .await
            .or(Err(EnforcementError::CommunicationError))?;
        return result_channel_rx.await.unwrap_or_else(|e| {
            slog::error!(self.log, "Failed to receive enforcement worker result"; "error" => e.to_string());
            Err(EnforcementError::CommunicationError)
        });
    }
}

pub enum SubscriberCondition {
    HasBalance,
    NoBalance,
}

struct PolicyUpdateMessage {
    new_state: SubscriberCondition,
    target: UserId,
    out_channel: tokio::sync::oneshot::Sender<Result<(), EnforcementError>>,
}

async fn enforce_via_iptables(
    mut chan: tokio::sync::mpsc::Receiver<PolicyUpdateMessage>,
    period: std::time::Duration,
    subscriber_interface: String,
    upstream_interface: Option<String>,
    db_pool: std::sync::Arc<sqlx::PgPool>,
    log: slog::Logger,
) -> () {
    // Issue handle ids to subscribers on a first-come first-serve basis. In
    // this initial low-scale implementation don't try to reclaim IDs while
    // operating.
    let mut next_handle_id = 1;
    let mut subscriber_limit_control_state = HashMap::<i32, SubscriberControlState>::new();

    // On startup synchronize the state in the database with the local iptables
    // rules. This is not very robust, and would be better integrated with
    // actual netfilter tables for efficiency and better control of the actual
    // state of the rules present when other firewalls my also be active.
    let current_db_state = query_all_subscriber_bridge_state(&db_pool, &log)
        .await
        .expect("Unable to get initial desired iptables state!");

    for sub in current_db_state {
        let sub_handle = format!("{:03X}", next_handle_id);
        next_handle_id += 1;
        subscriber_limit_control_state.insert(
            sub.subscriber_id,
            SubscriberControlState {
                qdisc_handle: sub_handle,
                ip: sub.ip,
            },
        );
        if sub.bridged {
            delete_forwarding_reject_rule(&sub.ip.ip(), &log)
                .await
                .unwrap();
        } else {
            set_forwarding_reject_rule(&sub.ip.ip(), &log)
                .await
                .unwrap();
        }
    }

    // Clear any existing queuing disciplines on startup.
    clear_interface_limit(&subscriber_interface, &log)
        .await
        .unwrap();

    // Setup the root QFQ qdisc
    setup_root_qdisc(&subscriber_interface, &log).await.unwrap();

    if upstream_interface.is_some() {
        setup_root_qdisc(upstream_interface.as_ref().unwrap(), &log)
            .await
            .unwrap();
        setup_fallback_class(upstream_interface.as_ref().unwrap(), &log)
            .await
            .unwrap();
    }

    let current_db_state = query_all_subscriber_ratelimit_state(&db_pool, &log)
        .await
        .expect("Unable to get initial ratelimit state");
    for sub in current_db_state {
        // TODO Match subscriber to control state
        let sub_limit_state = subscriber_limit_control_state.get(&sub.subscriber_id);
        let sub_limit_state = match sub_limit_state {
            Some(state) => state,
            None => {
                let sub_handle = format!("{:03X}", next_handle_id);
                next_handle_id += 1;
                subscriber_limit_control_state.insert(
                    sub.subscriber_id,
                    SubscriberControlState {
                        qdisc_handle: sub_handle,
                        ip: sub.ip,
                    },
                );
                subscriber_limit_control_state
                    .get(&sub.subscriber_id)
                    .expect("Unable to retrieve key just inserted")
            }
        };

        // Setup subscriber qfq class
        setup_subscriber_class(&subscriber_interface, &sub_limit_state.qdisc_handle, &log)
            .await
            .unwrap();

        add_subscriber_dst_filter(&subscriber_interface, &sub_limit_state, &log)
            .await
            .unwrap();

        if upstream_interface.is_some() {
            // Setup subscriber qfq class
            setup_subscriber_class(
                upstream_interface.as_ref().unwrap(),
                &sub_limit_state.qdisc_handle,
                &log,
            )
            .await
            .unwrap();

            add_subscriber_src_filter(upstream_interface.as_ref().unwrap(), &sub_limit_state, &log)
                .await
                .unwrap();
        }

        match sub.backhaul_ul_policy {
            RateLimitPolicy::Unlimited => {
                match &upstream_interface {
                    None => {
                        slog::warn!(
                            log,
                            "No 'upstreamInterface' configured, not modifying queues for unlimited rate limit policy!"
                        );
                    }
                    Some(upstream_if) => {
                        clear_user_limit(upstream_if, &sub_limit_state.qdisc_handle, &log)
                            .await
                            .unwrap();
                    }
                };
            }
            RateLimitPolicy::TokenBucket(params) => {
                match &upstream_interface {
                    None => {
                        slog::error!(
                            log,
                            "Cannot set uplink TokenBucket rate limit policy without 'upstreamInterface' config!"
                        );
                    }
                    Some(upstream_if) => {
                        set_user_token_bucket(
                            upstream_if,
                            &sub_limit_state.qdisc_handle,
                            params,
                            &log,
                        )
                        .await
                        .unwrap();
                    }
                };
            }
        }

        match sub.backhaul_dl_policy {
            RateLimitPolicy::Unlimited => {
                clear_user_limit(&subscriber_interface, &sub_limit_state.qdisc_handle, &log)
                    .await
                    .unwrap();
            }
            RateLimitPolicy::TokenBucket(params) => {
                set_user_token_bucket(
                    &subscriber_interface,
                    &sub_limit_state.qdisc_handle,
                    params,
                    &log,
                )
                .await
                .unwrap();
            }
        }
    }

    let mut timer = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
    loop {
        tokio::select! {
            _ = timer.tick() => {
                let reenabled_subs = query_reenabled_subscriber_bridge_state(&db_pool, &log)
                    .await
                    .unwrap_or_else(|e| {
                        slog::error!(log, "Unable to query for reenabled subscribers"; "error" => e.to_string());
                        Vec::<SubscriberBridgeInfo>::new()
                    });
                for sub in reenabled_subs {
                    //TODO(matt9j) Check policy type
                    set_policy(sub.subscriber_id, SubscriberCondition::HasBalance, &db_pool, &log)
                        .await
                        .unwrap_or_else(|e| {
                            slog::error!(log, "Unable to reenable subscriber"; "id" => sub.subscriber_id, "error" => e.to_string())
                        });
                }
            }
            message = chan.recv() => {
                if message.is_none() {
                    break;
                }
                let message = message.unwrap();

                let result = set_policy(message.target, message.new_state, &db_pool, &log).await;
                message.out_channel.send(result).unwrap();
            }
        }
    }
}

//TODO async fn apply_subscriber_policy(upstream_iface: Option<String>, downstream_iface: Option<String>, )

async fn forwarding_reject_rule_present(addr: &std::net::IpAddr) -> Result<bool, std::io::Error> {
    // IPTables holds state outside the lifetime of this program. The `-C`
    // option will return success if the rule is present, and 1 if it is not.
    let status = tokio::process::Command::new("iptables")
        .args(&["-C", "FORWARD", "-s", &addr.to_string(), "-j", "REJECT"])
        .status()
        .await?;
    if status.success() {
        return Ok(true);
    }
    return Ok(false);
}

async fn set_policy(
    target: UserId,
    policy: SubscriberCondition,
    db_pool: &sqlx::PgPool,
    log: &slog::Logger,
) -> Result<(), EnforcementError> {
    match policy {
        SubscriberCondition::HasBalance => set_unlimited_policy(&db_pool, target, &log).await,
        SubscriberCondition::NoBalance => set_local_only_policy(&db_pool, target, &log).await,
    }
}

async fn set_unlimited_policy(
    db_pool: &sqlx::PgPool,
    target: UserId,
    log: &slog::Logger,
) -> Result<(), EnforcementError> {
    let bridge_state = update_bridged(&db_pool, target, true, log).await?;
    delete_forwarding_reject_rule(&bridge_state.ip.ip(), log).await
}

async fn set_local_only_policy(
    db_pool: &sqlx::PgPool,
    target: UserId,
    log: &slog::Logger,
) -> Result<(), EnforcementError> {
    let bridge_state = update_bridged(&db_pool, target, false, log).await?;
    set_forwarding_reject_rule(&bridge_state.ip.ip(), log).await
}

async fn delete_forwarding_reject_rule(
    ip: &std::net::IpAddr,
    log: &slog::Logger,
) -> Result<(), EnforcementError> {
    let command_status = tokio::process::Command::new("iptables")
        .args(&["-D", "FORWARD", "-s", &ip.to_string(), "-j", "REJECT"])
        .status()
        .await?;

    if !command_status.success() {
        slog::warn!(log, "iptables delete forward reject rule failed"; "ip" => ip.to_string());
    }

    Ok(())
}

async fn set_forwarding_reject_rule(
    ip: &std::net::IpAddr,
    log: &slog::Logger,
) -> Result<(), EnforcementError> {
    // Do not double insert, as this will require delete to run multiple times
    // and break the delete implementation
    if forwarding_reject_rule_present(ip).await? {
        slog::info!(log, "Forwarding filter already present"; "ip" => ip.to_string());
        return Ok(());
    }

    let command_status = tokio::process::Command::new("iptables")
        .args(&["-I", "FORWARD", "-s", &ip.to_string(), "-j", "REJECT"])
        .status()
        .await?;

    if !command_status.success() {
        slog::warn!(log, "iptables insert failed"; "ip" => ip.to_string());
    }

    Ok(())
}

// A hacky fixup to remove the malformed options element from the token bucket
// filter json output. This implementation assumes the input is ASCII, and that
// the options element is never the first key in a givem object.
fn delete_malformed_options_element(input: &str) -> String {
    let mut output = String::new();
    let mut i = input.find(r#","options":"#).unwrap_or(input.len());
    let mut copy_begin_index: usize = 0;
    while i < input.len() {
        output.push_str(&input[copy_begin_index..i]);

        // Find the matching close bracket by scanning the index without copying
        let mut curly_count = 0;
        while i < input.len() {
            if input.as_bytes()[i] as char == '{' {
                curly_count += 1;
            }
            if input.as_bytes()[i] as char == '}' {
                curly_count -= 1;
                if curly_count == 0 {
                    i += 1;
                    break;
                }
            }
            i += 1;
        }

        if i >= input.len() {
            break;
        }
        copy_begin_index = i;
        i = input[copy_begin_index..]
            .find(r#","options":"#)
            .unwrap_or(input[copy_begin_index..].len())
            + copy_begin_index;
    }
    // Handle any leftovers if needed
    output.push_str(&input[copy_begin_index..i]);

    output
}

async fn clear_interface_limit(iface: &str, log: &slog::Logger) -> Result<(), EnforcementError> {
    slog::debug!(log, "clearing interface config"; "interface" => iface);
    let current_iface_status = tokio::process::Command::new("tc")
        .args(&["-j", "qdisc", "show", "dev", iface])
        .output()
        .await?;

    // Delete the options "key", which in debian Buster and earlier is not valid
    // JSON!
    // https://lkml.kernel.org/netdev/278df9b9-e2f6-fe8a-e7d6-432b29a39697@gmail.com/T/
    let current_iface_status = delete_malformed_options_element(
        std::str::from_utf8(&current_iface_status.stdout).unwrap(),
    );
    let current_iface_qdiscs: Vec<QDiscInfo> = serde_json::from_str(&current_iface_status)?;
    if current_iface_qdiscs.len() == 1 {
        if current_iface_qdiscs.first().unwrap().handle == "0:" {
            slog::info!(log, "only default qdisc present, nothing to clear"; "interface" => iface);
            return Ok(());
        }
    }

    slog::warn!(log, "clearing non-trivial qdisc config");

    let clear_output = tokio::process::Command::new("tc")
        .args(&["qdisc", "del", "dev", iface, "parent", "root"])
        .output()
        .await?;

    if !clear_output.status.success() {
        slog::error!(log, "tc command to clear interface failed";
            "stdout" => String::from_utf8(clear_output.stdout).unwrap_or("[Failed to parse output]".to_owned()),
            "stderr" => String::from_utf8(clear_output.stderr).unwrap_or("[Failed to parse output]".to_owned())
        );
        return Err(EnforcementError::TcCommandError);
    }

    Ok(())
}

async fn setup_root_qdisc(iface: &str, log: &slog::Logger) -> Result<(), EnforcementError> {
    slog::debug!(log, "Setting up root qdisc"; "interface" => iface);

    let add_status = tokio::process::Command::new("tc")
        .args(&[
            "qdisc", "replace", "dev", iface, "parent", "root", "handle", "1:", "qfq",
        ])
        .status()
        .await?;

    if !add_status.success() {
        slog::warn!(log, "qdisc replace root with qfq failed");
    }

    Ok(())
}

async fn setup_subscriber_class(
    iface: &str,
    sub_handle_fragment: &str,
    log: &slog::Logger,
) -> Result<(), EnforcementError> {
    slog::debug!(log, "adding subscriber class to base qdisc"; "interface" => iface, "sub" => sub_handle_fragment);

    let add_status = tokio::process::Command::new("tc")
        .args(&[
            "class",
            "replace",
            "dev",
            iface,
            "parent",
            "1:",
            "classid",
            &format!("1:{}", sub_handle_fragment).as_str(),
            "qfq",
            "weight",
            "10",
        ])
        .status()
        .await?;

    if !add_status.success() {
        slog::warn!(log, "qfq add subscriber class failed");
    }

    let add_status = tokio::process::Command::new("tc")
        .args(&[
            "qdisc",
            "replace",
            "dev",
            iface,
            "parent",
            &format!("1:{}", sub_handle_fragment).as_str(),
            "handle",
            &format!("A{}:", sub_handle_fragment).as_str(),
            "pfifo",
        ])
        .status()
        .await?;

    if !add_status.success() {
        slog::warn!(log, "qdisc add temporary user qdisc failed");
    }

    Ok(())
}

async fn setup_fallback_class(iface: &str, log: &slog::Logger) -> Result<(), EnforcementError> {
    slog::debug!(log, "adding fallback class to base qdisc"; "interface" => iface);

    let add_status = tokio::process::Command::new("tc")
        .args(&[
            "class", "replace", "dev", iface, "parent", "1:", "classid", "1:0xFFFF", "qfq",
            "weight", "10",
        ])
        .status()
        .await?;

    if !add_status.success() {
        slog::warn!(log, "qfq add default class failed");
    }

    slog::debug!(log, "adding catchall_filter"; "interface" => iface);

    let add_status = tokio::process::Command::new("tc")
        .args(&[
            "filter", "replace", "dev", iface, "parent", "1:", "protocol", "ip", "prio", "2",
            "u32", "match", "u32", "0", "0", "flowid", "1:0xFFFF",
        ])
        .status()
        .await?;

    if !add_status.success() {
        slog::warn!(log, "add catchall filter failed");
    }

    slog::debug!(log, "adding catchall_qdisc"; "interface" => iface);
    let add_status = tokio::process::Command::new("tc")
        .args(&[
            "qdisc", "replace", "dev", iface, "parent", "1:0xFFFF", "handle", "0x1FFF", "fq_codel",
        ])
        .status()
        .await?;

    if !add_status.success() {
        slog::warn!(log, "add catchall qdisc failed");
    }

    Ok(())
}

async fn clear_user_limit(
    iface: &str,
    sub_handle: &str,
    log: &slog::Logger,
) -> Result<(), EnforcementError> {
    slog::debug!(log, "clearing limit"; "interface" => iface, "sub_handle" => sub_handle);

    let del_status = tokio::process::Command::new("tc")
        .args(&[
            "qdisc",
            "del",
            "dev",
            iface,
            "parent",
            &format!("1:{}", sub_handle).as_str(),
        ])
        .status()
        .await?;
    if !del_status.success() {
        slog::warn!(log, "qdisc delete existing user qdisc failed");
    }

    let add_status = tokio::process::Command::new("tc")
        .args(&[
            "qdisc",
            "add",
            "dev",
            iface,
            "parent",
            &format!("1:{}", sub_handle).as_str(),
            "handle",
            &format!("A{}:", sub_handle).as_str(),
            "sfq",
            "perturb",
            "30",
            "headdrop",
            "probability",
            "0.5",
            "redflowlimit",
            "20000",
            "ecn",
            "harddrop",
        ])
        .status()
        .await?;

    if !add_status.success() {
        slog::warn!(log, "qdisc add basic sfq failed");
    }

    Ok(())
}

async fn set_user_token_bucket(
    iface: &str,
    sub_handle: &str,
    params: TokenBucketParameters,
    log: &slog::Logger,
) -> Result<(), EnforcementError> {
    slog::debug!(log, "setting token bucket limit"; "interface" => iface, "sub_handle" => sub_handle);

    let del_status = tokio::process::Command::new("tc")
        .args(&[
            "qdisc",
            "del",
            "dev",
            iface,
            "parent",
            &format!("1:{}", sub_handle).as_str(),
        ])
        .status()
        .await?;
    if !del_status.success() {
        slog::warn!(log, "qdisc delete existing user qdisc failed");
    }

    // For now set common-sense defaults within haulage. Derive the burst size
    // from the rate. Set a max latency of 20ms, although it should not matter
    // since we are overriding the internal TBF queue with SFQ. Set the max
    // burst to 20ms worth of data, or at least 2kB

    let burst_size_kbit = std::cmp::max(16, ((params.rate_kibps as f64) / 50.0) as u32);

    let add_status = tokio::process::Command::new("tc")
        .args(&[
            "qdisc",
            "add",
            "dev",
            iface,
            "parent",
            &format!("1:{}", sub_handle).as_str(),
            "handle",
            &format!("2{}:", sub_handle).as_str(),
            "tbf",
            "rate",
            &format!("{}kbit", params.rate_kibps).as_str(),
            "burst",
            &format!("{}kbit", burst_size_kbit).as_str(),
            "latency",
            "20ms",
        ])
        .status()
        .await?;

    if !add_status.success() {
        slog::warn!(log, "qdisc add with first level tbf failed");
    }

    let add_status = tokio::process::Command::new("tc")
        .args(&[
            "qdisc",
            "add",
            "dev",
            iface,
            "parent",
            &format!("2{}:", sub_handle).as_str(),
            "handle",
            &format!("A{}:", sub_handle).as_str(),
            "sfq",
            "perturb",
            "30",
            "headdrop",
            "probability",
            "0.5",
            "redflowlimit",
            "20000",
            "ecn",
            "harddrop",
        ])
        .status()
        .await?;

    if !add_status.success() {
        slog::warn!(log, "qdisc add second level sfq failed");
    }

    Ok(())
}

async fn add_subscriber_dst_filter(
    iface: &str,
    sub: &SubscriberControlState,
    log: &slog::Logger,
) -> Result<(), EnforcementError> {
    // TODO(matt9j) Only supports IPv4, should support v4 and v6!
    slog::debug!(log, "adding sub dst_filter"; "interface" => iface, "sub_handle" => &sub.qdisc_handle);

    let add_status = tokio::process::Command::new("tc")
        .args(&[
            "filter",
            "replace",
            "dev",
            iface,
            "parent",
            "1:",
            "protocol",
            "ip",
            "prio",
            "1",
            "u32",
            "match",
            "ip",
            "dst",
            &sub.ip.to_string(),
            "flowid",
            &format!("1:{}", &sub.qdisc_handle).as_str(),
        ])
        .status()
        .await?;

    if !add_status.success() {
        slog::warn!(log, "add subscriber dst filter failed");
    }

    Ok(())
}

// TODO(matt9j) heavily duplicated with add_subscriber_dst_filter
async fn add_subscriber_src_filter(
    iface: &str,
    sub: &SubscriberControlState,
    log: &slog::Logger,
) -> Result<(), EnforcementError> {
    // TODO(matt9j) Only supports IPv4, should support v4 and v6!
    slog::debug!(log, "adding sub src filter"; "interface" => iface, "sub_handle" => &sub.qdisc_handle);

    let add_status = tokio::process::Command::new("tc")
        .args(&[
            "filter",
            "replace",
            "dev",
            iface,
            "parent",
            "1:",
            "protocol",
            "ip",
            "prio",
            "1",
            "u32",
            "match",
            "ip",
            "src",
            &sub.ip.to_string(),
            "flowid",
            &format!("1:{}", &sub.qdisc_handle).as_str(),
        ])
        .status()
        .await?;

    if !add_status.success() {
        slog::warn!(log, "add subscriber src filter failed");
    }

    Ok(())
}

async fn update_bridged(
    db_pool: &sqlx::PgPool,
    id: UserId,
    new_bridge_state: bool,
    log: &slog::Logger,
) -> Result<SubscriberBridgeInfo, EnforcementError> {
    let mut transaction = db_pool.begin().await?;
    slog::debug!(log, "updating bridge state in DB"; "id" => id);

    let subscriber_update_query = r#"
        UPDATE subscribers
        SET "bridged" = $1
        FROM static_ips
        WHERE static_ips.imsi = subscribers.imsi AND "internal_uid" = $2
        RETURNING "ip", "internal_uid" AS "subscriber_id", "bridged";
    "#;

    let rows: Vec<SubscriberBridgeInfo> = sqlx::query_as(subscriber_update_query)
        .bind(new_bridge_state)
        .bind(id)
        .fetch_all(&mut transaction)
        .await?;

    // Ensure the user is unique
    if rows.len() != 1 {
        return Err(EnforcementError::UserIdError);
    }
    let user_state = rows.first().unwrap().clone();

    transaction.commit().await?;
    Ok(user_state)
}

async fn query_all_subscriber_ratelimit_state(
    db_pool: &sqlx::PgPool,
    log: &slog::Logger,
) -> Result<Vec<SubscriberRateLimitInfo>, EnforcementError> {
    slog::debug!(log, "querying global ratelimit db state");
    let mut transaction = db_pool.begin().await?;

    // Get the ratelimit state to apply for each condition of subscribers. Need
    // to return different columns based on the subscriber's account balance (or
    // possibly other conditions in the future).

    // Zero balance subscribers
    let ratelimit_state_query = r#"
        SELECT "internal_uid" AS "subscriber_id", "ip", "local_ul_policy_kind", "local_ul_policy_parameters", "local_dl_policy_kind", "local_dl_policy_parameters", "backhaul_ul_policy_kind", "backhaul_ul_policy_parameters", "backhaul_dl_policy_kind", "backhaul_dl_policy_parameters"
        FROM subscribers
        INNER JOIN static_ips ON subscribers.imsi = static_ips.imsi
        INNER JOIN access_policies ON subscribers.zero_balance_policy = access_policies.id
        WHERE (subscribers.data_balance = 0)
    "#;

    let zero_balance_rows: Vec<SubscriberRateLimitRow> = sqlx::query_as(ratelimit_state_query)
        .fetch_all(&mut transaction)
        .await?;

    // Positive balance subscribers
    let ratelimit_state_query = r#"
        SELECT "internal_uid" AS "subscriber_id", "ip", "local_ul_policy_kind", "local_ul_policy_parameters", "local_dl_policy_kind", "local_dl_policy_parameters", "backhaul_ul_policy_kind", "backhaul_ul_policy_parameters", "backhaul_dl_policy_kind", "backhaul_dl_policy_parameters"
        FROM subscribers
        INNER JOIN static_ips ON subscribers.imsi = static_ips.imsi
        INNER JOIN access_policies ON subscribers.positive_balance_policy = access_policies.id
        WHERE (subscribers.data_balance > 0)
    "#;

    let positive_balance_rows: Vec<SubscriberRateLimitRow> = sqlx::query_as(ratelimit_state_query)
        .fetch_all(&mut transaction)
        .await?;

    transaction.commit().await?;

    // Once rows are retreived, parse them into our internal representation.
    let mut parsed_ratelimits: Vec<SubscriberRateLimitInfo> = Vec::new();
    parsed_ratelimits.reserve_exact(zero_balance_rows.len() + positive_balance_rows.len());
    for row in zero_balance_rows.iter() {
        parsed_ratelimits.push(row.try_into()?)
    }
    for row in positive_balance_rows.iter() {
        parsed_ratelimits.push(row.try_into()?)
    }

    Ok(parsed_ratelimits)
}

async fn query_all_subscriber_bridge_state(
    db_pool: &sqlx::PgPool,
    log: &slog::Logger,
) -> Result<Vec<SubscriberBridgeInfo>, EnforcementError> {
    let mut transaction = db_pool.begin().await?;
    slog::debug!(log, "querying global bridged db state");

    let bridge_state_query = r#"
        SELECT "ip", "internal_uid" AS "subscriber_id", "bridged"
        FROM subscribers INNER JOIN static_ips ON subscribers.imsi = static_ips.imsi
    "#;

    let rows: Vec<SubscriberBridgeInfo> = sqlx::query_as(bridge_state_query)
        .fetch_all(&mut transaction)
        .await?;

    transaction.commit().await?;
    Ok(rows)
}

async fn query_reenabled_subscriber_bridge_state(
    db_pool: &sqlx::PgPool,
    log: &slog::Logger,
) -> Result<Vec<SubscriberBridgeInfo>, EnforcementError> {
    let mut transaction = db_pool.begin().await?;
    slog::debug!(log, "querying reenabled subscribers");

    let bridge_state_query = r#"
        SELECT "ip", "internal_uid" AS "subscriber_id", "bridged"
        FROM subscribers INNER JOIN static_ips ON subscribers.imsi = static_ips.imsi
        WHERE "data_balance" > 0 AND "bridged" = false
    "#;

    let rows: Vec<SubscriberBridgeInfo> = sqlx::query_as(bridge_state_query)
        .fetch_all(&mut transaction)
        .await?;

    transaction.commit().await?;
    Ok(rows)
}

#[derive(Debug)]
struct SubscriberControlState {
    qdisc_handle: String,
    ip: ipnetwork::IpNetwork,
}

#[derive(Debug, Deserialize)]
struct QDiscInfo {
    handle: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct SubscriberBridgeInfo {
    ip: ipnetwork::IpNetwork,
    subscriber_id: i32,
    bridged: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct LimitPolicyParameters {
    rate_kibps: Option<u32>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct SubscriberRateLimitRow {
    ip: ipnetwork::IpNetwork,
    subscriber_id: i32,
    local_ul_policy_kind: i32,
    local_ul_policy_parameters: sqlx::types::Json<LimitPolicyParameters>,
    local_dl_policy_kind: i32,
    local_dl_policy_parameters: sqlx::types::Json<LimitPolicyParameters>,
    backhaul_ul_policy_kind: i32,
    backhaul_ul_policy_parameters: sqlx::types::Json<LimitPolicyParameters>,
    backhaul_dl_policy_kind: i32,
    backhaul_dl_policy_parameters: sqlx::types::Json<LimitPolicyParameters>,
}

#[derive(Debug, Clone)]
struct TokenBucketParameters {
    rate_kibps: u32,
}

#[derive(Debug, Clone)]
enum RateLimitPolicy {
    Unlimited,
    TokenBucket(TokenBucketParameters),
}

#[derive(Debug, Clone)]
struct SubscriberRateLimitInfo {
    ip: ipnetwork::IpNetwork,
    subscriber_id: i32,
    local_ul_policy: RateLimitPolicy,
    local_dl_policy: RateLimitPolicy,
    backhaul_ul_policy: RateLimitPolicy,
    backhaul_dl_policy: RateLimitPolicy,
}

fn create_policy_from_parameters(
    policy_id: i32,
    parameters: &LimitPolicyParameters,
) -> Result<RateLimitPolicy, EnforcementError> {
    match policy_id {
        1 => Ok(RateLimitPolicy::Unlimited),
        2 => {
            let parsed_parameters = TokenBucketParameters {
                rate_kibps: parameters.rate_kibps.ok_or(
                    EnforcementError::RateLimitParameterError("Missing rate_kibps".to_owned()),
                )?,
            };
            Ok(RateLimitPolicy::TokenBucket(parsed_parameters))
        }
        _ => Err(EnforcementError::RateLimitPolicyError(policy_id)),
    }
}

impl TryFrom<&SubscriberRateLimitRow> for SubscriberRateLimitInfo {
    type Error = EnforcementError;

    fn try_from(row: &SubscriberRateLimitRow) -> Result<Self, Self::Error> {
        Ok(SubscriberRateLimitInfo {
            ip: row.ip,
            subscriber_id: row.subscriber_id,
            local_ul_policy: create_policy_from_parameters(
                row.local_ul_policy_kind,
                &row.local_ul_policy_parameters,
            )?,
            local_dl_policy: create_policy_from_parameters(
                row.local_dl_policy_kind,
                &row.local_dl_policy_parameters,
            )?,
            backhaul_ul_policy: create_policy_from_parameters(
                row.backhaul_ul_policy_kind,
                &row.backhaul_ul_policy_parameters,
            )?,
            backhaul_dl_policy: create_policy_from_parameters(
                row.backhaul_dl_policy_kind,
                &row.backhaul_dl_policy_parameters,
            )?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_options_parse() {
        let input = r#" [{"kind":"tbf","handle":"1:","root":true,"refcnt":2,"options":{rate 1Mbit burst 3840b lat 10.0ms }},{"kind":"qfq","handle":"2:","parent":"1:1","options":{}}]"#;
        let desired_output = r#" [{"kind":"tbf","handle":"1:","root":true,"refcnt":2},{"kind":"qfq","handle":"2:","parent":"1:1"}]"#;
        assert_eq!(delete_malformed_options_element(input), desired_output)
    }
}
