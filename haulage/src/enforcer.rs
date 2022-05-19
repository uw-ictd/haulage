use serde::Deserialize;
use std::collections::HashMap;
use thiserror::Error;

pub use i32 as UserId;
use i32 as PolicyId;

#[derive(Error, Debug)]
pub enum EnforcementError {
    #[error("Database operation failed: {0}")]
    DatabaseError(#[from] sqlx::error::Error),
    #[error("User ID is not uniquely present")]
    UserIdError,
    #[error("Failed to update iptables: {0}")]
    IptablesExecutionError(#[from] std::io::Error),
    #[error("Failed to update iptables: {0}")]
    IptablesLogicError(String),
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
    _PositiveBalance,
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
    // Track local ephemeral state per subscriber in an in-memory table
    //
    // Issue handle ids to subscribers on a first-come first-serve basis. In
    // this initial low-scale implementation don't try to reclaim IDs while
    // operating.
    let mut next_handle_id = 1;
    let mut subscriber_limit_control_state = HashMap::<i32, SubscriberControlState>::new();

    // Clear any existing queuing disciplines on startup.
    clear_interface_limit(&subscriber_interface, &log)
        .await
        .unwrap();

    // Setup the root qdisc
    setup_root_qdisc(&subscriber_interface, 0, &log)
        .await
        .unwrap();

    if upstream_interface.is_some() {
        // Clear any existing queuing disciplines on startup.
        clear_interface_limit(upstream_interface.as_ref().unwrap(), &log)
            .await
            .unwrap();
        setup_root_qdisc(upstream_interface.as_ref().unwrap(), 8, &log)
            .await
            .unwrap();
        setup_fallback_class(upstream_interface.as_ref().unwrap(), 8, &log)
            .await
            .unwrap();
    }

    // On startup synchronize the state in the database with the local iptables
    // rules and qdisc configuration. This is not very robust, and would be
    // better integrated with actual netfilter tables for efficiency and better
    // control of the actual state of the rules present when other firewalls may
    // also be active.
    let current_db_state = query_all_subscriber_access_state(&db_pool, &log)
        .await
        .expect("Unable to get initial access policy state");

    for sub in current_db_state {
        // Assign ephemeral state to each subscriber
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

        // Setup subscriber class
        setup_subscriber_class(
            &subscriber_interface,
            0,
            &sub_limit_state.qdisc_handle,
            &log,
        )
        .await
        .unwrap();

        add_subscriber_dst_filter(&subscriber_interface, 0, &sub_limit_state, &log)
            .await
            .unwrap();

        if upstream_interface.is_some() {
            // Setup subscriber class
            setup_subscriber_class(
                upstream_interface.as_ref().unwrap(),
                8,
                &sub_limit_state.qdisc_handle,
                &log,
            )
            .await
            .unwrap();

            add_subscriber_src_filter(
                upstream_interface.as_ref().unwrap(),
                8,
                &sub_limit_state,
                &log,
            )
            .await
            .unwrap();
        }

        set_policy(
            sub.subscriber_id,
            sub_limit_state,
            &sub,
            &upstream_interface,
            &subscriber_interface,
            &db_pool,
            &log,
        )
        .await
        .expect("Unable to set initial subscriber policy");
    }

    let mut timer = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
    loop {
        tokio::select! {
            _ = timer.tick() => {
                let reenabled_subs = query_modified_subscriber_access_state(&db_pool, &log)
                    .await
                    .unwrap_or_else(|e| {
                        slog::error!(log, "Unable to query for reenabled subscribers"; "error" => e.to_string());
                        Vec::<SubscriberAccessInfo>::new()
                    });
                for sub in reenabled_subs {
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

                    set_policy(sub.subscriber_id, sub_limit_state, &sub, &upstream_interface, &subscriber_interface, &db_pool, &log)
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

                let sub_limit_state = subscriber_limit_control_state.get(&message.target);
                let sub_limit_state = match sub_limit_state {
                    Some(state) => state,
                    None => {
                        let sub_handle = format!("{:03X}", next_handle_id);
                        next_handle_id += 1;
                        subscriber_limit_control_state.insert(
                            message.target,
                            SubscriberControlState {
                                qdisc_handle: sub_handle,
                                ip: query_subscriber_ip(message.target, &db_pool, &log).await.unwrap(),
                            },
                        );
                        subscriber_limit_control_state
                            .get(&message.target)
                            .expect("Unable to retrieve key just inserted")
                    }
                };

                let result = set_policy_for_condition(message.target, &sub_limit_state, message.new_state, &upstream_interface, &subscriber_interface, &db_pool, &log).await;
                message.out_channel.send(result).unwrap();
            }
        }
    }
}

async fn forwarding_reject_rule_present(addr: &std::net::IpAddr) -> Result<bool, std::io::Error> {
    // IPTables holds state outside the lifetime of this program. The `-C`
    // option will return success if the rule is present, and 1 if it is not.
    let output = tokio::process::Command::new("iptables")
        .args(&["-C", "FORWARD", "-s", &addr.to_string(), "-j", "REJECT"])
        .output()
        .await?;

    Ok(output.status.success())
}
async fn set_policy_for_condition(
    target: UserId,
    subscriber_state: &SubscriberControlState,
    condition: SubscriberCondition,
    upstream_interface: &Option<String>,
    subscriber_interface: &str,
    db_pool: &sqlx::PgPool,
    log: &slog::Logger,
) -> Result<(), EnforcementError> {
    let policy_to_apply = query_subscriber_access_policy(target, condition, db_pool, log).await?;

    set_policy(
        target,
        subscriber_state,
        &policy_to_apply,
        upstream_interface,
        subscriber_interface,
        db_pool,
        log,
    )
    .await
}

async fn set_policy(
    target: UserId,
    subscriber_state: &SubscriberControlState,
    policy: &SubscriberAccessInfo,
    upstream_interface: &Option<String>,
    subscriber_interface: &str,
    db_pool: &sqlx::PgPool,
    log: &slog::Logger,
) -> Result<(), EnforcementError> {
    // Apply policy across interfaces
    match &policy.backhaul_ul_policy {
        AccessPolicy::Unlimited => {
            match &upstream_interface {
                None => {
                    slog::warn!(
                        log,
                        "No 'upstreamInterface' configured, not modifying queues for unlimited rate limit policy!"
                    );
                }
                Some(upstream_if) => {
                    clear_user_limit(upstream_if, 8, &subscriber_state.qdisc_handle, &log).await?;
                }
            };
        }
        AccessPolicy::Block => {
            // Partially implemented-- currently no difference between
            // uplink and downlink block/allow policies, so set/unset
            // forwarding as part of the downlink policy only.
        }
        AccessPolicy::TokenBucket(params) => {
            match &upstream_interface {
                None => {
                    slog::error!(
                        log,
                        "Cannot set uplink TokenBucket rate limit policy without 'upstreamInterface' config!"
                    );
                    return Err(EnforcementError::RateLimitPolicyError(policy.policy_id));
                }
                Some(upstream_if) => {
                    set_user_token_bucket(
                        upstream_if,
                        8,
                        &subscriber_state.qdisc_handle,
                        params,
                        &log,
                    )
                    .await?;
                }
            };
        }
    }

    match &policy.backhaul_dl_policy {
        AccessPolicy::Unlimited => {
            delete_forwarding_reject_rule(&subscriber_state.ip.ip(), &log).await?;
            clear_user_limit(
                &subscriber_interface,
                0,
                &subscriber_state.qdisc_handle,
                &log,
            )
            .await?;
        }
        AccessPolicy::Block => {
            set_forwarding_reject_rule(&subscriber_state.ip.ip(), &log).await?;
        }
        AccessPolicy::TokenBucket(params) => {
            delete_forwarding_reject_rule(&subscriber_state.ip.ip(), &log).await?;
            set_user_token_bucket(
                &subscriber_interface,
                0,
                &subscriber_state.qdisc_handle,
                params,
                &log,
            )
            .await?;
        }
    }

    update_current_policy(db_pool, target, policy.policy_id, log).await?;
    Ok(())
}

async fn delete_forwarding_reject_rule(
    ip: &std::net::IpAddr,
    log: &slog::Logger,
) -> Result<(), EnforcementError> {
    if !forwarding_reject_rule_present(ip).await? {
        slog::debug!(log, "Forwarding filter delete requested but filter not present"; "ip" => ip.to_string());
        return Ok(());
    }

    let command_output = tokio::process::Command::new("iptables")
        .args(&["-D", "FORWARD", "-s", &ip.to_string(), "-j", "REJECT"])
        .output()
        .await?;

    if !command_output.status.success() {
        slog::error!(log, "iptables delete forward reject rule failed"; "ip" => ip.to_string());
        return Err(EnforcementError::IptablesLogicError(
            String::from_utf8(command_output.stderr).unwrap(),
        ));
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

    let mut found_child = false;
    for qdisc in current_iface_qdiscs {
        if qdisc.handle != "0:" {
            found_child = true;
            break;
        }
    }

    if !found_child {
        slog::info!(log, "only default qdisc present, nothing to clear"; "interface" => iface);
        return Ok(());
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

async fn setup_root_qdisc(
    iface: &str,
    id_offset: u8,
    log: &slog::Logger,
) -> Result<(), EnforcementError> {
    slog::debug!(log, "Setting up root qdisc"; "interface" => iface);

    let add_status = tokio::process::Command::new("tc")
        .args(&[
            "qdisc",
            "add",
            "dev",
            iface,
            "parent",
            "root",
            "handle",
            &format!("{:X}:", id_offset + 1),
            "htb",
        ])
        .status()
        .await?;

    if !add_status.success() {
        slog::warn!(log, "qdisc add root with htb failed");
    }

    Ok(())
}

async fn setup_subscriber_class(
    iface: &str,
    id_offset: u8,
    sub_handle_fragment: &str,
    log: &slog::Logger,
) -> Result<(), EnforcementError> {
    slog::debug!(log, "adding subscriber class to base qdisc"; "interface" => iface, "sub" => sub_handle_fragment);

    let add_status = tokio::process::Command::new("tc")
        .args(&[
            "class",
            "add",
            "dev",
            iface,
            "parent",
            &format!("{:X}:", id_offset + 1),
            "classid",
            &format!("{:X}:{}", id_offset + 1, sub_handle_fragment),
            "htb",
            "rate",
            "100kbits",
        ])
        .status()
        .await?;

    if !add_status.success() {
        slog::warn!(log, "htb add subscriber class failed");
    }

    let add_status = tokio::process::Command::new("tc")
        .args(&[
            "qdisc",
            "add",
            "dev",
            iface,
            "parent",
            &format!("{:X}:{}", id_offset + 1, sub_handle_fragment),
            "handle",
            &format!("{:X}{}:", id_offset + 6, sub_handle_fragment),
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
        slog::warn!(log, "qdisc add sub sfq failed");
    }

    Ok(())
}

async fn setup_fallback_class(
    iface: &str,
    id_offset: u8,
    log: &slog::Logger,
) -> Result<(), EnforcementError> {
    slog::debug!(log, "adding fallback class to base qdisc"; "interface" => iface);

    let add_status = tokio::process::Command::new("tc")
        .args(&[
            "class",
            "add",
            "dev",
            iface,
            "parent",
            &format!("{:X}:", id_offset + 1),
            "classid",
            &format!("{:X}:0xFFFF", id_offset + 1),
            "htb",
            "rate",
            "100kbps",
            "ceil",
            "1gbps",
        ])
        .status()
        .await?;

    if !add_status.success() {
        slog::warn!(log, "htb add default class failed");
    }

    slog::debug!(log, "adding catchall_filter"; "interface" => iface);

    let add_status = tokio::process::Command::new("tc")
        .args(&[
            "filter",
            "add",
            "dev",
            iface,
            "parent",
            &format!("{:X}:", id_offset + 1),
            "prio",
            "2",
            "matchall",
            "flowid",
            &format!("{:X}:0xFFFF", id_offset + 1),
        ])
        .status()
        .await?;

    if !add_status.success() {
        slog::warn!(log, "add catchall filter failed");
    }

    slog::debug!(log, "adding catchall_qdisc"; "interface" => iface);
    let add_status = tokio::process::Command::new("tc")
        .args(&[
            "qdisc",
            "add",
            "dev",
            iface,
            "parent",
            &format!("{:X}:0xFFFF", id_offset + 1),
            "handle",
            &format!("0x{:X}FFF:", id_offset + 1),
            "fq_codel",
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
    id_offset: u8,
    sub_handle: &str,
    log: &slog::Logger,
) -> Result<(), EnforcementError> {
    slog::debug!(log, "clearing limit"; "interface" => iface, "sub_handle" => sub_handle);

    let change_status = tokio::process::Command::new("tc")
        .args(&[
            "class",
            "change",
            "dev",
            iface,
            "parent",
            &format!("{:X}:", id_offset + 1),
            "classid",
            &format!("{:X}:{}", id_offset + 1, sub_handle),
            "htb",
            "rate",
            "100kbps",
            "ceil",
            "1gbps",
        ])
        .status()
        .await?;
    if !change_status.success() {
        slog::warn!(log, "htb class change rate limit to 1gbps failed");
    }

    Ok(())
}

async fn set_user_token_bucket(
    iface: &str,
    id_offset: u8,
    sub_handle: &str,
    params: &TokenBucketParameters,
    log: &slog::Logger,
) -> Result<(), EnforcementError> {
    slog::debug!(log, "setting token bucket limit"; "interface" => iface, "sub_handle" => sub_handle);

    let change_status = tokio::process::Command::new("tc")
        .args(&[
            "class",
            "change",
            "dev",
            iface,
            "parent",
            &format!("{:X}:", id_offset + 1),
            "classid",
            &format!("{:X}:{}", id_offset + 1, sub_handle),
            "htb",
            "rate",
            &format!("{}kbit", params.rate_kibps),
            "ceil",
            &format!("{}kbit", params.rate_kibps),
        ])
        .status()
        .await?;
    if !change_status.success() {
        slog::warn!(log, "htb class change rate limit failed");
    }

    Ok(())
}

async fn add_subscriber_dst_filter(
    iface: &str,
    id_offset: u8,
    sub: &SubscriberControlState,
    log: &slog::Logger,
) -> Result<(), EnforcementError> {
    // TODO(matt9j) Only supports IPv4, should support v4 and v6!
    slog::debug!(log, "adding sub dst_filter"; "interface" => iface, "sub_handle" => &sub.qdisc_handle);

    let add_status = tokio::process::Command::new("tc")
        .args(&[
            "filter",
            "add",
            "dev",
            iface,
            "parent",
            &format!("{:X}:", id_offset + 1),
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
            &format!("{:X}:{}", id_offset + 1, &sub.qdisc_handle),
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
    id_offset: u8,
    sub: &SubscriberControlState,
    log: &slog::Logger,
) -> Result<(), EnforcementError> {
    // TODO(matt9j) Only supports IPv4, should support v4 and v6!
    slog::debug!(log, "adding sub src filter"; "interface" => iface, "sub_handle" => &sub.qdisc_handle);

    let add_status = tokio::process::Command::new("tc")
        .args(&[
            "filter",
            "add",
            "dev",
            iface,
            "parent",
            &format!("{:X}:", id_offset + 1),
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
            &format!("{:X}:{}", id_offset + 1, &sub.qdisc_handle),
        ])
        .status()
        .await?;

    if !add_status.success() {
        slog::warn!(log, "add subscriber src filter failed");
    }

    Ok(())
}

async fn update_current_policy(
    db_pool: &sqlx::PgPool,
    id: UserId,
    new_policy: PolicyId,
    log: &slog::Logger,
) -> Result<SubscriberAccessInfo, EnforcementError> {
    let mut transaction = db_pool.begin().await?;
    slog::debug!(log, "noting the currently applied policy in the DB"; "id" => id);

    let subscriber_update_query = r#"
        UPDATE subscribers
        SET "current_policy" = $1
        FROM access_policies, static_ips
        WHERE ("internal_uid" = $2) AND (subscribers.current_policy = access_policies.id) AND (subscribers.imsi = static_ips.imsi)
        RETURNING "internal_uid" AS "subscriber_id", access_policies."id" AS "policy_id", "ip", "local_ul_policy_kind", "local_ul_policy_parameters", "local_dl_policy_kind", "local_dl_policy_parameters", "backhaul_ul_policy_kind", "backhaul_ul_policy_parameters", "backhaul_dl_policy_kind", "backhaul_dl_policy_parameters"
    "#;

    let policy_row: SubscriberAccessPolicyRow = sqlx::query_as(subscriber_update_query)
        .bind(new_policy)
        .bind(id)
        .fetch_one(&mut transaction)
        .await?;

    transaction.commit().await?;

    let parsed_access_info: SubscriberAccessInfo = (&policy_row).try_into()?;
    Ok(parsed_access_info)
}

async fn query_subscriber_ip(
    subscriber_id: UserId,
    db_pool: &sqlx::PgPool,
    log: &slog::Logger,
) -> Result<ipnetwork::IpNetwork, EnforcementError> {
    slog::debug!(log, "querying subscriber ip");
    let mut transaction = db_pool.begin().await?;

    let ip_query = r#"
        SELECT "ip"
        FROM subscribers
        INNER JOIN static_ips ON subscribers.imsi = static_ips.imsi
        WHERE (subscribers.internal_uid = $1)
    "#;

    let ip_rows: Vec<SubscriberIpRow> = sqlx::query_as(ip_query)
        .bind(subscriber_id)
        .fetch_all(&mut transaction)
        .await?;

    transaction.commit().await?;

    if ip_rows.len() != 1 {
        return Err(EnforcementError::UserIdError);
    }

    Ok(ip_rows.first().unwrap().ip)
}

async fn query_subscriber_access_policy(
    subscriber_id: UserId,
    condition: SubscriberCondition,
    db_pool: &sqlx::PgPool,
    log: &slog::Logger,
) -> Result<SubscriberAccessInfo, EnforcementError> {
    slog::debug!(log, "querying subscriber access policy");
    let ratelimit_state_query = match condition {
        SubscriberCondition::_PositiveBalance => {
            r#"
                SELECT "internal_uid" AS "subscriber_id", "access_policies"."id" AS "policy_id", "local_ul_policy_kind", "local_ul_policy_parameters", "local_dl_policy_kind", "local_dl_policy_parameters", "backhaul_ul_policy_kind", "backhaul_ul_policy_parameters", "backhaul_dl_policy_kind", "backhaul_dl_policy_parameters"
                FROM subscribers
                INNER JOIN access_policies ON subscribers.positive_balance_policy = access_policies.id
                WHERE (subscriber_id = $1)
            "#
        }
        SubscriberCondition::NoBalance => {
            r#"
                SELECT "internal_uid" AS "subscriber_id", "access_policies"."id" AS "policy_id", "local_ul_policy_kind", "local_ul_policy_parameters", "local_dl_policy_kind", "local_dl_policy_parameters", "backhaul_ul_policy_kind", "backhaul_ul_policy_parameters", "backhaul_dl_policy_kind", "backhaul_dl_policy_parameters"
                FROM subscribers
                INNER JOIN access_policies ON subscribers.zero_balance_policy = access_policies.id
                WHERE (subscriber_id = $1)
            "#
        }
    };

    let mut transaction = db_pool.begin().await?;
    let policy_rows: Vec<SubscriberAccessPolicyRow> = sqlx::query_as(ratelimit_state_query)
        .bind(subscriber_id)
        .fetch_all(&mut transaction)
        .await?;

    transaction.commit().await?;

    if policy_rows.len() != 1 {
        return Err(EnforcementError::UserIdError);
    }

    let parsed_access_info: SubscriberAccessInfo = policy_rows.first().unwrap().try_into()?;
    Ok(parsed_access_info)
}

async fn query_all_subscriber_access_state(
    db_pool: &sqlx::PgPool,
    log: &slog::Logger,
) -> Result<Vec<SubscriberAccessInfo>, EnforcementError> {
    slog::debug!(log, "querying global ratelimit db state");
    let mut transaction = db_pool.begin().await?;

    // Get the ratelimit state to apply for each condition of subscribers. Need
    // to return different columns based on the subscriber's account balance (or
    // possibly other conditions in the future).

    // Zero balance subscribers
    let ratelimit_state_query = r#"
        SELECT "internal_uid" AS "subscriber_id", access_policies."id" AS "policy_id", "ip", "local_ul_policy_kind", "local_ul_policy_parameters", "local_dl_policy_kind", "local_dl_policy_parameters", "backhaul_ul_policy_kind", "backhaul_ul_policy_parameters", "backhaul_dl_policy_kind", "backhaul_dl_policy_parameters"
        FROM subscribers
        INNER JOIN static_ips ON subscribers.imsi = static_ips.imsi
        INNER JOIN access_policies ON subscribers.zero_balance_policy = access_policies.id
        WHERE (subscribers.data_balance = 0)
    "#;

    let zero_balance_rows: Vec<SubscriberAccessPolicyRow> = sqlx::query_as(ratelimit_state_query)
        .fetch_all(&mut transaction)
        .await?;

    // Positive balance subscribers
    let ratelimit_state_query = r#"
        SELECT "internal_uid" AS "subscriber_id", access_policies."id" AS "policy_id", "ip", "local_ul_policy_kind", "local_ul_policy_parameters", "local_dl_policy_kind", "local_dl_policy_parameters", "backhaul_ul_policy_kind", "backhaul_ul_policy_parameters", "backhaul_dl_policy_kind", "backhaul_dl_policy_parameters"
        FROM subscribers
        INNER JOIN static_ips ON subscribers.imsi = static_ips.imsi
        INNER JOIN access_policies ON subscribers.positive_balance_policy = access_policies.id
        WHERE (subscribers.data_balance > 0)
    "#;

    let positive_balance_rows: Vec<SubscriberAccessPolicyRow> =
        sqlx::query_as(ratelimit_state_query)
            .fetch_all(&mut transaction)
            .await?;

    transaction.commit().await?;

    // Once rows are retreived, parse them into our internal representation.
    let mut parsed_ratelimits: Vec<SubscriberAccessInfo> = Vec::new();
    parsed_ratelimits.reserve_exact(zero_balance_rows.len() + positive_balance_rows.len());
    for row in zero_balance_rows.iter() {
        parsed_ratelimits.push(row.try_into()?)
    }
    for row in positive_balance_rows.iter() {
        parsed_ratelimits.push(row.try_into()?)
    }

    Ok(parsed_ratelimits)
}

async fn query_modified_subscriber_access_state(
    db_pool: &sqlx::PgPool,
    log: &slog::Logger,
) -> Result<Vec<SubscriberAccessInfo>, EnforcementError> {
    let mut transaction = db_pool.begin().await?;
    slog::debug!(log, "querying subscribers with modified access state");

    // Get the ratelimit state to apply for each condition of subscribers. Need
    // to return different columns based on the subscriber's account balance (or
    // possibly other conditions in the future).

    // Zero balance subscribers
    let ratelimit_state_updated_query = r#"
        SELECT "internal_uid" AS "subscriber_id", access_policies."id" AS "policy_id", "ip", "local_ul_policy_kind", "local_ul_policy_parameters", "local_dl_policy_kind", "local_dl_policy_parameters", "backhaul_ul_policy_kind", "backhaul_ul_policy_parameters", "backhaul_dl_policy_kind", "backhaul_dl_policy_parameters"
        FROM subscribers
        INNER JOIN static_ips ON subscribers.imsi = static_ips.imsi
        INNER JOIN access_policies ON subscribers.zero_balance_policy = access_policies.id
        WHERE (subscribers.data_balance = 0) AND (subscribers.zero_balance_policy != subscribers.current_policy)
    "#;

    let zero_balance_rows: Vec<SubscriberAccessPolicyRow> =
        sqlx::query_as(ratelimit_state_updated_query)
            .fetch_all(&mut transaction)
            .await?;

    // Positive balance subscribers
    let ratelimit_state_updated_query = r#"
        SELECT "internal_uid" AS "subscriber_id", access_policies."id" AS "policy_id", "ip", "local_ul_policy_kind", "local_ul_policy_parameters", "local_dl_policy_kind", "local_dl_policy_parameters", "backhaul_ul_policy_kind", "backhaul_ul_policy_parameters", "backhaul_dl_policy_kind", "backhaul_dl_policy_parameters"
        FROM subscribers
        INNER JOIN static_ips ON subscribers.imsi = static_ips.imsi
        INNER JOIN access_policies ON subscribers.positive_balance_policy = access_policies.id
        WHERE (subscribers.data_balance > 0) AND (subscribers.positive_balance_policy != subscribers.current_policy)
    "#;

    let positive_balance_rows: Vec<SubscriberAccessPolicyRow> =
        sqlx::query_as(ratelimit_state_updated_query)
            .fetch_all(&mut transaction)
            .await?;

    transaction.commit().await?;

    // Once rows are retreived, parse them into our internal representation.
    let mut parsed_ratelimits: Vec<SubscriberAccessInfo> = Vec::new();
    parsed_ratelimits.reserve_exact(zero_balance_rows.len() + positive_balance_rows.len());
    for row in zero_balance_rows.iter() {
        parsed_ratelimits.push(row.try_into()?)
    }
    for row in positive_balance_rows.iter() {
        parsed_ratelimits.push(row.try_into()?)
    }

    Ok(parsed_ratelimits)
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

#[derive(Debug, Clone, Deserialize)]
struct LimitPolicyParameters {
    rate_kibps: Option<u32>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct SubscriberAccessPolicyRow {
    ip: ipnetwork::IpNetwork,
    subscriber_id: i32,
    policy_id: i32,
    local_ul_policy_kind: i32,
    local_ul_policy_parameters: sqlx::types::Json<LimitPolicyParameters>,
    local_dl_policy_kind: i32,
    local_dl_policy_parameters: sqlx::types::Json<LimitPolicyParameters>,
    backhaul_ul_policy_kind: i32,
    backhaul_ul_policy_parameters: sqlx::types::Json<LimitPolicyParameters>,
    backhaul_dl_policy_kind: i32,
    backhaul_dl_policy_parameters: sqlx::types::Json<LimitPolicyParameters>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct SubscriberIpRow {
    ip: ipnetwork::IpNetwork,
}

#[derive(Debug, Clone)]
struct TokenBucketParameters {
    rate_kibps: u32,
}

#[derive(Debug, Clone)]
enum AccessPolicy {
    Unlimited,
    Block,
    TokenBucket(TokenBucketParameters),
}

#[derive(Debug, Clone)]
struct SubscriberAccessInfo {
    ip: ipnetwork::IpNetwork,
    subscriber_id: i32,
    policy_id: i32,
    _local_ul_policy: AccessPolicy,
    _local_dl_policy: AccessPolicy,
    backhaul_ul_policy: AccessPolicy,
    backhaul_dl_policy: AccessPolicy,
}

fn create_policy_from_parameters(
    policy_kind_id: i32,
    parameters: &LimitPolicyParameters,
) -> Result<AccessPolicy, EnforcementError> {
    match policy_kind_id {
        1 => Ok(AccessPolicy::Unlimited),
        2 => Ok(AccessPolicy::Block),
        3 => {
            let parsed_parameters = TokenBucketParameters {
                rate_kibps: parameters.rate_kibps.ok_or(
                    EnforcementError::RateLimitParameterError("Missing rate_kibps".to_owned()),
                )?,
            };
            Ok(AccessPolicy::TokenBucket(parsed_parameters))
        }
        _ => Err(EnforcementError::RateLimitPolicyError(policy_kind_id)),
    }
}

impl TryFrom<&SubscriberAccessPolicyRow> for SubscriberAccessInfo {
    type Error = EnforcementError;

    fn try_from(row: &SubscriberAccessPolicyRow) -> Result<Self, Self::Error> {
        Ok(SubscriberAccessInfo {
            ip: row.ip,
            subscriber_id: row.subscriber_id,
            policy_id: row.policy_id,
            _local_ul_policy: create_policy_from_parameters(
                row.local_ul_policy_kind,
                &row.local_ul_policy_parameters,
            )?,
            _local_dl_policy: create_policy_from_parameters(
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
