use serde::Deserialize;
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
    #[error("Failed to parse json: {0}")]
    SerdeJsonError(#[from] serde_json::Error),
}

#[derive(Debug)]
pub struct Iptables {
    dispatch_handle: tokio::task::JoinHandle<()>,
    dispatch_channel: tokio::sync::mpsc::Sender<PolicyUpdateMessage>,
    log: slog::Logger,
}
impl Iptables {
    pub fn new(
        poll_period: std::time::Duration,
        interface: &str,
        db_pool: std::sync::Arc<sqlx::PgPool>,
        log: slog::Logger,
    ) -> Iptables {
        let (sender, receiver) = tokio::sync::mpsc::channel(64);
        let local_logger = log.clone();
        let interface = interface.to_owned();
        let dispatch_handle = tokio::task::spawn(async move {
            enforce_via_iptables(receiver, poll_period, &interface, db_pool, log).await;
        });
        Iptables {
            dispatch_handle: dispatch_handle,
            dispatch_channel: sender,
            log: local_logger,
        }
    }
    pub async fn update_policy(
        &self,
        target: UserId,
        new_policy: Policy,
    ) -> Result<(), EnforcementError> {
        let (result_channel_tx, result_channel_rx) =
            tokio::sync::oneshot::channel::<Result<(), EnforcementError>>();
        self.dispatch_channel
            .send(PolicyUpdateMessage {
                new_policy: new_policy,
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

pub enum Policy {
    Unlimited,
    LocalOnly,
}

struct PolicyUpdateMessage {
    new_policy: Policy,
    target: UserId,
    out_channel: tokio::sync::oneshot::Sender<Result<(), EnforcementError>>,
}

async fn enforce_via_iptables(
    mut chan: tokio::sync::mpsc::Receiver<PolicyUpdateMessage>,
    period: std::time::Duration,
    interface: &str,
    db_pool: std::sync::Arc<sqlx::PgPool>,
    log: slog::Logger,
) -> () {
    // On startup synchronize the state in the database with the local iptables
    // rules. This is not very robust, and would be better integrated with
    // actual netfilter tables for efficiency and better control of the actual
    // state of the rules present when other firewalls my also be active.
    let current_db_state = query_all_subscriber_bridge_state(&db_pool, &log)
        .await
        .expect("Unable to get initial desired iptables state!");

    for sub in current_db_state {
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
    clear_interface_limit(interface, &log).await.unwrap();

    // TODO(matt9j) Setup the qdisc framework for rate limiting, ensuring to
    // clean up after an unclean prior exit if needed.
    let current_db_state = query_all_subscriber_ratelimit_state(&db_pool, &log)
        .await
        .expect("Unable to get initial ratelimit state");
    for sub in current_db_state {
        match sub.ul_policy {
            RateLimitPolicy::Unlimited => {
                // TODO(matt9j) Ensure the ratelimit is not set for this sub
            }
        }

        match sub.dl_policy {
            RateLimitPolicy::Unlimited => {
                // TODO(matt9j) Ensure the ratelimit is not set for this sub
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
                    set_policy(sub.subscriber_id, Policy::Unlimited, &db_pool, &log)
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

                let result = set_policy(message.target, message.new_policy, &db_pool, &log).await;
                message.out_channel.send(result).unwrap();
            }
        }
    }
}

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
    policy: Policy,
    db_pool: &sqlx::PgPool,
    log: &slog::Logger,
) -> Result<(), EnforcementError> {
    match policy {
        Policy::Unlimited => set_unlimited_policy(&db_pool, target, &log).await,
        Policy::LocalOnly => set_local_only_policy(&db_pool, target, &log).await,
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

// TODO(matt9j) Add handlers for adding a user to ratelimiting, and removing a
// user from rate-limiting in the overall filter tree.

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
    slog::debug!(log, "About to clear interface config"; "interface" => iface);
    let current_iface_status = tokio::process::Command::new("tc")
        .args(&["-j", "qdisc", "show", "dev", iface])
        .output()
        .await?;

    // Delete the options "key", which in debian Buster and earlier is not valid
    // JSON for the tbf qdisc :(
    let current_iface_status = delete_malformed_options_element(
        std::str::from_utf8(&current_iface_status.stdout).unwrap(),
    );
    let current_iface_qdiscs: Vec<QDiscInfo> = serde_json::from_str(&current_iface_status)?;
    if current_iface_qdiscs.len() > 1 {
        slog::warn!(log, "Clearing non-trivial qdisc config");
        for qdisc in current_iface_qdiscs {
            if qdisc.root.unwrap_or(false) {
                // Skip the root qdisc, which cannot be deleted.
                continue;
            }

            slog::info!(log, "Clearing"; "kind" => qdisc.kind, "handle" => qdisc.handle);

            let clear_status = tokio::process::Command::new("tc")
                .args(&["qdisc", "del", "dev", iface, "root"])
                .status()
                .await?;

            if !clear_status.success() {
                slog::warn!(log, "qdisc clear failed");
            }
        }
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
    slog::debug!(log, "Updating bridge state in DB"; "id" => id);

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
    let mut transaction = db_pool.begin().await?;
    slog::debug!(log, "Querying global ratelimit db state");

    let ratelimit_state_query = r#"
        SELECT "internal_uid" AS "subscriber_id", "ip", "ul_limit_policy", "dl_limit_policy", "ul_limit_policy_parameters", "dl_limit_policy_parameters"
        FROM subscribers
        INNER JOIN static_ips ON subscribers.imsi = static_ips.imsi
    "#;

    let rows: Vec<SubscriberRateLimitRow> = sqlx::query_as(ratelimit_state_query)
        .fetch_all(&mut transaction)
        .await?;

    let mut parsed_ratelimits: Vec<SubscriberRateLimitInfo> = Vec::new();
    for row in rows.iter() {
        parsed_ratelimits.push(row.try_into()?)
    }

    transaction.commit().await?;
    Ok(parsed_ratelimits)
}

async fn query_all_subscriber_bridge_state(
    db_pool: &sqlx::PgPool,
    log: &slog::Logger,
) -> Result<Vec<SubscriberBridgeInfo>, EnforcementError> {
    let mut transaction = db_pool.begin().await?;
    slog::debug!(log, "Querying global bridged db state");

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
    slog::debug!(log, "Querying reenabled subscribers");

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

#[derive(Debug, Deserialize)]
struct QDiscInfo {
    kind: String,
    handle: String,
    root: Option<bool>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct SubscriberBridgeInfo {
    ip: ipnetwork::IpNetwork,
    subscriber_id: i32,
    bridged: bool,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct SubscriberRateLimitRow {
    ip: ipnetwork::IpNetwork,
    subscriber_id: i32,
    ul_limit_policy: i32,
    dl_limit_policy: i32,
    ul_limit_policy_parameters: String,
    dl_limit_policy_parameters: String,
}

#[derive(Debug, Clone)]
enum RateLimitPolicy {
    Unlimited = 1,
}

#[derive(Debug, Clone)]
struct SubscriberRateLimitInfo {
    ip: ipnetwork::IpNetwork,
    subscriber_id: i32,
    ul_policy: RateLimitPolicy,
    dl_policy: RateLimitPolicy,
}

fn create_policy_from_parameters(
    policy_id: i32,
    _parameters: &String,
) -> Result<RateLimitPolicy, EnforcementError> {
    match policy_id {
        1 => Ok(RateLimitPolicy::Unlimited),
        _ => Err(EnforcementError::RateLimitPolicyError(policy_id)),
    }
}

impl TryFrom<&SubscriberRateLimitRow> for SubscriberRateLimitInfo {
    type Error = EnforcementError;

    fn try_from(row: &SubscriberRateLimitRow) -> Result<Self, Self::Error> {
        Ok(SubscriberRateLimitInfo {
            ip: row.ip,
            subscriber_id: row.subscriber_id,
            ul_policy: create_policy_from_parameters(
                row.ul_limit_policy,
                &row.ul_limit_policy_parameters,
            )?,
            dl_policy: create_policy_from_parameters(
                row.dl_limit_policy,
                &row.dl_limit_policy_parameters,
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
