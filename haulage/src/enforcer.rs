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
        db_pool: std::sync::Arc<sqlx::PgPool>,
        log: slog::Logger,
    ) -> Iptables {
        let (sender, receiver) = tokio::sync::mpsc::channel(64);
        let local_logger = log.clone();
        let dispatch_handle = tokio::task::spawn(async move {
            enforce_via_iptables(receiver, poll_period, db_pool, log).await;
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

#[derive(Debug, Clone, sqlx::FromRow)]
struct SubscriberBridgeInfo {
    ip: ipnetwork::IpNetwork,
    subscriber_id: i32,
    bridged: bool,
}
