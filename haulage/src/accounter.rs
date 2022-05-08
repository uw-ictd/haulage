use std::collections::HashMap;

pub use i32 as UserId;

#[derive(Debug)]
pub struct UserAccounter {
    dispatch_channel: tokio::sync::mpsc::Sender<Message>,
}
impl UserAccounter {
    pub fn new(
        period: std::time::Duration,
        db_pool: std::sync::Arc<sqlx::PgPool>,
        enforcer: std::sync::Arc<crate::enforcer::Iptables>,
        log: slog::Logger,
    ) -> UserAccounter {
        let (sender, receiver) = tokio::sync::mpsc::channel(64);
        tokio::task::spawn(async move {
            accounting_task_dispatcher(receiver, period, db_pool, enforcer, log).await;
        });
        UserAccounter {
            dispatch_channel: sender,
        }
    }
    pub fn clone_input_channel(&self) -> tokio::sync::mpsc::Sender<Message> {
        self.dispatch_channel.clone()
    }
}

pub enum Message {
    Report { ip: std::net::IpAddr, amount: u64 },
}

async fn accounting_task_dispatcher(
    mut chan: tokio::sync::mpsc::Receiver<Message>,
    period: std::time::Duration,
    db_pool: std::sync::Arc<sqlx::PgPool>,
    enforcer: std::sync::Arc<crate::enforcer::Iptables>,
    log: slog::Logger,
) -> () {
    let mut directory: HashMap<std::net::IpAddr, tokio::sync::mpsc::Sender<WorkerMessage>> =
        HashMap::new();

    while let Some(message) = chan.recv().await {
        match message {
            Message::Report { ip: dest, amount } => {
                if !directory.contains_key(&dest) {
                    let (worker_chan_send, worker_chan_recv) = tokio::sync::mpsc::channel(32);
                    let worker_log =
                        log.new(slog::o!("aggregation" => String::from(format!("{:?}", dest))));

                    let db_pool = db_pool.clone();
                    let enforcer = std::sync::Arc::clone(&enforcer);

                    directory.insert(dest.clone(), worker_chan_send);
                    tokio::task::spawn(async move {
                        accounting_worker(
                            dest,
                            worker_chan_recv,
                            period,
                            db_pool,
                            enforcer,
                            worker_log,
                        )
                        .await;
                    });
                }
                directory
                    .get(&dest)
                    .unwrap()
                    .send(WorkerMessage::Report { amount: amount })
                    .await
                    .unwrap_or_else(
                        |e| slog::error!(log, "Failed to dispatch"; "error" => e.to_string()),
                    );
                slog::debug!(log, "Received at dispatch {:?} {}", dest, amount);
            }
        };
    }
}

#[derive(Debug)]
enum WorkerMessage {
    Report {
        amount: u64,
    },
    _GetBalance {
        out_channel: tokio::sync::oneshot::Sender<i64>,
    },
}

async fn accounting_worker(
    ip: std::net::IpAddr,
    mut chan: tokio::sync::mpsc::Receiver<WorkerMessage>,
    db_change_poll_period: std::time::Duration,
    db_pool: std::sync::Arc<sqlx::PgPool>,
    enforcer: std::sync::Arc<crate::enforcer::Iptables>,
    log: slog::Logger,
) -> () {
    // Lookup current balance from DB
    let current_state = query_balance(&db_pool, ip, &log).await.unwrap();
    let subscriber_id = current_state.subscriber_id;
    let mut balance = current_state.data_balance;
    let mut bytes_aggregated: i64 = 0;

    let mut timer = tokio::time::interval_at(
        tokio::time::Instant::now() + db_change_poll_period,
        db_change_poll_period,
    );
    loop {
        tokio::select! {
            _ = timer.tick() => {
                let update_result = update_balance(&db_pool, subscriber_id, -bytes_aggregated, &log).await;
                match update_result {
                    Ok(new_state) => {
                        // Detect if the subscriber's balance has gone negative after synchronizing with the DB
                        if (new_state.data_balance <= 0) && (balance > 0) {
                            enforcer
                                .update_policy(subscriber_id, crate::enforcer::SubscriberCondition::NoBalance)
                                .await
                                .unwrap_or_else(
                                    |e| slog::error!(log, "Unable to update policy for zero balance sub"; "error" => e.to_string())
                                );
                        }

                        balance = new_state.data_balance;
                    }
                    Err(e) => {
                        slog::warn!(log, "Failed to update balance"; "ip" => ip.to_string(), "error" => e.to_string());
                    }
                }
                bytes_aggregated = 0;
            }
            message = chan.recv() => {
                if message.is_none() {
                    break;
                }
                match message.unwrap() {
                    WorkerMessage::Report{amount} => {
                        bytes_aggregated += amount as i64;
                        slog::debug!(log, "Aggregated {} bytes", bytes_aggregated);

                        // Synchronize datastore and rule state at the point of transition to zero balance
                        if (bytes_aggregated >= balance) && (balance > 0) {
                            let update_result = update_balance(&db_pool, subscriber_id, -bytes_aggregated, &log).await;
                            match update_result {
                                Ok(new_state) => {
                                    // Handle the transition to zero balance
                                    if (new_state.data_balance <= 0) && (balance > 0) {
                                        enforcer
                                            .update_policy(subscriber_id, crate::enforcer::SubscriberCondition::NoBalance)
                                            .await
                                            .unwrap_or_else(
                                                |e| slog::error!(log, "Unable to update policy for zero balance sub"; "error" => e.to_string())
                                            );
                                    }

                                    balance = new_state.data_balance;
                                }
                                Err(e) => {
                                    slog::warn!(log, "Failed to update balance"; "ip" => ip.to_string(), "error" => e.to_string());
                                }
                            }
                            bytes_aggregated = 0;
                        }
                    }
                    WorkerMessage::_GetBalance{out_channel} => {
                        // ToDo(matt9j) This might panic during shutdown, if there is a
                        // get request in flight as the dispatcher shuts down?

                        // Account for the bytes aggregated but not sent to the
                        // db yet when answering queries for the balance.
                        out_channel.send(balance - bytes_aggregated).expect("Failed to send oneshot return");
                    }
                }
            }
        };
    }
    slog::debug!(log, "Shutting down worker {}", ip);
}

use thiserror::Error;

#[derive(Error, Debug)]
pub enum QueryError {
    #[error("Database operation failed: {0}")]
    DatabaseError(#[from] sqlx::error::Error),
    #[error("Failed to lookup user")]
    UserLookupError,
}

async fn query_balance(
    db_pool: &sqlx::PgPool,
    ip: std::net::IpAddr,
    log: &slog::Logger,
) -> Result<SubscriberBalanceInfo, QueryError> {
    let mut transaction = db_pool.begin().await?;
    slog::debug!(log, "Querying for balance"; "ip" => ip.to_string());

    let balance_state_query = r#"
        SELECT "ip", "internal_uid" AS "subscriber_id", "data_balance", "bridged"
        FROM subscribers
        INNER JOIN static_ips ON static_ips.imsi = subscribers.imsi
        WHERE static_ips.ip = $1
    "#;

    let rows: Vec<SubscriberBalanceInfo> = sqlx::query_as(balance_state_query)
        .bind(ipnetwork::IpNetwork::from(ip))
        .fetch_all(&mut transaction)
        .await?;

    transaction.commit().await?;

    // Ensure the user is unique
    if rows.len() != 1 {
        return Err(QueryError::UserLookupError);
    }
    let user_state = rows.first().unwrap();

    Ok(user_state.clone())
}

async fn update_balance(
    db_pool: &sqlx::PgPool,
    id: UserId,
    balance_delta: i64,
    log: &slog::Logger,
) -> Result<SubscriberBalanceInfo, QueryError> {
    let mut transaction = db_pool.begin().await?;
    slog::debug!(log, "Updating balance"; "id" => id);

    let subscriber_update_query = r#"
        UPDATE subscribers
        SET "data_balance" = "data_balance" + $1
        FROM static_ips
        WHERE static_ips.imsi = subscribers.imsi AND "internal_uid" = $2
        RETURNING "ip", "internal_uid" AS "subscriber_id", "data_balance", "bridged";
    "#;

    let rows: Vec<SubscriberBalanceInfo> = sqlx::query_as(subscriber_update_query)
        .bind(balance_delta)
        .bind(id)
        .fetch_all(&mut transaction)
        .await?;

    // Ensure the user is unique
    if rows.len() != 1 {
        return Err(QueryError::UserLookupError);
    }
    let mut user_state = rows.first().unwrap().clone();

    // TODO(matt9j) Can we define a better behavior here?
    // For now floor the data balance at zero
    if user_state.data_balance < 0 {
        slog::debug!(log, "Flooring data balance at 0"; "id" => id);
        let update_zero_floor_query = r#"
            UPDATE subscribers
            SET "data_balance" = 0
            FROM static_ips
            WHERE static_ips.imsi = subscribers.imsi AND "internal_uid" = $1
            RETURNING "ip", "internal_uid" AS "subscriber_id", "data_balance", "bridged";
        "#;

        let rows: Vec<SubscriberBalanceInfo> = sqlx::query_as(update_zero_floor_query)
            .bind(id)
            .fetch_all(&mut transaction)
            .await?;

        // Ensure the user is unique
        if rows.len() != 1 {
            return Err(QueryError::UserLookupError);
        }

        user_state = rows.first().unwrap().clone();
    }

    transaction.commit().await?;
    Ok(user_state)
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct SubscriberBalanceInfo {
    ip: ipnetwork::IpNetwork,
    subscriber_id: i32,
    data_balance: i64,
    bridged: bool,
}
