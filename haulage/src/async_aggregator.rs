use crate::reporter::Reporter;
use std::collections::HashMap;

#[derive(Debug)]
pub struct AsyncAggregator {
    dispatch_channel: tokio::sync::mpsc::Sender<Message>,
}
impl AsyncAggregator {
    pub fn new<T>(
        period: std::time::Duration,
        db_pool: std::sync::Arc<sqlx::PgPool>,
        log: slog::Logger,
    ) -> AsyncAggregator
    where
        T: Reporter + Send + Sync + Clone + 'static,
    {
        let (sender, receiver) = tokio::sync::mpsc::channel(64);
        tokio::task::spawn(async move {
            aggregate_dispatcher::<T>(receiver, period, db_pool, log).await;
        });
        AsyncAggregator {
            dispatch_channel: sender,
        }
    }
    pub fn clone_input_channel(&self) -> tokio::sync::mpsc::Sender<Message> {
        self.dispatch_channel.clone()
    }
}

pub enum Message {
    Report {
        id: std::net::IpAddr,
        amount: crate::NetResourceBundle,
    },
}

async fn aggregate_dispatcher<T>(
    mut chan: tokio::sync::mpsc::Receiver<Message>,
    period: std::time::Duration,
    db_pool: std::sync::Arc<sqlx::PgPool>,
    log: slog::Logger,
) -> ()
where
    T: Reporter + Send + Sync + Clone + 'static,
{
    let mut directory: HashMap<std::net::IpAddr, tokio::sync::mpsc::Sender<WorkerMessage>> =
        HashMap::new();

    while let Some(message) = chan.recv().await {
        match message {
            Message::Report { id: dest, amount } => {
                slog::debug!(
                    log,
                    "Received at aggregator dispatch {:?} {:?}",
                    dest,
                    amount
                );
                if !directory.contains_key(&dest) {
                    let (worker_chan_send, worker_chan_recv) = tokio::sync::mpsc::channel(32);
                    let worker_log =
                        log.new(slog::o!("aggregation" => String::from(format!("{:?}", dest))));

                    let new_reporter = T::new(db_pool.clone(), dest.clone());
                    directory.insert(dest.clone(), worker_chan_send);
                    tokio::task::spawn(async move {
                        aggregate_worker(dest, worker_chan_recv, period, new_reporter, worker_log)
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
            }
        };
    }
}

#[derive(Debug)]
enum WorkerMessage {
    Report { amount: crate::NetResourceBundle },
}

async fn aggregate_worker<T>(
    id: std::net::IpAddr,
    mut chan: tokio::sync::mpsc::Receiver<WorkerMessage>,
    period: std::time::Duration,
    mut reporter: T,
    log: slog::Logger,
) -> ()
where
    T: Reporter + Send + Sync + Clone + 'static,
{
    // Note: This timing is relatively imprecise since the timestamping is
    // happening in an async context. Ideally the timestamping could happen in
    // hardware per packet. This simple approach is sufficient for the
    // relatively long time durations (minutes) targeted by the software though.
    let mut resources_aggregated = crate::NetResourceBundle::zeroed();

    let interval_start = tokio::time::Instant::now();
    let mut start_chrono = chrono::Utc::now();

    let mut timer = tokio::time::interval_at(interval_start + period, period);

    match reporter.initialize().await {
        Ok(_) => {}
        Err(e) => {
            slog::error!(log, "Failed to initialize reporter"; "id" => id.to_string(), "error" => e.to_string());
            chan.close();
            return;
        }
    }
    loop {
        tokio::select! {
            _ = timer.tick() => {
                let tick_time = chrono::Utc::now();
                let record_start = start_chrono;
                let record_stop = tick_time;
                let archived_resources = resources_aggregated;

                // Reset the loop state variables for the next interval
                resources_aggregated = crate::NetResourceBundle::zeroed();
                start_chrono = tick_time;

                let result = reporter.report(crate::reporter::UseRecord{
                    start: record_start,
                    end: record_stop,
                    usage: archived_resources,
                }).await;
                match result {
                    Ok(_) => {},
                    Err(e) => {
                        slog::warn!(log, "Failed to write out report for {} with error {}", id, e);
                    }
                }
            }
            message = chan.recv() => {
                if message.is_none() {
                    break;
                }
                match message.unwrap() {
                    WorkerMessage::Report{amount} => {
                        resources_aggregated += amount;
                        slog::debug!(log, "Aggregated {:?} bytes", resources_aggregated);
                    }
                }
            }
        };
    }
    slog::debug!(log, "Shutting down worker {}", id);
}
