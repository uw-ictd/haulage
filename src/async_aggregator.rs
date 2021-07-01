use crate::reporter::Reporter;
use std::collections::HashMap;

#[derive(Debug)]
pub struct AsyncAggregator {
    dispatch_handle: tokio::task::JoinHandle<()>,
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
        let dispatch_handle = tokio::task::spawn(async move {
            aggregate_dispatcher::<T>(receiver, period, db_pool, log).await;
        });
        AsyncAggregator {
            dispatch_handle: dispatch_handle,
            dispatch_channel: sender,
        }
    }
    pub fn clone_input_channel(&self) -> tokio::sync::mpsc::Sender<Message> {
        self.dispatch_channel.clone()
    }
}

pub enum Message {
    Report { id: std::net::IpAddr, amount: u64 },
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
    _GetTotal {
        out_channel: tokio::sync::oneshot::Sender<u64>,
    },
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
    let mut bytes_aggregated: u64 = 0;
    let mut timer = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
    reporter
        .initialize()
        .await
        .expect("Failed to initialize user reporter");
    loop {
        tokio::select! {
            _ = timer.tick() => {
                let result = reporter.report(bytes_aggregated).await;
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
                        bytes_aggregated += amount;
                        slog::debug!(log, "Aggregated {} bytes", bytes_aggregated);
                    }
                    WorkerMessage::_GetTotal{out_channel} => {
                        // ToDo(matt9j) This might panic during shutdown, if there is a
                        // get request in flight as the dispatcher shuts down?
                        out_channel.send(bytes_aggregated).expect("Failed to send oneshot return");
                    }
                }
            }
        };
    }
    slog::debug!(log, "Shutting down worker {}", id);
}
