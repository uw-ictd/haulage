use std::collections::HashMap;

#[derive(Debug)]
pub struct AsyncAggregator {
    dispatch_handle: tokio::task::JoinHandle<()>,
    dispatch_channel: tokio::sync::mpsc::Sender<Message>,
}
impl AsyncAggregator {
    pub fn new(log: slog::Logger) -> AsyncAggregator {
        println!("made an aggregator");
        let (sender, receiver) = tokio::sync::mpsc::channel(64);
        let dispatch_handle = tokio::task::spawn(async move {
            aggregate_dispatcher(receiver, log).await;
        });
        AsyncAggregator {
            dispatch_handle: dispatch_handle,
            dispatch_channel: sender,
        }
    }
    pub fn clone_input_channel(& self) -> tokio::sync::mpsc::Sender<Message> {
        self.dispatch_channel.clone()
    }
}

pub enum Message {
    Report {id: std::net::IpAddr, amount: u64}
}

async fn aggregate_dispatcher(mut chan: tokio::sync::mpsc::Receiver<Message>, log: slog::Logger) -> () {
    let mut directory: HashMap<std::net::IpAddr, tokio::sync::mpsc::Sender<WorkerMessage>> = HashMap::new();

    while let Some(message) = chan.recv().await {
        match message {
            Message::Report {id: dest, amount}=> {
                if !directory.contains_key(&dest) {
                    let (worker_chan_send, worker_chan_recv) = tokio::sync::mpsc::channel(32);
                    let worker_log = log.new(slog::o!("aggregation" => String::from(format!("{:?}", dest))));
                    directory.insert(dest.clone(), worker_chan_send);
                    tokio::task::spawn(async move {
                        aggregate_worker(dest.clone(), worker_chan_recv, worker_log).await;
                    });
                }
                directory.get(&dest).unwrap().send(WorkerMessage::Report{amount: amount}).await.unwrap_or_else(|e|
                    slog::error!(log, "Failed to dispatch"; "error" => e.to_string())
                );
                slog::debug!(log, "Received at dispatch {:?} {}", dest, amount);
            }
        };
    }
}

enum WorkerMessage {
    Report {amount: u64},
    _GetTotal {out_channel: tokio::sync::oneshot::Sender<u64>},
}

async fn aggregate_worker(id: std::net::IpAddr, mut chan: tokio::sync::mpsc::Receiver<WorkerMessage>, log: slog::Logger) -> () {
    let mut bytes_aggregated: u64 = 0;
    while let Some(message) = chan.recv().await {
        match message {
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
    slog::debug!(log, "Shutting down worker {}", id);
}