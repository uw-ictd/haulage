use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ReportError {
    #[error("Database operation failed: {0}")]
    DatabaseError(#[from] sqlx::error::Error),
    #[error("Failed to lookup user")]
    UserLookupError,
}

#[async_trait]
pub trait Reporter {
    async fn report(&self, use_record: UseRecord) -> Result<(), ReportError>;
    fn new(pool: Arc<sqlx::PgPool>, id: std::net::IpAddr) -> Self;
    async fn initialize(&mut self) -> Result<(), ReportError>;
}

#[derive(Debug, Clone)]
pub struct UserReporter {
    db_pool: Arc<sqlx::PgPool>,
    ip_addr: std::net::IpAddr,
    id: i32,
}

#[async_trait]
impl Reporter for UserReporter {
    async fn report(&self, record: UseRecord) -> Result<(), ReportError> {
        if self.id < 0 {
            // TODO Actually enforce at compile time rather than with a runtime panic.
            panic!("Invalid ID: reporter not initialized!");
        }
        let mut transaction = self.db_pool.begin().await?;

        let update_history_query = r#"
            INSERT INTO subscriber_usage("subscriber", "start_time", "end_time", "ran_bytes_up", "ran_bytes_down", "wan_bytes_up", "wan_bytes_down")
            VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#;
        sqlx::query(update_history_query)
            .bind(&self.id)
            .bind(&record.start)
            .bind(&record.end)
            .bind(&record.usage.ran_bytes_up)
            .bind(&record.usage.ran_bytes_down)
            .bind(&record.usage.wan_bytes_up)
            .bind(&record.usage.wan_bytes_down)
            .execute(&mut transaction)
            .await?;

        transaction.commit().await?;
        Ok(())
    }

    fn new(pool: Arc<sqlx::PgPool>, ip: std::net::IpAddr) -> Self {
        Self {
            db_pool: pool,
            ip_addr: ip,
            id: -1,
        }
    }

    async fn initialize(&mut self) -> Result<(), ReportError> {
        let mut transaction = self.db_pool.begin().await?;

        let id_query = r#"
            SELECT "internal_uid" AS "subscriber_id", ip
            FROM subscribers
            INNER JOIN static_ips ON static_ips.imsi = subscribers.imsi
            WHERE static_ips.ip = $1
        "#;

        let rows: Vec<IdRow> = sqlx::query_as(id_query)
            .bind(ipnetwork::IpNetwork::from(self.ip_addr))
            .fetch_all(&mut transaction)
            .await?;

        // Ensure the user is unique
        if rows.len() != 1 {
            return Err(ReportError::UserLookupError);
        }
        let user_state = rows.first().unwrap();

        self.id = user_state.subscriber_id;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct UseRecord {
    pub start: chrono::DateTime<Utc>,
    pub end: chrono::DateTime<Utc>,

    pub usage: crate::NetResourceBundle,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct SubscriberReportRow {
    subscriber: i32,
    timestamp: chrono::DateTime<chrono::Utc>,
    data_balance: i64,
    balance: rust_decimal::Decimal,
    bridged: bool,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct SubscriberRow {
    ip: ipnetwork::IpNetwork,
    imsi: String,
    subscriber_id: i32,
    data_balance: i64,
    balance: rust_decimal::Decimal,
    bridged: bool,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct IdRow {
    subscriber_id: i32,
    ip: ipnetwork::IpNetwork,
}
