use std::sync::Arc;

use async_trait::async_trait;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ReportError {
    #[error("Report failed to connect to the database")]
    DatabaseError(#[from] sqlx::error::Error),
    #[error("Report failed to connect to the database")]
    UserLookupError,
}

#[async_trait]
pub trait Reporter {
    async fn report(&self, amount: u64) -> Result<(), ReportError>;
}

#[derive(Debug, Clone)]
pub struct UserReporter {
    db_pool: Arc<sqlx::PgPool>,
}
impl UserReporter {
    pub fn new(pool: Arc<sqlx::PgPool>) -> Self {
        Self {
            db_pool: pool,
        }
    }
}

#[async_trait]
impl Reporter for UserReporter {
    async fn report(&self, amount: u64) -> Result<(), ReportError> {
        let mut transaction = self.db_pool.begin().await?;

        let current_state_query = r#"
            SELECT "ip", subscribers."imsi", "internal_uid" AS "subscriber_id", "data_balance", "balance", "bridged"
            FROM subscribers
            INNER JOIN static_ips ON static_ips.imsi = subscribers.imsi
            WHERE static_ips.ip='10.45.0.2'
        "#;

        let rows: Vec<SubscriberRow> = sqlx::query_as(current_state_query).fetch_all(&mut transaction).await?;

        // Ensure the user is unique
        if rows.len() != 1 {
            return Err(ReportError::UserLookupError);
        }
        let user_state = rows.first().unwrap();

        let new_data_balance = user_state.data_balance - (amount as i64);

        let update_history_query = r#"
            INSERT INTO subscriber_history("subscriber", "time", "data_balance", "balance", "bridged")
            VALUES ($1, $2, $3, $4, $5)
        "#;
        sqlx::query(update_history_query).bind(
            &user_state.subscriber_id).bind(chrono::Utc::now()).bind(&new_data_balance).bind(&user_state.balance).bind(&user_state.bridged)
        .execute(&mut transaction).await?;

        let subscriber_update_query = r#"
            UPDATE subscribers
            SET "data_balance" = $1
            WHERE "internal_uid" = $2
        "#;

        sqlx::query(subscriber_update_query)
            .bind(&new_data_balance)
            .bind(&user_state.subscriber_id)
            .execute(&mut transaction).await?;

        transaction.commit().await?;
        Ok(())
    }
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
