use crate::{hash_token, AppError, ShareStatus};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use sqlx::{sqlite::SqliteRow, Row, SqlitePool};
use std::time::Duration;
use uuid::Uuid;

#[derive(Clone)]
pub struct Store {
    pool: SqlitePool,
    claim_lease: Duration,
    tombstone_retention: Duration,
}

#[derive(Debug, Clone)]
pub struct StoredShare {
    pub share_id: Uuid,
    pub status: ShareStatus,
    pub ciphertext: Option<Vec<u8>>,
    pub nonce: Option<Vec<u8>>,
    pub expires_at: DateTime<Utc>,
    pub one_time: bool,
    pub aad_version: u32,
    pub admin_token_hash: String,
    pub claim_token_hash: Option<String>,
    pub claim_expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

pub struct ClaimOutcome {
    pub share_id: Uuid,
    pub status: ShareStatus,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub expires_at: DateTime<Utc>,
    pub one_time: bool,
    pub aad_version: u32,
    pub claim_token: Option<String>,
}

pub struct CleanupSummary {
    pub expired: u64,
    pub released_claims: u64,
    pub purged: u64,
}

impl Store {
    pub fn new(pool: SqlitePool, claim_lease: Duration, tombstone_retention: Duration) -> Self {
        Self {
            pool,
            claim_lease,
            tombstone_retention,
        }
    }

    pub async fn initialize(&self) -> Result<(), AppError> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS shares (
                share_id TEXT PRIMARY KEY NOT NULL,
                ciphertext BLOB,
                nonce BLOB,
                expires_at TEXT NOT NULL,
                one_time INTEGER NOT NULL,
                aad_version INTEGER NOT NULL,
                admin_token_hash TEXT NOT NULL,
                state TEXT NOT NULL,
                claim_token_hash TEXT,
                claim_expires_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                consumed_at TEXT,
                revoked_at TEXT
            )
            "#,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn create_share(
        &self,
        share_id: Uuid,
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        expires_at: DateTime<Utc>,
        one_time: bool,
        aad_version: u32,
        admin_token_hash: String,
    ) -> Result<(), AppError> {
        let now = Utc::now();
        let insert = sqlx::query(
            r#"
            INSERT INTO shares (
                share_id, ciphertext, nonce, expires_at, one_time, aad_version,
                admin_token_hash, state, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(share_id.to_string())
        .bind(ciphertext)
        .bind(nonce)
        .bind(expires_at.to_rfc3339())
        .bind(if one_time { 1 } else { 0 })
        .bind(i64::from(aad_version))
        .bind(admin_token_hash)
        .bind(ShareStatus::Available.as_str())
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await;

        match insert {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(db_error)) if db_error.is_unique_violation() => {
                Err(AppError::Validation("share_id already exists".to_string()))
            }
            Err(error) => Err(AppError::from(error)),
        }
    }

    pub async fn claim_share(&self, share_id: Uuid) -> Result<Option<ClaimOutcome>, AppError> {
        let mut tx = self.pool.begin().await?;
        let Some(mut share) = self.load_share_tx(&mut tx, share_id).await? else {
            tx.commit().await?;
            return Ok(None);
        };

        self.refresh_share_state_tx(&mut tx, &mut share).await?;

        let result = match share.status {
            ShareStatus::Available => {
                let Some(ciphertext) = share.ciphertext.clone() else {
                    tx.commit().await?;
                    return Ok(None);
                };
                let Some(nonce) = share.nonce.clone() else {
                    tx.commit().await?;
                    return Ok(None);
                };

                if share.one_time {
                    let claim_token = Uuid::new_v4().to_string();
                    let claim_expires_at = Utc::now()
                        + ChronoDuration::from_std(self.claim_lease)
                            .unwrap_or_else(|_| ChronoDuration::seconds(60));
                    sqlx::query(
                        r#"
                        UPDATE shares
                        SET state = ?, claim_token_hash = ?, claim_expires_at = ?, updated_at = ?
                        WHERE share_id = ?
                        "#,
                    )
                    .bind(ShareStatus::Claimed.as_str())
                    .bind(hash_token(&claim_token))
                    .bind(claim_expires_at.to_rfc3339())
                    .bind(Utc::now().to_rfc3339())
                    .bind(share_id.to_string())
                    .execute(&mut *tx)
                    .await?;

                    Some(ClaimOutcome {
                        share_id,
                        status: ShareStatus::Claimed,
                        ciphertext,
                        nonce,
                        expires_at: share.expires_at,
                        one_time: true,
                        aad_version: share.aad_version,
                        claim_token: Some(claim_token),
                    })
                } else {
                    Some(ClaimOutcome {
                        share_id,
                        status: ShareStatus::Available,
                        ciphertext,
                        nonce,
                        expires_at: share.expires_at,
                        one_time: false,
                        aad_version: share.aad_version,
                        claim_token: None,
                    })
                }
            }
            ShareStatus::Claimed | ShareStatus::Consumed | ShareStatus::Revoked | ShareStatus::Expired => None,
        };

        tx.commit().await?;
        Ok(result)
    }

    pub async fn consume_share(
        &self,
        share_id: Uuid,
        claim_token: &str,
    ) -> Result<Option<ShareStatus>, AppError> {
        let mut tx = self.pool.begin().await?;
        let Some(mut share) = self.load_share_tx(&mut tx, share_id).await? else {
            tx.commit().await?;
            return Ok(None);
        };
        self.refresh_share_state_tx(&mut tx, &mut share).await?;

        let Some(stored_hash) = share.claim_token_hash.as_deref() else {
            tx.commit().await?;
            return Ok(None);
        };
        let Some(claim_expires_at) = share.claim_expires_at else {
            tx.commit().await?;
            return Ok(None);
        };

        if share.status != ShareStatus::Claimed
            || stored_hash != hash_token(claim_token)
            || claim_expires_at <= Utc::now()
        {
            tx.commit().await?;
            return Ok(None);
        }

        let now = Utc::now();
        sqlx::query(
            r#"
            UPDATE shares
            SET state = ?, ciphertext = NULL, nonce = NULL, claim_token_hash = NULL,
                claim_expires_at = NULL, consumed_at = ?, updated_at = ?
            WHERE share_id = ?
            "#,
        )
        .bind(ShareStatus::Consumed.as_str())
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .bind(share_id.to_string())
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(Some(ShareStatus::Consumed))
    }

    pub async fn revoke_share(
        &self,
        share_id: Uuid,
        admin_token: &str,
    ) -> Result<Option<ShareStatus>, AppError> {
        let mut tx = self.pool.begin().await?;
        let Some(mut share) = self.load_share_tx(&mut tx, share_id).await? else {
            tx.commit().await?;
            return Ok(None);
        };
        self.refresh_share_state_tx(&mut tx, &mut share).await?;

        if share.admin_token_hash != hash_token(admin_token) {
            tx.commit().await?;
            return Ok(None);
        }

        match share.status {
            ShareStatus::Available | ShareStatus::Claimed => {
                let now = Utc::now();
                sqlx::query(
                    r#"
                    UPDATE shares
                    SET state = ?, ciphertext = NULL, nonce = NULL, claim_token_hash = NULL,
                        claim_expires_at = NULL, revoked_at = ?, updated_at = ?
                    WHERE share_id = ?
                    "#,
                )
                .bind(ShareStatus::Revoked.as_str())
                .bind(now.to_rfc3339())
                .bind(now.to_rfc3339())
                .bind(share_id.to_string())
                .execute(&mut *tx)
                .await?;
                tx.commit().await?;
                Ok(Some(ShareStatus::Revoked))
            }
            other => {
                tx.commit().await?;
                Ok(Some(other))
            }
        }
    }

    pub async fn share_status(
        &self,
        share_id: Uuid,
        admin_token: &str,
    ) -> Result<Option<StoredShare>, AppError> {
        let mut tx = self.pool.begin().await?;
        let Some(mut share) = self.load_share_tx(&mut tx, share_id).await? else {
            tx.commit().await?;
            return Ok(None);
        };
        self.refresh_share_state_tx(&mut tx, &mut share).await?;

        if share.admin_token_hash != hash_token(admin_token) {
            tx.commit().await?;
            return Ok(None);
        }

        let refreshed = self
            .load_share_tx(&mut tx, share_id)
            .await?
            .expect("share still present");
        tx.commit().await?;
        Ok(Some(refreshed))
    }

    pub async fn run_cleanup(&self) -> Result<CleanupSummary, AppError> {
        let now = Utc::now();
        let release_result = sqlx::query(
            r#"
            UPDATE shares
            SET state = ?, claim_token_hash = NULL, claim_expires_at = NULL, updated_at = ?
            WHERE state = ? AND claim_expires_at IS NOT NULL AND claim_expires_at <= ?
            "#,
        )
        .bind(ShareStatus::Available.as_str())
        .bind(now.to_rfc3339())
        .bind(ShareStatus::Claimed.as_str())
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await?;

        let expire_result = sqlx::query(
            r#"
            UPDATE shares
            SET state = ?, ciphertext = NULL, nonce = NULL, claim_token_hash = NULL,
                claim_expires_at = NULL, updated_at = ?
            WHERE state IN (?, ?) AND expires_at <= ?
            "#,
        )
        .bind(ShareStatus::Expired.as_str())
        .bind(now.to_rfc3339())
        .bind(ShareStatus::Available.as_str())
        .bind(ShareStatus::Claimed.as_str())
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await?;

        let purge_before = now
            - ChronoDuration::from_std(self.tombstone_retention)
                .unwrap_or_else(|_| ChronoDuration::hours(24));
        let purge_result = sqlx::query(
            r#"
            DELETE FROM shares
            WHERE expires_at <= ? AND state IN (?, ?, ?)
            "#,
        )
        .bind(purge_before.to_rfc3339())
        .bind(ShareStatus::Expired.as_str())
        .bind(ShareStatus::Consumed.as_str())
        .bind(ShareStatus::Revoked.as_str())
        .execute(&self.pool)
        .await?;

        Ok(CleanupSummary {
            expired: expire_result.rows_affected(),
            released_claims: release_result.rows_affected(),
            purged: purge_result.rows_affected(),
        })
    }

    async fn refresh_share_state_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        share: &mut StoredShare,
    ) -> Result<(), AppError> {
        let now = Utc::now();

        if matches!(share.status, ShareStatus::Available | ShareStatus::Claimed)
            && share.expires_at <= now
        {
            sqlx::query(
                r#"
                UPDATE shares
                SET state = ?, ciphertext = NULL, nonce = NULL, claim_token_hash = NULL,
                    claim_expires_at = NULL, updated_at = ?
                WHERE share_id = ?
                "#,
            )
            .bind(ShareStatus::Expired.as_str())
            .bind(now.to_rfc3339())
            .bind(share.share_id.to_string())
            .execute(&mut **tx)
            .await?;
            share.status = ShareStatus::Expired;
            share.ciphertext = None;
            share.nonce = None;
            share.claim_token_hash = None;
            share.claim_expires_at = None;
            share.updated_at = now;
            return Ok(());
        }

        if share.status == ShareStatus::Claimed
            && share
                .claim_expires_at
                .map(|expiry| expiry <= now)
                .unwrap_or(true)
        {
            sqlx::query(
                r#"
                UPDATE shares
                SET state = ?, claim_token_hash = NULL, claim_expires_at = NULL, updated_at = ?
                WHERE share_id = ?
                "#,
            )
            .bind(ShareStatus::Available.as_str())
            .bind(now.to_rfc3339())
            .bind(share.share_id.to_string())
            .execute(&mut **tx)
            .await?;
            share.status = ShareStatus::Available;
            share.claim_token_hash = None;
            share.claim_expires_at = None;
            share.updated_at = now;
        }

        Ok(())
    }

    async fn load_share_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        share_id: Uuid,
    ) -> Result<Option<StoredShare>, AppError> {
        let row = sqlx::query(
            r#"
            SELECT share_id, state, ciphertext, nonce, expires_at, one_time, aad_version,
                   admin_token_hash, claim_token_hash, claim_expires_at, created_at, updated_at,
                   consumed_at, revoked_at
            FROM shares
            WHERE share_id = ?
            "#,
        )
        .bind(share_id.to_string())
        .fetch_optional(&mut **tx)
        .await?;

        row.map(parse_share).transpose()
    }
}

fn parse_share(row: SqliteRow) -> Result<StoredShare, AppError> {
    Ok(StoredShare {
        share_id: Uuid::parse_str(row.get::<&str, _>("share_id"))
            .map_err(|error| AppError::internal(error.to_string()))?,
        status: row
            .get::<String, _>("state")
            .parse()
            .map_err(|error: AppError| error)?,
        ciphertext: row.get("ciphertext"),
        nonce: row.get("nonce"),
        expires_at: parse_rfc3339(&row.get::<String, _>("expires_at"))?,
        one_time: row.get::<i64, _>("one_time") == 1,
        aad_version: row.get::<i64, _>("aad_version") as u32,
        admin_token_hash: row.get("admin_token_hash"),
        claim_token_hash: row.get("claim_token_hash"),
        claim_expires_at: row
            .get::<Option<String>, _>("claim_expires_at")
            .map(|value| parse_rfc3339(&value))
            .transpose()?,
        created_at: parse_rfc3339(&row.get::<String, _>("created_at"))?,
        updated_at: parse_rfc3339(&row.get::<String, _>("updated_at"))?,
        consumed_at: row
            .get::<Option<String>, _>("consumed_at")
            .map(|value| parse_rfc3339(&value))
            .transpose()?,
        revoked_at: row
            .get::<Option<String>, _>("revoked_at")
            .map(|value| parse_rfc3339(&value))
            .transpose()?,
    })
}

fn parse_rfc3339(value: &str) -> Result<DateTime<Utc>, AppError> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|error| AppError::internal(error.to_string()))
}
