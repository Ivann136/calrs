//! Calendar source sync failures (#162).
//!
//! When a source stops syncing, calrs keeps serving availability from the
//! last good copy of its events: refusing every booking because one server
//! blinked would turn a short outage into a hard one. What was missing is
//! the signal. Every sync records its outcome on the source, the calendar
//! sources page shows the error, and the owner is emailed once when the
//! failure persists, again only after a recovery and a new failure.

use sqlx::SqlitePool;

/// Consecutive failed syncs before the owner is emailed.
pub const ALERT_MIN_FAILURES: i64 = 3;

/// How long a source must have been failing before the owner is emailed.
/// With both conditions, a server restart or a network blip that the next
/// syncs ride out never reaches anyone's inbox, while a revoked password or
/// a dead server does within the hour.
pub const ALERT_AFTER_MINUTES: i64 = 60;

/// Record the outcome of one sync attempt of `source_id`. Success clears
/// every trace of earlier failures (and re-arms the alert); a failure is
/// counted and may send the one alert.
pub async fn record_sync_outcome(
    pool: &SqlitePool,
    key: &[u8; 32],
    source_id: &str,
    result: &anyhow::Result<()>,
) {
    match result {
        Ok(()) => {
            let cleared = sqlx::query(
                "UPDATE caldav_sources SET last_sync_error = NULL, last_sync_error_at = NULL, \
                 sync_failing_since = NULL, sync_failure_count = 0, sync_alerted_at = NULL \
                 WHERE id = ? AND sync_failure_count > 0",
            )
            .bind(source_id)
            .execute(pool)
            .await
            .map(|r| r.rows_affected())
            .unwrap_or(0);
            if cleared > 0 {
                tracing::info!(source_id = %source_id, "calendar source recovered");
            }
        }
        Err(e) => record_sync_failure(pool, key, source_id, e).await,
    }
}

/// Record a failed sync attempt, including failures that happen before any
/// request is sent (credentials that no longer decrypt, an OAuth2 token that
/// cannot be refreshed).
pub async fn record_sync_failure(
    pool: &SqlitePool,
    key: &[u8; 32],
    source_id: &str,
    error: &anyhow::Error,
) {
    let message = summarize(&format!("{error:#}"));
    tracing::warn!(source_id = %source_id, error = %message, "calendar source sync failed");
    let _ = sqlx::query(
        "UPDATE caldav_sources SET last_sync_error = ?, last_sync_error_at = datetime('now'), \
         sync_failing_since = COALESCE(sync_failing_since, datetime('now')), \
         sync_failure_count = sync_failure_count + 1 \
         WHERE id = ?",
    )
    .bind(&message)
    .bind(source_id)
    .execute(pool)
    .await;
    alert_owner_once(pool, key, source_id).await;
}

fn summarize(error: &str) -> String {
    if error.chars().count() > 500 {
        let cut: String = error.chars().take(500).collect();
        format!("{cut}...")
    } else {
        error.to_string()
    }
}

/// Email the source's owner when the failure has lasted long enough, once:
/// `sync_alerted_at` is claimed atomically and only cleared on recovery.
/// Left unclaimed while SMTP is not configured.
async fn alert_owner_once(pool: &SqlitePool, key: &[u8; 32], source_id: &str) {
    let due: Option<(i64,)> = sqlx::query_as(
        "SELECT 1 FROM caldav_sources WHERE id = ? AND sync_alerted_at IS NULL \
         AND sync_failure_count >= ? \
         AND sync_failing_since <= datetime('now', ?)",
    )
    .bind(source_id)
    .bind(ALERT_MIN_FAILURES)
    .bind(format!("-{ALERT_AFTER_MINUTES} minutes"))
    .fetch_optional(pool)
    .await
    .unwrap_or(None);
    if due.is_none() {
        return;
    }
    let Ok(Some(smtp)) = crate::email::load_smtp_config(pool, key).await else {
        tracing::warn!(
            source_id = %source_id,
            "calendar source keeps failing and SMTP is unconfigured, so its owner cannot be emailed"
        );
        return;
    };
    let claimed = sqlx::query(
        "UPDATE caldav_sources SET sync_alerted_at = datetime('now') \
         WHERE id = ? AND sync_alerted_at IS NULL",
    )
    .bind(source_id)
    .execute(pool)
    .await
    .map(|r| r.rows_affected() == 1)
    .unwrap_or(false);
    if !claimed {
        return;
    }

    #[allow(clippy::type_complexity)]
    let row: Option<(
        String,
        String,
        Option<String>,
        String,
        Option<String>,
        String,
    )> = sqlx::query_as(
        "SELECT u.name, COALESCE(u.booking_email, u.email), u.language, cs.name, \
                    cs.last_sync_error, COALESCE(cs.sync_failing_since, '') \
             FROM caldav_sources cs \
             JOIN accounts a ON a.id = cs.account_id \
             JOIN users u ON u.id = a.user_id \
             WHERE cs.id = ?",
    )
    .bind(source_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);
    let Some((name, email, language, source_name, error, since)) = row else {
        return;
    };
    let alert = crate::email::SourceSyncFailure {
        owner_name: name,
        owner_email: email,
        language: crate::email::supported_language(language),
        source_name,
        error: error.unwrap_or_default(),
        failing_since: format!("{since} UTC"),
    };
    // Off the request path: on-demand syncs run while a guest waits for a
    // slot page. `drain_emails` lets the CLI wait for it before exiting.
    let source_id = source_id.to_string();
    crate::web::spawn_emails(async move {
        if let Err(e) = crate::email::send_source_sync_failure(&smtp, &alert).await {
            tracing::warn!(source_id = %source_id, error = format!("{e:#}"), "could not email the owner about a failing calendar source");
        }
    });
}
