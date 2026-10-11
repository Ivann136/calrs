//! Calendar write-back failures: record, retry (#162).
//!
//! A confirmed booking whose event did not land on the host's calendar stays
//! confirmed. calrs's own `bookings` table already blocks the slot, and the
//! guest already has the invitation; refusing the booking after the fact
//! would leave the guest with an invite to a meeting that no longer exists.
//! What was missing is the signal: the failure is recorded on the booking,
//! retried from the background loop, and shown to the host.
//!
//! Every write-back goes through [`push_and_record`], whether it comes from a
//! new booking, an approval, a reschedule, a claim or a retry, so the
//! bookkeeping lives in one place.

use chrono::{DateTime, Utc};
use chrono_tz::Tz;
use sqlx::SqlitePool;

/// Minutes to wait before the next attempt, indexed by the number of failed
/// attempts so far minus one. The initial push is attempt 1, so a booking
/// gets up to `RETRY_DELAYS_MIN.len()` retries spread over about 16 hours
/// (5 min, 15 min, 30 min, 1 h, 2 h, 4 h, 8 h) and then stops: a calendar
/// still refusing the event by then needs a human, not another PUT.
pub(super) const RETRY_DELAYS_MIN: [i64; 7] = [5, 15, 30, 60, 120, 240, 480];

/// Total attempts, the initial push included.
pub(super) const MAX_ATTEMPTS: i64 = RETRY_DELAYS_MIN.len() as i64 + 1;

/// Whether this push is the first one for the booking's current state (a
/// new booking, an approval, a reschedule, a claim) or a background retry.
/// A fresh push restarts the retry schedule; a retry continues it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PushKind {
    Fresh,
    Retry,
}

/// SQLite-comparable UTC timestamp, the format `datetime('now')` produces.
fn stamp(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%d %H:%M:%S").to_string()
}

/// When to try again after `attempts` failed attempts, `None` once they are
/// used up.
pub(super) fn next_attempt_at(attempts: i64, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
    let idx = usize::try_from(attempts.checked_sub(1)?).ok()?;
    RETRY_DELAYS_MIN
        .get(idx)
        .map(|m| now + chrono::Duration::minutes(*m))
}

/// The error summary stored on the booking and shown on the dashboard. Long
/// server bodies are cut: the host needs the gist, the log has the rest.
fn summarize(failures: &[(String, String)]) -> String {
    let joined = failures
        .iter()
        .map(|(_, msg)| msg.as_str())
        .collect::<Vec<_>>()
        .join("; ");
    if joined.chars().count() > 500 {
        let cut: String = joined.chars().take(500).collect();
        format!("{cut}...")
    } else {
        joined
    }
}

/// Push a booking to every calendar it belongs to (see
/// `booking_write_targets`) and record the outcome on the booking. Returns
/// the failures as (user id, message), empty on success.
pub(super) async fn push_and_record(
    pool: &SqlitePool,
    key: &[u8; 32],
    user_id: &str,
    booking_uid: &str,
    details: &crate::email::BookingDetails,
    kind: PushKind,
) -> Vec<(String, String)> {
    let mut failures = Vec::new();
    for target in super::booking_write_targets(pool, booking_uid, user_id).await {
        for msg in
            super::caldav_push_booking_for_user(pool, key, &target, booking_uid, details).await
        {
            failures.push((target.clone(), msg));
        }
    }
    record_outcome(pool, booking_uid, &failures, kind, Utc::now()).await;
    failures
}

/// Store the outcome of a write-back attempt. Success clears every trace of
/// earlier failures. A failure counts the attempt and schedules the next
/// one; a fresh push restarts the count. Returns the attempt count.
pub(super) async fn record_outcome(
    pool: &SqlitePool,
    booking_uid: &str,
    failures: &[(String, String)],
    kind: PushKind,
    now: DateTime<Utc>,
) -> i64 {
    if failures.is_empty() {
        let _ = sqlx::query(
            "UPDATE bookings SET writeback_error = NULL, writeback_attempts = 0, \
             writeback_next_attempt_at = NULL, writeback_alerted_at = NULL \
             WHERE uid = ? AND (writeback_error IS NOT NULL OR writeback_attempts > 0)",
        )
        .bind(booking_uid)
        .execute(pool)
        .await;
        return 0;
    }
    let previous: i64 = match kind {
        PushKind::Fresh => 0,
        PushKind::Retry => {
            sqlx::query_scalar("SELECT writeback_attempts FROM bookings WHERE uid = ?")
                .bind(booking_uid)
                .fetch_optional(pool)
                .await
                .ok()
                .flatten()
                .unwrap_or(0)
        }
    };
    let attempts = previous + 1;
    let next = next_attempt_at(attempts, now).map(stamp);
    let summary = summarize(failures);
    tracing::warn!(
        uid = %booking_uid,
        attempts,
        next_attempt_at = next.as_deref().unwrap_or("none"),
        error = %summary,
        "calendar write-back failed; booking stays confirmed"
    );
    let _ = sqlx::query(
        "UPDATE bookings SET writeback_error = ?, writeback_attempts = ?, \
         writeback_next_attempt_at = ? WHERE uid = ?",
    )
    .bind(&summary)
    .bind(attempts)
    .bind(&next)
    .bind(booking_uid)
    .execute(pool)
    .await;
    attempts
}

/// Everything a retry needs to rebuild the event from the booking row: the
/// same fields the original push carried into the ICS. Returns the details
/// and the event type owner (the fallback write target).
pub(super) async fn writeback_details(
    pool: &SqlitePool,
    booking_uid: &str,
) -> Option<(crate::email::BookingDetails, String)> {
    #[allow(clippy::type_complexity)]
    let row: Option<(
        String,
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        String,
        Option<String>,
        Option<i32>,
        Option<String>,
        Option<String>,
        Option<String>,
        String,
    )> = sqlx::query_as(
        "SELECT b.id, b.guest_name, b.guest_email, COALESCE(NULLIF(b.guest_timezone, ''), 'UTC'), \
                CASE b.time_version WHEN 1 THEN b.start_at ELSE rtrim(b.start_at, 'Z') END, \
                CASE b.time_version WHEN 1 THEN b.end_at ELSE rtrim(b.end_at, 'Z') END, \
                u.name, COALESCE(u.booking_email, u.email), \
                COALESCE(NULLIF(b.meeting_url, ''), et.location_value), et.id, b.notes, \
                et.reminder_minutes, b.language, u.language, a.user_id, et.title \
         FROM bookings b \
         JOIN event_types et ON et.id = b.event_type_id \
         LEFT JOIN accounts a ON a.id = et.account_id \
         LEFT JOIN users u ON u.id = COALESCE(b.assigned_user_id, a.user_id) \
         WHERE b.uid = ?",
    )
    .bind(booking_uid)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);
    let (
        booking_id,
        guest_name,
        guest_email,
        guest_timezone,
        start_at,
        end_at,
        host_name,
        host_email,
        location,
        et_id,
        notes,
        reminder_minutes,
        guest_language,
        host_language,
        owner_id,
        event_title,
    ) = row?;

    let stored_tz = super::get_host_tz(pool, &et_id).await;
    let guest_tz = guest_timezone.parse::<Tz>().unwrap_or(Tz::UTC);
    let (date, start_time, end_time) =
        super::booking_strings_in_guest_tz(&start_at, &end_at, stored_tz, guest_tz);
    let additional_attendees: Vec<String> =
        sqlx::query_scalar("SELECT email FROM booking_attendees WHERE booking_id = ?")
            .bind(&booking_id)
            .fetch_all(pool)
            .await
            .unwrap_or_default();

    let details = crate::email::BookingDetails {
        utc_times: crate::booking_time::ics_times(&start_at, &end_at),
        event_title,
        date,
        start_time,
        end_time,
        guest_name,
        guest_email,
        guest_timezone,
        host_name: host_name.unwrap_or_default(),
        host_email: host_email.unwrap_or_default(),
        uid: booking_uid.to_string(),
        notes,
        location: location.filter(|l| !l.is_empty()),
        reminder_minutes,
        additional_attendees,
        guest_language,
        host_language: crate::email::supported_language(host_language),
        host_timezone: stored_tz.name().to_string(),
        ..Default::default()
    };
    Some((details, owner_id.unwrap_or_default()))
}

/// One pass of the retry sweep, run from the background loop: every
/// confirmed booking still ahead whose next attempt is due. Cancelled,
/// declined and past bookings are never retried. Returns how many bookings
/// were attempted.
pub(crate) async fn retry_failed_writebacks(
    pool: &SqlitePool,
    key: &[u8; 32],
    now: DateTime<Utc>,
) -> usize {
    let due: Vec<(String,)> = sqlx::query_as(
        "SELECT uid FROM bookings \
         WHERE status = 'confirmed' \
           AND writeback_next_attempt_at IS NOT NULL \
           AND writeback_next_attempt_at <= ? \
           AND datetime(start_at) > datetime(?) \
         ORDER BY writeback_next_attempt_at \
         LIMIT 20",
    )
    .bind(stamp(now))
    .bind(now.to_rfc3339())
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let mut attempted = 0;
    for (uid,) in &due {
        let Some((details, owner_id)) = writeback_details(pool, uid).await else {
            continue;
        };
        attempted += 1;
        let failures = push_and_record(pool, key, &owner_id, uid, &details, PushKind::Retry).await;
        if failures.is_empty() {
            tracing::info!(uid = %uid, "calendar write-back retry succeeded");
        }

        // The booking may have been cancelled while the PUT was in flight.
        // The cancel path deletes the event only when it saw an href, which
        // this retry may have stored after it looked: clean up here so a
        // retry never leaves a ghost event behind.
        let status: Option<String> =
            sqlx::query_scalar("SELECT status FROM bookings WHERE uid = ?")
                .bind(uid)
                .fetch_optional(pool)
                .await
                .unwrap_or(None);
        if status.as_deref() != Some("confirmed") {
            super::caldav_delete_booking(pool, key, &owner_id, uid).await;
        }
    }
    attempted
}
