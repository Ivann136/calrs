// Pending requests hold their slot, expire, and are re-checked on approval
// (#234). Included into `web::tests`, so it shares that module's helpers.

/// A UTC instant as stored on a version 1 booking.
fn utc_stamp(t: chrono::DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn utc(y: i32, m: u32, d: u32, h: u32, min: u32) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(y, m, d, h, min, 0).unwrap()
}

/// Insert a version 1 (UTC) booking and return its id. `extra` is a list of
/// (column, value) pairs set right after the insert.
async fn insert_v1_booking(
    pool: &SqlitePool,
    et_id: &str,
    email: &str,
    start: chrono::DateTime<Utc>,
    minutes: i64,
    status: &str,
    extra: &[(&str, Option<String>)],
) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO bookings (time_version, id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token, confirm_token)
         VALUES (1, ?, ?, ?, 'Guest', ?, 'UTC', ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(et_id)
    .bind(format!("uid-{id}"))
    .bind(email)
    .bind(utc_stamp(start))
    .bind(utc_stamp(start + Duration::minutes(minutes)))
    .bind(status)
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(format!("confirm-{id}"))
    .execute(pool)
    .await
    .unwrap();
    for (col, value) in extra {
        sqlx::query(&format!("UPDATE bookings SET {col} = ? WHERE id = ?"))
            .bind(value)
            .bind(&id)
            .execute(pool)
            .await
            .unwrap();
    }
    id
}

async fn booking_status(pool: &SqlitePool, id: &str) -> String {
    sqlx::query_scalar("SELECT status FROM bookings WHERE id = ?")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn second_event_type(pool: &SqlitePool, account_id: &str) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO event_types (id, account_id, slug, title, duration_min, buffer_before, buffer_after, min_notice_min, enabled) VALUES (?, ?, 'other-meeting', 'Other Meeting', 30, 0, 0, 0, 1)")
        .bind(&id)
        .bind(account_id)
        .execute(pool)
        .await
        .unwrap();
    id
}

#[test]
fn pending_expiry_deadline_uses_the_expiry_window() {
    let now = utc(2030, 1, 1, 0, 0);
    let start = utc(2030, 1, 10, 10, 0);
    assert_eq!(
        pending_expiry_deadline(now, start, Some(24), 60),
        Some(utc(2030, 1, 2, 0, 0))
    );
}

#[test]
fn pending_expiry_deadline_is_capped_by_the_minimum_notice() {
    let now = utc(2030, 1, 1, 0, 0);
    let start = utc(2030, 1, 1, 10, 0);
    // 24h from now is past the meeting; the latest bookable moment wins.
    assert_eq!(
        pending_expiry_deadline(now, start, Some(24), 60),
        Some(utc(2030, 1, 1, 9, 0))
    );
    // Without a minimum notice the cap is the start itself.
    assert_eq!(
        pending_expiry_deadline(now, start, Some(24), 0),
        Some(start)
    );
}

#[test]
fn pending_expiry_deadline_is_none_when_requests_never_expire() {
    let now = utc(2030, 1, 1, 0, 0);
    let start = utc(2030, 1, 10, 10, 0);
    assert_eq!(pending_expiry_deadline(now, start, None, 60), None);
    assert_eq!(pending_expiry_deadline(now, start, Some(0), 60), None);
}

#[test]
fn pending_expiry_select_values_round_trip() {
    assert_eq!(parse_pending_expiry("24"), Some(24));
    assert_eq!(parse_pending_expiry("never"), None);
    assert_eq!(parse_pending_expiry("5"), None, "only the offered choices");
    assert_eq!(pending_expiry_form_value("72"), "72");
    assert_eq!(pending_expiry_form_value("bogus"), "never");
}

#[tokio::test]
async fn pending_booking_blocks_its_slot_and_overlapping_event_types() {
    let pool = setup_test_db().await;
    let (user_id, account_id, et_id) = seed_test_data(&pool).await;
    let other_et = second_event_type(&pool, &account_id).await;
    sqlx::query("UPDATE event_types SET requires_confirmation = 1 WHERE id = ?")
        .bind(&et_id)
        .execute(&pool)
        .await
        .unwrap();
    // Monday 2030-03-18, 10:00-10:30 UTC.
    insert_v1_booking(
        &pool,
        &et_id,
        "first@test.com",
        utc(2030, 3, 18, 10, 0),
        30,
        "pending",
        &[],
    )
    .await;

    let busy_for = |et: String| {
        let pool = pool.clone();
        let user_id = user_id.clone();
        async move {
            fetch_busy_times_for_user(
                &pool,
                &user_id,
                dt(2030, 3, 18, 0, 0),
                dt(2030, 3, 18, 23, 59),
                Tz::UTC,
                Some(&et),
            )
            .await
        }
    };

    // Same event type: the exact slot is taken.
    let busy = busy_for(et_id.clone()).await;
    assert!(has_conflict(
        &busy,
        dt(2030, 3, 18, 10, 0),
        dt(2030, 3, 18, 10, 30)
    ));
    // Another event type of the same host: an overlapping slot is taken too.
    let busy = busy_for(other_et.clone()).await;
    assert!(has_conflict(
        &busy,
        dt(2030, 3, 18, 10, 15),
        dt(2030, 3, 18, 10, 45)
    ));
    assert!(!has_conflict(
        &busy,
        dt(2030, 3, 18, 10, 30),
        dt(2030, 3, 18, 11, 0)
    ));

    // Opting out on the pending booking's own event type frees the time,
    // whichever event type is asking.
    sqlx::query("UPDATE event_types SET pending_blocks_slot = 0 WHERE id = ?")
        .bind(&et_id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(busy_for(et_id.clone()).await.is_empty());
    assert!(busy_for(other_et).await.is_empty());
}

#[tokio::test]
async fn troubleshoot_labels_a_held_pending_request() {
    let (app, pool, session, et_id) = setup_test_app().await;
    insert_v1_booking(
        &pool,
        &et_id,
        "held@test.com",
        utc(2030, 3, 18, 10, 0),
        30,
        "pending",
        &[],
    )
    .await;
    let response = app
        .oneshot(get_authed(
            "/dashboard/troubleshoot?date=2030-03-18&event_type=test-meeting",
            &session,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = body_string(response).await;
    assert!(body.contains("(pending request)"), "{body}");
}

#[tokio::test]
async fn new_pending_booking_gets_an_expiry_deadline() {
    let (app, pool, _, et_id) = setup_test_app().await;
    sqlx::query(
        "UPDATE event_types SET requires_confirmation = 1, pending_expiry_hours = 24 WHERE id = ?",
    )
    .bind(&et_id)
    .execute(&pool)
    .await
    .unwrap();
    let csrf = "csrf-pending-deadline";
    let body = format!(
        "_csrf={}&date={}&time=10%3A00&name=Pending+Guest&email=deadline%40test.com&tz=UTC",
        csrf,
        far_future_monday()
    );
    let before = Utc::now();
    let response = app
        .oneshot(post_form_unauthed(
            "/u/testuser/test-meeting/book",
            csrf,
            &body,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let (status, expires, since): (String, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT status, pending_expires_at, pending_since FROM bookings WHERE guest_email = 'deadline@test.com'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(status, "pending");
    let expires = chrono::DateTime::parse_from_rfc3339(&expires.unwrap()).unwrap();
    let expected = before + Duration::hours(24);
    assert!((expires.with_timezone(&Utc) - expected).num_seconds().abs() < 120);
    assert!(since.is_some());
}

#[tokio::test]
async fn sweep_declines_expired_requests_once_and_emails_the_guest_in_their_language() {
    let _env = crate::test_support::ENV_LOCK.lock().await;
    let _guard = crate::test_support::EnvGuard::new();
    std::env::set_var("CALRS_BASE_URL", "https://cal.example.com");
    let pool = setup_test_db().await;
    let (_user_id, _account_id, et_id) = seed_test_data(&pool).await;
    sqlx::query("UPDATE event_types SET requires_confirmation = 1 WHERE id = ?")
        .bind(&et_id)
        .execute(&pool)
        .await
        .unwrap();
    let (port, mails) = spawn_capturing_mta().await;
    use_capturing_mta(&pool, port).await;

    let now = Utc::now();
    let start = now + Duration::days(3);
    let past = Some(utc_stamp(now - Duration::minutes(1)));
    let future = Some(utc_stamp(now + Duration::hours(5)));
    let expired = insert_v1_booking(
        &pool,
        &et_id,
        "expired@test.com",
        start,
        30,
        "pending",
        &[
            ("pending_expires_at", past.clone()),
            ("language", Some("fr".into())),
        ],
    )
    .await;
    let waiting = insert_v1_booking(
        &pool,
        &et_id,
        "waiting@test.com",
        start + Duration::hours(1),
        30,
        "pending",
        &[("pending_expires_at", future)],
    )
    .await;
    let never = insert_v1_booking(
        &pool,
        &et_id,
        "never@test.com",
        start + Duration::hours(2),
        30,
        "pending",
        &[],
    )
    .await;
    let confirmed = insert_v1_booking(
        &pool,
        &et_id,
        "confirmed@test.com",
        start + Duration::hours(3),
        30,
        "confirmed",
        &[("pending_expires_at", past)],
    )
    .await;

    let sweep = sweep_pending_requests(&pool, &[0u8; 32], now).await;
    assert_eq!(sweep.expired, 1);
    assert_eq!(booking_status(&pool, &expired).await, "declined");
    assert_eq!(booking_status(&pool, &waiting).await, "pending");
    assert_eq!(booking_status(&pool, &never).await, "pending");
    assert_eq!(booking_status(&pool, &confirmed).await, "confirmed");

    let guest = mail_to(&mails, "expired@test.com").await;
    assert!(guest.contains("Bonjour Guest,"), "{guest}");
    assert!(
        guest.contains("Votre demande de réservation a expiré"),
        "{guest}"
    );
    assert!(
        guest.contains("https://cal.example.com/u/testuser/test-meeting"),
        "the guest gets a link to pick another time: {guest}"
    );
    let host = mail_to(&mails, "test@example.com").await;
    assert!(host.contains("Booking request expired."), "{host}");

    // Idempotent: a second pass finds nothing and sends nothing.
    let sent = mails.lock().unwrap().len();
    let again = sweep_pending_requests(&pool, &[0u8; 32], now).await;
    assert_eq!(again, PendingSweep::default());
    assert_eq!(mails.lock().unwrap().len(), sent);
    assert_eq!(booking_status(&pool, &expired).await, "declined");
}

#[tokio::test]
async fn sweep_nudges_the_host_once_halfway_to_the_deadline() {
    let _env = crate::test_support::ENV_LOCK.lock().await;
    let _guard = crate::test_support::EnvGuard::new();
    let pool = setup_test_db().await;
    let (_user_id, _account_id, et_id) = seed_test_data(&pool).await;
    let (port, mails) = spawn_capturing_mta().await;
    use_capturing_mta(&pool, port).await;

    let now = Utc::now();
    let start = now + Duration::days(3);
    let due = insert_v1_booking(
        &pool,
        &et_id,
        "due@test.com",
        start,
        30,
        "pending",
        &[
            ("pending_since", Some(utc_stamp(now - Duration::hours(10)))),
            (
                "pending_expires_at",
                Some(utc_stamp(now + Duration::hours(2))),
            ),
        ],
    )
    .await;
    let early = insert_v1_booking(
        &pool,
        &et_id,
        "early@test.com",
        start + Duration::hours(1),
        30,
        "pending",
        &[
            ("pending_since", Some(utc_stamp(now - Duration::hours(1)))),
            (
                "pending_expires_at",
                Some(utc_stamp(now + Duration::hours(10))),
            ),
        ],
    )
    .await;

    let sweep = sweep_pending_requests(&pool, &[0u8; 32], now).await;
    assert_eq!(
        sweep,
        PendingSweep {
            expired: 0,
            nudged: 1
        }
    );
    let host = mail_to(&mails, "test@example.com").await;
    assert!(host.contains("is still waiting for your answer"), "{host}");
    assert!(host.contains("due@test.com"), "{host}");

    let sent_at = |id: String| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, Option<String>>(
                "SELECT pending_reminder_sent_at FROM bookings WHERE id = ?",
            )
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };
    assert!(sent_at(due.clone()).await.is_some());
    assert!(sent_at(early).await.is_none());

    let again = sweep_pending_requests(&pool, &[0u8; 32], now).await;
    assert_eq!(again, PendingSweep::default());
    assert_eq!(booking_status(&pool, &due).await, "pending");
}

#[tokio::test]
async fn dashboard_approval_is_refused_when_the_host_became_busy() {
    let (app, pool, session, et_id) = setup_test_app().await;
    let account_id: String = sqlx::query_scalar("SELECT account_id FROM event_types WHERE id = ?")
        .bind(&et_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    let other_et = second_event_type(&pool, &account_id).await;
    let pending = insert_v1_booking(
        &pool,
        &et_id,
        "pending@test.com",
        utc(2030, 3, 18, 10, 0),
        30,
        "pending",
        &[],
    )
    .await;
    // The host took another booking over the same time in the meantime.
    let blocker = insert_v1_booking(
        &pool,
        &other_et,
        "blocker@test.com",
        utc(2030, 3, 18, 10, 15),
        30,
        "confirmed",
        &[],
    )
    .await;

    let csrf = "csrf-approve-busy";
    let response = app
        .clone()
        .oneshot(post_form(
            &format!("/dashboard/bookings/{}/confirm", pending),
            &session,
            csrf,
            &format!("_csrf={}", csrf),
        ))
        .await
        .unwrap();
    assert!(response.status().is_redirection());
    let location = response.headers()["location"].to_str().unwrap().to_string();
    assert_eq!(location, "/dashboard/bookings?error=host-busy");
    assert_eq!(booking_status(&pool, &pending).await, "pending");

    // The dashboard renders the reason, translated.
    let page = app
        .clone()
        .oneshot(get_authed(&location, &session))
        .await
        .unwrap();
    assert!(body_string(page)
        .await
        .contains("is no longer free at this time"));

    // Once the conflict is gone the approval goes through: the pending
    // booking's own hold does not count against itself.
    sqlx::query("UPDATE bookings SET status = 'cancelled' WHERE id = ?")
        .bind(&blocker)
        .execute(&pool)
        .await
        .unwrap();
    let csrf = "csrf-approve-free";
    let response = app
        .oneshot(post_form(
            &format!("/dashboard/bookings/{}/confirm", pending),
            &session,
            csrf,
            &format!("_csrf={}", csrf),
        ))
        .await
        .unwrap();
    assert!(response.status().is_redirection());
    assert_eq!(booking_status(&pool, &pending).await, "confirmed");
}

#[tokio::test]
async fn token_approval_is_refused_when_a_calendar_event_now_overlaps() {
    let (app, pool, _, et_id) = setup_test_app().await;
    let account_id: String = sqlx::query_scalar("SELECT account_id FROM event_types WHERE id = ?")
        .bind(&et_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    let pending = insert_v1_booking(
        &pool,
        &et_id,
        "pending@test.com",
        utc(2030, 3, 18, 10, 0),
        30,
        "pending",
        &[],
    )
    .await;
    seed_synced_event(
        &pool,
        &account_id,
        "20300318T100000",
        "20300318T110000",
        "UTC",
        "OPAQUE",
    )
    .await;

    let response = app
        .oneshot(post_bare(&format!("/booking/approve/confirm-{}", pending)))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body = body_string(response).await;
    assert!(body.contains("is no longer free at this time"), "{body}");
    assert_eq!(booking_status(&pool, &pending).await, "pending");
}

#[tokio::test]
async fn guest_reschedule_back_to_pending_restarts_the_expiry_clock() {
    let (app, pool, _, et_id) = setup_test_app().await;
    sqlx::query(
        "UPDATE event_types SET requires_confirmation = 1, pending_expiry_hours = 24 WHERE id = ?",
    )
    .bind(&et_id)
    .execute(&pool)
    .await
    .unwrap();
    let id = insert_v1_booking(
        &pool,
        &et_id,
        "resched@test.com",
        Utc::now() + Duration::days(2),
        30,
        "pending",
        &[
            ("pending_expires_at", Some("2000-01-01T00:00:00Z".into())),
            (
                "pending_reminder_sent_at",
                Some("2000-01-01T00:00:00Z".into()),
            ),
        ],
    )
    .await;
    let token: String = sqlx::query_scalar("SELECT reschedule_token FROM bookings WHERE id = ?")
        .bind(&id)
        .fetch_one(&pool)
        .await
        .unwrap();

    let csrf = "csrf-resched-pending";
    let before = Utc::now();
    let response = app
        .oneshot(post_form_unauthed(
            &format!("/booking/reschedule/{}", token),
            csrf,
            &format!(
                "_csrf={}&date={}&time=10%3A00&tz=UTC",
                csrf,
                far_future_monday()
            ),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let (status, expires, nudged): (String, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT status, pending_expires_at, pending_reminder_sent_at FROM bookings WHERE id = ?",
    )
    .bind(&id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(status, "pending");
    let expires = chrono::DateTime::parse_from_rfc3339(&expires.unwrap()).unwrap();
    let expected = before + Duration::hours(24);
    assert!(
        (expires.with_timezone(&Utc) - expected).num_seconds().abs() < 120,
        "deadline restarted from the reschedule: {expires}"
    );
    assert!(nudged.is_none(), "a fresh window gets a fresh nudge");
}

#[tokio::test]
async fn event_type_form_persists_the_pending_settings() {
    let (app, pool, session, _) = setup_test_app().await;
    let settings = |slug: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query_as::<_, (i32, Option<i32>)>(
                "SELECT pending_blocks_slot, pending_expiry_hours FROM event_types WHERE slug = ?",
            )
            .bind(slug)
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };
    let base = "title=Held&slug=held&duration_min=30&requires_confirmation=on&location_type=link&location_value=https%3A%2F%2Fmeet.example.com%2Froom&avail_days=1,2,3,4,5&avail_start=09:00&avail_end=17:00";

    // A form without the section gets the defaults.
    let csrf = "csrf-pending-create";
    let response = app
        .clone()
        .oneshot(post_form(
            "/dashboard/event-types/new",
            &session,
            csrf,
            &format!("_csrf={}&{}", csrf, base),
        ))
        .await
        .unwrap();
    assert!(response.status().is_redirection());
    assert_eq!(settings("held").await, (1, Some(24)));

    // Unchecked box and a chosen expiry are stored as such.
    let csrf = "csrf-pending-edit";
    let response = app
        .clone()
        .oneshot(post_form(
            "/dashboard/event-types/held/edit",
            &session,
            csrf,
            &format!("_csrf={}&{}&pending_expiry_hours=48", csrf, base),
        ))
        .await
        .unwrap();
    assert!(response.status().is_redirection());
    assert_eq!(settings("held").await, (0, Some(48)));

    // "never" stores NULL; an edit without the section keeps what is stored.
    let csrf = "csrf-pending-never";
    app.clone()
        .oneshot(post_form(
            "/dashboard/event-types/held/edit",
            &session,
            csrf,
            &format!(
                "_csrf={}&{}&pending_blocks_slot=on&pending_expiry_hours=never",
                csrf, base
            ),
        ))
        .await
        .unwrap();
    assert_eq!(settings("held").await, (1, None));
    let csrf = "csrf-pending-keep";
    app.clone()
        .oneshot(post_form(
            "/dashboard/event-types/held/edit",
            &session,
            csrf,
            &format!("_csrf={}&{}", csrf, base),
        ))
        .await
        .unwrap();
    assert_eq!(settings("held").await, (1, None));

    // The edit form shows them.
    let page = app
        .oneshot(get_authed("/dashboard/event-types/held/edit", &session))
        .await
        .unwrap();
    let body = body_string(page).await;
    assert!(body.contains("id=\"pending-options\""), "{body}");
    assert!(body.contains("<option value=\"never\" selected>"), "{body}");
}

#[tokio::test]
async fn team_event_type_form_persists_the_pending_settings() {
    let (app, pool, session, _) = setup_test_app().await;
    let (team_id, team_et_id) = seed_team_event_type(&pool).await;
    let csrf = "csrf-pending-team";
    let body = format!(
        "_csrf={}&title=Team+Sync&slug=team-sync&duration_min=30&requires_confirmation=on&pending_expiry_hours=4&location_type=link&location_value=https%3A%2F%2Fmeet.example.com%2Froom&avail_days=1,2,3,4,5&avail_start=09:00&avail_end=17:00&scheduling_mode=round_robin",
        csrf
    );
    let response = app
        .oneshot(post_form(
            &format!("/dashboard/group-event-types/{}/team-sync/edit", team_id),
            &session,
            csrf,
            &body,
        ))
        .await
        .unwrap();
    assert!(response.status().is_redirection());
    let stored: (i32, Option<i32>) = sqlx::query_as(
        "SELECT pending_blocks_slot, pending_expiry_hours FROM event_types WHERE id = ?",
    )
    .bind(&team_et_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stored, (0, Some(4)));
}
