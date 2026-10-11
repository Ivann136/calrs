//! Emails and texts sent by the booking flows (#209, #221), via a capturing MTA.

use super::*;

// --- The daily cap stops sending without failing bookings ---

#[tokio::test]
async fn the_daily_cap_counts_todays_messages() {
    let pool = setup_test_db().await;
    assert_eq!(crate::sms::sent_today(&pool).await, 0);

    for i in 0..3 {
        sqlx::query(
            "INSERT INTO sms_usage (id, event, provider, segments, cost, currency) \
                 VALUES (?, 'confirmed', 'sevenio', 1, 0.075, 'EUR')",
        )
        .bind(format!("usage-{}", i))
        .execute(&pool)
        .await
        .unwrap();
    }
    assert_eq!(crate::sms::sent_today(&pool).await, 3);

    let (cost, currency) = crate::sms::cost_today(&pool).await;
    assert!((cost - 0.225).abs() < 1e-9, "cost was {}", cost);
    assert_eq!(currency, "EUR");

    // Yesterday's traffic does not count against today's allowance.
    sqlx::query(
        "INSERT INTO sms_usage (id, sent_at, event, provider) \
             VALUES ('old', datetime('now', '-2 days'), 'reminder', 'sevenio')",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(crate::sms::sent_today(&pool).await, 3);
}

#[tokio::test]
async fn task_tracker_drains_spawned_tasks() {
    static TRACKER: TaskTracker = TaskTracker::new();
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = done.clone();
    TRACKER.spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        flag.store(true, std::sync::atomic::Ordering::SeqCst);
    });
    let left = TRACKER.drain(std::time::Duration::from_secs(5)).await;
    assert_eq!(left, 0);
    assert!(done.load(std::sync::atomic::Ordering::SeqCst));

    // A panicking task still counts as finished.
    TRACKER.spawn(async { panic!("send blew up") });
    assert_eq!(TRACKER.drain(std::time::Duration::from_secs(5)).await, 0);

    // A task that outlives the timeout is reported, not waited on.
    TRACKER.spawn(tokio::time::sleep(std::time::Duration::from_secs(60)));
    let left = TRACKER.drain(std::time::Duration::from_millis(50)).await;
    assert_eq!(left, 1);
}

/// The host's approval-request email carries the guest phone (#231).
#[tokio::test]
async fn approval_request_email_includes_the_guest_phone() {
    let _env = crate::test_support::ENV_LOCK.lock().await;
    let (app, pool, _, et_id) = setup_test_app().await;
    let (port, mails) = spawn_capturing_mta().await;
    use_capturing_mta(&pool, port).await;
    sqlx::query("UPDATE event_types SET sms_phone_mode = 'optional', requires_confirmation = 1 WHERE id = ?")
        .bind(&et_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO sms_config (id, provider, api_secret_enc, sender, default_country_code) \
             VALUES ('cfg', 'sevenio', 'x', 'calrs', '+33')",
    )
    .execute(&pool)
    .await
    .unwrap();

    let base = chrono::Utc::now() + chrono::Duration::days(3);
    let csrf = "test-csrf-231-email";
    let form = format!(
        "_csrf={}&date={}&time=10%3A00&name=Phone+Guest&email=phone-guest%40test.com&notes=&phone=06+12+34+56+78",
        csrf,
        base.format("%Y-%m-%d")
    );
    let response = app
        .oneshot(post_form_unauthed(
            "/u/testuser/test-meeting/book",
            csrf,
            &form,
        ))
        .await
        .unwrap();
    assert!(response.status() == 200 || response.status().is_redirection());

    let mail = mail_to(&mails, "test@example.com").await;
    assert!(mail.contains("+33612345678"), "{mail}");
}

/// The host approving from the dashboard browses in their own language;
/// the guest still gets the confirmation in the language they booked in.
/// Before #209 this path never read `bookings.language` and fell back to
/// English.
#[tokio::test]
async fn dashboard_approval_emails_the_guest_in_the_booking_language() {
    let _env = crate::test_support::ENV_LOCK.lock().await;
    let (app, pool, session, et_id) = setup_test_app().await;
    let (port, mails) = spawn_capturing_mta().await;
    use_capturing_mta(&pool, port).await;
    let booking_id = insert_pending_french_booking(&pool, &et_id, "uid-209-approve").await;

    let csrf = "test-csrf-209-approve";
    let response = app
        .oneshot(post_form(
            &format!("/dashboard/bookings/{}/confirm", booking_id),
            &session,
            csrf,
            &format!("_csrf={}", csrf),
        ))
        .await
        .unwrap();
    assert!(response.status().is_redirection());

    let mail = mail_to(&mails, "guest@test.com").await;
    assert!(mail.contains("Bonjour Guest,"), "{mail}");
    assert!(mail.contains("<html lang=\"fr\">"), "{mail}");
    assert!(!mail.contains("Hi Guest,"), "{mail}");
}

/// A guest cancelling a round-robin booking used to notify the event
/// type owner, who was not hosting it: the host notice now goes to the
/// assigned member, in the member's language, and the cancel page names
/// them too.
#[tokio::test]
async fn guest_cancel_notifies_the_assigned_member_not_the_owner() {
    let _env = crate::test_support::ENV_LOCK.lock().await;
    let (app, pool, _, et_id) = setup_test_app().await;
    let (port, mails) = spawn_capturing_mta().await;
    use_capturing_mta(&pool, port).await;

    let member_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO users (id, email, name, role, auth_provider, username, enabled, language) \
             VALUES (?, 'member@test.com', 'Morgan Member', 'user', 'local', 'morgan', 1, 'fr')",
    )
    .bind(&member_id)
    .execute(&pool)
    .await
    .unwrap();
    let cancel_tok = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token, assigned_user_id, language) VALUES (?, ?, 'uid-rr-gcancel', 'Guest', 'guest@test.com', 'UTC', '2030-07-02T10:00:00', '2030-07-02T10:30:00', 'confirmed', ?, ?, ?, 'en')")
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&et_id)
        .bind(&cancel_tok)
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&member_id)
        .execute(&pool)
        .await
        .unwrap();

    let response = app
        .clone()
        .oneshot(get(&format!("/booking/cancel/{}", cancel_tok)))
        .await
        .unwrap();
    let body = body_string(response).await;
    assert!(body.contains("Morgan Member"), "{body}");
    assert!(!body.contains("Test User"), "{body}");

    let csrf = "test-csrf-rr-gcancel";
    let response = app
        .oneshot(post_form_unauthed(
            &format!("/booking/cancel/{}", cancel_tok),
            csrf,
            &format!("_csrf={}", csrf),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    // Both emails have arrived once these return.
    mail_to(&mails, "guest@test.com").await;
    let host_mail = mail_to(&mails, "member@test.com").await;
    assert!(host_mail.contains("<html lang=\"fr\">"), "{host_mail}");
    let to_owner = mails
        .lock()
        .unwrap()
        .iter()
        .filter(|m| m.rcpt.iter().any(|r| r.contains("test@example.com")))
        .count();
    assert_eq!(to_owner, 0, "the event type owner was not hosting it");
}

/// A webhook SMS gateway on a local port that records each request and
/// accepts it.
async fn spawn_sms_webhook() -> (u16, Arc<std::sync::Mutex<Vec<String>>>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let received = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let sink = received.clone();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let n = sock.read(&mut chunk).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                let text = String::from_utf8_lossy(&buf);
                if let Some(end) = text.find("\r\n\r\n") {
                    let len = text[..end]
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                        })
                        .unwrap_or(0);
                    if buf.len() >= end + 4 + len {
                        break;
                    }
                }
            }
            sink.lock()
                .unwrap()
                .push(String::from_utf8_lossy(&buf).into_owned());
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                .await;
        }
    });

    (port, received)
}

async fn use_sms_webhook(pool: &SqlitePool, port: u16) {
    sqlx::query(
        "INSERT INTO sms_config (id, provider, sender, base_url, default_country_code) \
             VALUES ('cfg', 'webhook', 'calrs', ?, '+33')",
    )
    .bind(format!("http://127.0.0.1:{port}/sms"))
    .execute(pool)
    .await
    .unwrap();
}

/// Two approvals racing (a double click, or the dashboard and the email
/// link together) confirm once: one SMS, one guest email.
#[tokio::test]
async fn concurrent_approvals_notify_the_guest_once() {
    let _env = crate::test_support::ENV_LOCK.lock().await;
    let (app, pool, session, et_id) = setup_test_app().await;
    let (sms_port, received) = spawn_sms_webhook().await;
    use_sms_webhook(&pool, sms_port).await;
    let (mta_port, mails) = spawn_capturing_mta().await;
    use_capturing_mta(&pool, mta_port).await;
    sqlx::query("UPDATE event_types SET sms_phone_mode = 'optional' WHERE id = ?")
        .bind(&et_id)
        .execute(&pool)
        .await
        .unwrap();
    let uid = "uid-double-approve";
    let booking_id = insert_pending_french_booking(&pool, &et_id, uid).await;
    sqlx::query("UPDATE bookings SET guest_phone = '+33612345678' WHERE id = ?")
        .bind(&booking_id)
        .execute(&pool)
        .await
        .unwrap();

    let csrf = "test-csrf-double-approve";
    let dashboard = app.clone().oneshot(post_form(
        &format!("/dashboard/bookings/{}/confirm", booking_id),
        &session,
        csrf,
        &format!("_csrf={}", csrf),
    ));
    let dashboard_again = app.clone().oneshot(post_form(
        &format!("/dashboard/bookings/{}/confirm", booking_id),
        &session,
        csrf,
        &format!("_csrf={}", csrf),
    ));
    let by_token = app.clone().oneshot(post_form_unauthed(
        &format!("/booking/approve/confirm-{uid}"),
        csrf,
        &format!("_csrf={}", csrf),
    ));
    let (a, b, c) = tokio::join!(dashboard, dashboard_again, by_token);
    a.unwrap();
    b.unwrap();
    c.unwrap();

    // The guest confirmation goes out in the background; wait for it.
    let _ = mail_to(&mails, "guest@test.com").await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let guest_mails = mails
        .lock()
        .unwrap()
        .iter()
        .filter(|m| m.rcpt.iter().any(|r| r.contains("guest@test.com")))
        .count();
    assert_eq!(guest_mails, 1, "the guest must be emailed once");
    assert_eq!(
        received.lock().unwrap().len(),
        1,
        "the guest must be texted once"
    );
}

/// Approving from the dashboard emails watcher teams their claim links,
/// as the approve link in the host's email always did.
#[tokio::test]
async fn dashboard_approval_notifies_watchers() {
    let _env = crate::test_support::ENV_LOCK.lock().await;
    let _vars = crate::test_support::EnvGuard::new();
    std::env::set_var("CALRS_BASE_URL", "https://cal.test");
    let (app, pool, session, et_id) = setup_test_app().await;
    let (port, mails) = spawn_capturing_mta().await;
    use_capturing_mta(&pool, port).await;

    let watcher_id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO users (id, email, name, role, auth_provider, username, enabled) VALUES (?, 'watcher@test.com', 'Watcher', 'user', 'local', 'watcher', 1)")
        .bind(&watcher_id)
        .execute(&pool)
        .await
        .unwrap();
    let team_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO teams (id, name, slug, visibility) VALUES (?, 'Sales', 'sales', 'public')",
    )
    .bind(&team_id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO team_members (team_id, user_id, role, source) VALUES (?, ?, 'member', 'direct')")
        .bind(&team_id)
        .bind(&watcher_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO event_type_watchers (event_type_id, team_id) VALUES (?, ?)")
        .bind(&et_id)
        .bind(&team_id)
        .execute(&pool)
        .await
        .unwrap();
    let booking_id = insert_pending_french_booking(&pool, &et_id, "uid-watch-approve").await;

    let csrf = "test-csrf-watch-approve";
    let response = app
        .oneshot(post_form(
            &format!("/dashboard/bookings/{}/confirm", booking_id),
            &session,
            csrf,
            &format!("_csrf={}", csrf),
        ))
        .await
        .unwrap();
    assert!(response.status().is_redirection());

    let tokens: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM booking_claim_tokens WHERE booking_id = ? AND user_id = ?",
    )
    .bind(&booking_id)
    .bind(&watcher_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(tokens.0, 1, "the watcher should get a claim token");
    let mail = mail_to(&mails, "watcher@test.com").await;
    assert!(mail.contains("https://cal.test/booking/claim/"), "{mail}");
}

/// Two declines racing email the guest once.
#[tokio::test]
async fn concurrent_declines_notify_the_guest_once() {
    let _env = crate::test_support::ENV_LOCK.lock().await;
    let (app, pool, session, et_id) = setup_test_app().await;
    let (port, mails) = spawn_capturing_mta().await;
    use_capturing_mta(&pool, port).await;
    let booking_id = insert_pending_french_booking(&pool, &et_id, "uid-double-decline").await;

    let csrf = "test-csrf-double-decline";
    let dashboard = app.clone().oneshot(post_form(
        &format!("/dashboard/bookings/{}/cancel", booking_id),
        &session,
        csrf,
        &format!("_csrf={}", csrf),
    ));
    let dashboard_again = app.clone().oneshot(post_form(
        &format!("/dashboard/bookings/{}/cancel", booking_id),
        &session,
        csrf,
        &format!("_csrf={}", csrf),
    ));
    let by_token = app.clone().oneshot(post_form_unauthed(
        "/booking/decline/confirm-uid-double-decline",
        csrf,
        &format!("_csrf={}", csrf),
    ));
    let (a, b, c) = tokio::join!(dashboard, dashboard_again, by_token);
    a.unwrap();
    b.unwrap();
    c.unwrap();

    let _ = mail_to(&mails, "guest@test.com").await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let guest_mails = mails
        .lock()
        .unwrap()
        .iter()
        .filter(|m| m.rcpt.iter().any(|r| r.contains("guest@test.com")))
        .count();
    assert_eq!(guest_mails, 1, "the guest must be emailed once");
    let status: (String,) = sqlx::query_as("SELECT status FROM bookings WHERE id = ?")
        .bind(&booking_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status.0, "declined");
}

/// Approving from the dashboard sends the guest the confirmation SMS, like
/// the approve link in the host's email always did.
#[tokio::test]
async fn dashboard_approval_texts_the_guest() {
    let _env = crate::test_support::ENV_LOCK.lock().await;
    let (app, pool, session, et_id) = setup_test_app().await;

    let (port, received) = spawn_sms_webhook().await;
    use_sms_webhook(&pool, port).await;
    sqlx::query("UPDATE event_types SET sms_phone_mode = 'optional' WHERE id = ?")
        .bind(&et_id)
        .execute(&pool)
        .await
        .unwrap();
    let booking_id = insert_pending_french_booking(&pool, &et_id, "uid-sms-approve").await;
    sqlx::query("UPDATE bookings SET guest_phone = '+33612345678' WHERE id = ?")
        .bind(&booking_id)
        .execute(&pool)
        .await
        .unwrap();

    let csrf = "test-csrf-sms-approve";
    let response = app
        .oneshot(post_form(
            &format!("/dashboard/bookings/{}/confirm", booking_id),
            &session,
            csrf,
            &format!("_csrf={}", csrf),
        ))
        .await
        .unwrap();
    assert!(response.status().is_redirection());

    let requests = received.lock().unwrap().clone();
    assert_eq!(requests.len(), 1, "expected one SMS: {requests:?}");
    assert!(requests[0].contains("+33612345678"), "{}", requests[0]);
    let usage: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sms_usage")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(usage.0, 1, "the accepted SMS should be recorded");
}

/// Same for the decline link in the host's approval email.
#[tokio::test]
async fn token_decline_emails_the_guest_in_the_booking_language() {
    let _env = crate::test_support::ENV_LOCK.lock().await;
    let (app, pool, _, et_id) = setup_test_app().await;
    let (port, mails) = spawn_capturing_mta().await;
    use_capturing_mta(&pool, port).await;
    insert_pending_french_booking(&pool, &et_id, "uid-209-decline").await;

    let csrf = "test-csrf-209-decline";
    let response = app
        .oneshot(post_form_unauthed(
            "/booking/decline/confirm-uid-209-decline",
            csrf,
            &format!("_csrf={}&reason=Conflit", csrf),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let mail = mail_to(&mails, "guest@test.com").await;
    assert!(mail.contains("Bonjour Guest,"), "{mail}");
    assert!(
        mail.contains("Cette réservation a été refusée par l'hôte."),
        "{mail}"
    );
    assert!(mail.contains("<html lang=\"fr\">"), "{mail}");
    assert!(!mail.contains("has been declined"), "{mail}");
}

/// The guest's confirmation goes out under the host's name in the
/// guest's language, on the instance address, with Reply-To pointing at
/// the host's booking address.
#[tokio::test]
async fn guest_confirmation_comes_from_the_host() {
    let _env = crate::test_support::ENV_LOCK.lock().await;
    let (app, pool, session, et_id) = setup_test_app().await;
    let (port, mails) = spawn_capturing_mta().await;
    use_capturing_mta(&pool, port).await;
    sqlx::query("UPDATE smtp_config SET from_name = 'Acme Scheduling'")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE users SET booking_email = 'bookings@example.com' WHERE email = 'test@example.com'",
    )
    .execute(&pool)
    .await
    .unwrap();
    let booking_id = insert_pending_french_booking(&pool, &et_id, "uid-221-approve").await;

    let csrf = "test-csrf-221-approve";
    let response = app
        .oneshot(post_form(
            &format!("/dashboard/bookings/{}/confirm", booking_id),
            &session,
            csrf,
            &format!("_csrf={}", csrf),
        ))
        .await
        .unwrap();
    assert!(response.status().is_redirection());

    let mail = mail_to(&mails, "guest@test.com").await;
    assert_eq!(
        mail_header(&mail, "From"),
        Some("\"Test User via Acme Scheduling\" <noreply@test.com>"),
        "{mail}"
    );
    assert_eq!(
        mail_header(&mail, "Reply-To"),
        Some("bookings@example.com"),
        "{mail}"
    );
}

/// A guest cancelling a booking assigned to a member other than the
/// event type's owner hears back from that member, not the owner, while
/// the host-side notice keeps the instance sender and no Reply-To.
#[tokio::test]
async fn guest_cancellation_comes_from_the_assigned_host() {
    let _env = crate::test_support::ENV_LOCK.lock().await;
    let (app, pool, _, et_id) = setup_test_app().await;
    let (port, mails) = spawn_capturing_mta().await;
    use_capturing_mta(&pool, port).await;

    let bob_id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO users (id, email, name, role, auth_provider, username, enabled, booking_email) VALUES (?, 'bob@test.com', 'Bob Member', 'user', 'local', 'bob', 1, 'bob.bookings@test.com')")
        .bind(&bob_id)
        .execute(&pool)
        .await
        .unwrap();
    let booking_id = insert_pending_french_booking(&pool, &et_id, "uid-221-cancel").await;
    sqlx::query("UPDATE bookings SET status = 'confirmed', assigned_user_id = ?, cancel_token = 'cancel-221', start_at = '2099-06-15T10:00:00', end_at = '2099-06-15T10:30:00' WHERE id = ?")
        .bind(&bob_id)
        .bind(&booking_id)
        .execute(&pool)
        .await
        .unwrap();

    let csrf = "test-csrf-221-cancel";
    let response = app
        .oneshot(post_form_unauthed(
            "/booking/cancel/cancel-221",
            csrf,
            &format!("_csrf={}", csrf),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let mail = mail_to(&mails, "guest@test.com").await;
    assert_eq!(
        mail_header(&mail, "From"),
        Some("\"Bob Member\" <noreply@test.com>"),
        "{mail}"
    );
    assert_eq!(
        mail_header(&mail, "Reply-To"),
        Some("bob.bookings@test.com"),
        "{mail}"
    );

    // The host notice goes to Bob too, not to the owner.
    let host_mail = mail_to(&mails, "bob.bookings@test.com").await;
    assert_eq!(
        mail_header(&host_mail, "From"),
        Some("noreply@test.com"),
        "{host_mail}"
    );
    assert_eq!(mail_header(&host_mail, "Reply-To"), None, "{host_mail}");
}

/// The host reads the new-booking email in their saved language, the
/// guest in the one they booked in. The legacy route takes the page
/// language from `Accept-Language` alone, so the two differ here.
#[tokio::test]
async fn new_booking_emails_the_host_in_their_saved_language() {
    let _env = crate::test_support::ENV_LOCK.lock().await;
    let (app, pool, _, _) = setup_test_app().await;
    let (port, mails) = spawn_capturing_mta().await;
    use_capturing_mta(&pool, port).await;
    set_user_language(&pool, "test@example.com", "fr").await;

    let csrf = "csrf-209-host-lang";
    let response = app
        .oneshot(post_form_unauthed(
            "/test-meeting/book",
            csrf,
            &book_body(csrf),
        ))
        .await
        .unwrap();
    assert!(response.status() == 200 || response.status().is_redirection());

    let host = mail_to(&mails, "test@example.com").await;
    assert!(host.contains("Nouvelle réservation !"), "{host}");
    assert!(
        host.contains("Guest a réservé un créneau avec vous."),
        "{host}"
    );
    assert!(host.contains("<html lang=\"fr\">"), "{host}");
    assert!(!host.contains("booked a slot"), "{host}");

    let guest = mail_to(&mails, "guest@test.com").await;
    assert!(guest.contains("Hi Guest,"), "{guest}");
    assert!(guest.contains("<html lang=\"en\">"), "{guest}");
    assert!(!guest.contains("Bonjour"), "{guest}");
}

/// Collective team bookings email every member, each in their own
/// language.
#[tokio::test]
async fn collective_booking_emails_each_member_in_their_language() {
    let _env = crate::test_support::ENV_LOCK.lock().await;
    let (app, pool, _, _) = setup_test_app().await;
    let (port, mails) = spawn_capturing_mta().await;
    use_capturing_mta(&pool, port).await;
    let (team_id, team_et_id) = seed_team_event_type(&pool).await;
    sqlx::query("UPDATE event_types SET scheduling_mode = 'collective' WHERE id = ?")
        .bind(&team_et_id)
        .execute(&pool)
        .await
        .unwrap();
    let bob = insert_role_user(&pool, "bob@test.com", "user").await;
    sqlx::query("INSERT INTO team_members (team_id, user_id, role, source) VALUES (?, ?, 'member', 'direct')")
        .bind(&team_id)
        .bind(&bob)
        .execute(&pool)
        .await
        .unwrap();
    // insert_role_user names users after their address, which is not a
    // valid display name in a To: header.
    sqlx::query("UPDATE users SET name = 'Bob' WHERE id = ?")
        .bind(&bob)
        .execute(&pool)
        .await
        .unwrap();
    set_user_language(&pool, "test@example.com", "fr").await;
    set_user_language(&pool, "bob@test.com", "de").await;

    let csrf = "csrf-209-collective";
    let response = app
        .oneshot(post_form_unauthed(
            "/team/horizon-team/team-sync/book",
            csrf,
            &book_body(csrf),
        ))
        .await
        .unwrap();
    assert!(response.status() == 200 || response.status().is_redirection());

    let alice = mail_to(&mails, "test@example.com").await;
    assert!(alice.contains("Nouvelle réservation !"), "{alice}");
    assert!(alice.contains("<html lang=\"fr\">"), "{alice}");
    let bob_mail = mail_to(&mails, "bob@test.com").await;
    assert!(bob_mail.contains("Neue Buchung!"), "{bob_mail}");
    assert!(bob_mail.contains("<html lang=\"de\">"), "{bob_mail}");
    assert!(!bob_mail.contains("Nouvelle"), "{bob_mail}");
}

/// A guest rescheduling from a browser in another language still gets
/// the update in the language stored with the booking; the host gets
/// theirs in their own.
#[tokio::test]
async fn reschedule_emails_follow_the_booking_and_host_languages() {
    let _env = crate::test_support::ENV_LOCK.lock().await;
    let (app, pool, _, et_id) = setup_test_app().await;
    let (port, mails) = spawn_capturing_mta().await;
    use_capturing_mta(&pool, port).await;
    set_user_language(&pool, "test@example.com", "de").await;
    let cancel_tok = uuid::Uuid::new_v4().to_string();
    let resched_tok = uuid::Uuid::new_v4().to_string();
    let booking_id = insert_booking_at(
        &pool,
        &et_id,
        &cancel_tok,
        &resched_tok,
        chrono::Duration::hours(48),
    )
    .await;
    sqlx::query("UPDATE bookings SET language = 'fr' WHERE id = ?")
        .bind(&booking_id)
        .execute(&pool)
        .await
        .unwrap();

    let csrf = "csrf-209-resched";
    let body = format!(
        "_csrf={}&date={}&time=10:00&tz=UTC",
        csrf,
        far_future_monday()
    );
    let response = app
        .oneshot(post_form_unauthed(
            &format!("/booking/reschedule/{}", resched_tok),
            csrf,
            &body,
        ))
        .await
        .unwrap();
    assert!(response.status() == 200 || response.status().is_redirection());

    let guest = mail_to(&mails, "guest@test.com").await;
    assert!(
        guest.contains("Votre réservation a été reprogrammée par"),
        "{guest}"
    );
    assert!(guest.contains("<html lang=\"fr\">"), "{guest}");
    assert!(!guest.contains("has been rescheduled"), "{guest}");

    let host = mail_to(&mails, "test@example.com").await;
    assert!(host.contains("Buchung bestätigt"), "{host}");
    assert!(host.contains("<html lang=\"de\">"), "{host}");
}

/// Watchers get the claim offer in their own saved language.
#[tokio::test]
async fn watcher_claim_email_is_in_the_watcher_language() {
    let _env = crate::test_support::ENV_LOCK.lock().await;
    let _vars = crate::test_support::EnvGuard::new();
    std::env::set_var("CALRS_BASE_URL", "https://cal.test");
    let (app, pool, session, et_id) = setup_test_app().await;
    let (port, mails) = spawn_capturing_mta().await;
    use_capturing_mta(&pool, port).await;

    let watcher_id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO users (id, email, name, role, auth_provider, username, enabled, language) VALUES (?, 'watcher@test.com', 'Watcher', 'user', 'local', 'watcher', 1, 'de')")
        .bind(&watcher_id)
        .execute(&pool)
        .await
        .unwrap();
    let team_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO teams (id, name, slug, visibility) VALUES (?, 'Sales', 'sales', 'public')",
    )
    .bind(&team_id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO team_members (team_id, user_id, role, source) VALUES (?, ?, 'member', 'direct')")
        .bind(&team_id)
        .bind(&watcher_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO event_type_watchers (event_type_id, team_id) VALUES (?, ?)")
        .bind(&et_id)
        .bind(&team_id)
        .execute(&pool)
        .await
        .unwrap();
    let booking_id = insert_pending_french_booking(&pool, &et_id, "uid-209-watch").await;

    let csrf = "test-csrf-209-watch";
    let response = app
        .oneshot(post_form(
            &format!("/dashboard/bookings/{}/confirm", booking_id),
            &session,
            csrf,
            &format!("_csrf={}", csrf),
        ))
        .await
        .unwrap();
    assert!(response.status().is_redirection());

    let mail = mail_to(&mails, "watcher@test.com").await;
    assert!(mail.contains("Hallo Watcher,"), "{mail}");
    assert!(mail.contains("<html lang=\"de\">"), "{mail}");
    assert!(mail.contains("Diese Buchung übernehmen"), "{mail}");
    assert!(!mail.contains("available to claim"), "{mail}");
}

/// Host language is looked up by user id, never by address: here the
/// host's booking address is another user's login email, and the email
/// must still follow the host's own saved language.
#[tokio::test]
async fn host_language_follows_the_host_not_a_user_sharing_the_address() {
    let _env = crate::test_support::ENV_LOCK.lock().await;
    let (app, pool, session, et_id) = setup_test_app().await;
    let (port, mails) = spawn_capturing_mta().await;
    use_capturing_mta(&pool, port).await;
    sqlx::query(
        "UPDATE users SET booking_email = 'carol@test.com', language = 'fr' WHERE email = 'test@example.com'",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO users (id, email, name, role, auth_provider, username, enabled, language) VALUES (?, 'carol@test.com', 'Carol', 'user', 'local', 'carol', 1, 'de')")
        .bind(uuid::Uuid::new_v4().to_string())
        .execute(&pool)
        .await
        .unwrap();
    let booking_id = insert_pending_french_booking(&pool, &et_id, "uid-209-shared-address").await;

    let csrf = "test-csrf-209-shared";
    let response = app
        .oneshot(post_form(
            &format!("/dashboard/bookings/{}/confirm", booking_id),
            &session,
            csrf,
            &format!("_csrf={}", csrf),
        ))
        .await
        .unwrap();
    assert!(response.status().is_redirection());

    let host = mail_to(&mails, "carol@test.com").await;
    assert!(host.contains("Réservation confirmée"), "{host}");
    assert!(host.contains("<html lang=\"fr\">"), "{host}");
    assert!(!host.contains("Buchung"), "{host}");
}

/// A guest who booked in French and cancels from an English browser sees
/// the cancel page in French and is told in French: the stored booking
/// language, like every guest email.
#[tokio::test]
async fn guest_cancel_emails_in_the_booking_language() {
    let _env = crate::test_support::ENV_LOCK.lock().await;
    let (app, pool, _, et_id) = setup_test_app().await;
    let (port, mails) = spawn_capturing_mta().await;
    use_capturing_mta(&pool, port).await;
    let cancel_tok = uuid::Uuid::new_v4().to_string();
    let resched_tok = uuid::Uuid::new_v4().to_string();
    let booking_id = insert_booking_at(
        &pool,
        &et_id,
        &cancel_tok,
        &resched_tok,
        chrono::Duration::hours(48),
    )
    .await;
    sqlx::query("UPDATE bookings SET language = 'fr' WHERE id = ?")
        .bind(&booking_id)
        .execute(&pool)
        .await
        .unwrap();

    let page = body_string(
        app.clone()
            .oneshot(get_with_language(
                &format!("/booking/cancel/{}", cancel_tok),
                "en-US,en;q=0.9",
            ))
            .await
            .unwrap(),
    )
    .await;
    assert!(page.contains("<html lang=\"fr\">"), "{page}");

    let csrf = "csrf-cancel-lang";
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/booking/cancel/{}", cancel_tok))
                .header("cookie", format!("__Host-calrs_csrf={}", csrf))
                .header("accept-language", "en-US,en;q=0.9")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!("_csrf={}", csrf)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let done = body_string(response).await;
    assert!(done.contains("<html lang=\"fr\">"), "{done}");

    let guest = mail_to(&mails, "guest@test.com").await;
    assert!(guest.contains("Bonjour Guest,"), "{guest}");
    assert!(guest.contains("<html lang=\"fr\">"), "{guest}");
    assert!(!guest.contains("Hi Guest"), "{guest}");
}
