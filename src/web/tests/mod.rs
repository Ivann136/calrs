//! Tests for the web module. Shared fixtures and router helpers live
//! here; each child module covers one area and reaches them, and every
//! item of `web`, through `use super::*`.

use super::*;

mod admin;
mod auth_pages;
mod availability;
mod booking;
mod booking_actions;
mod booking_time;
mod branding;
mod dashboard;
mod event_types;
mod format;
mod hosts;
mod invites;
mod organizer;
mod pending_hold;
mod public_pages;
mod resources;
mod security;
mod sources;
mod writeback_failures;

// --- has_conflict tests ---

fn dt(y: i32, m: u32, d: u32, h: u32, mi: u32) -> NaiveDateTime {
    NaiveDate::from_ymd_opt(y, m, d)
        .unwrap()
        .and_hms_opt(h, mi, 0)
        .unwrap()
}

// --- Integration tests with in-memory SQLite ---

async fn setup_test_db() -> SqlitePool {
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::str::FromStr;
    let pool = SqlitePoolOptions::new()
        .max_connections(2)
        .connect_with(
            SqliteConnectOptions::from_str("sqlite::memory:")
                .unwrap()
                .foreign_keys(true),
        )
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    pool
}

/// Insert test fixtures: user, account, event type, availability rules
async fn seed_test_data(pool: &SqlitePool) -> (String, String, String) {
    let user_id = uuid::Uuid::new_v4().to_string();
    let account_id = uuid::Uuid::new_v4().to_string();
    let et_id = uuid::Uuid::new_v4().to_string();

    sqlx::query("INSERT INTO users (id, email, name, role, auth_provider, username, enabled) VALUES (?, 'test@example.com', 'Test User', 'admin', 'local', 'testuser', 1)")
        .bind(&user_id)
        .execute(pool).await.unwrap();

    sqlx::query("INSERT INTO accounts (id, name, email, timezone, user_id) VALUES (?, 'Test User', 'test@example.com', 'UTC', ?)")
        .bind(&account_id)
        .bind(&user_id)
        .execute(pool).await.unwrap();

    sqlx::query("INSERT INTO event_types (id, account_id, slug, title, duration_min, buffer_before, buffer_after, min_notice_min, enabled) VALUES (?, ?, 'test-meeting', 'Test Meeting', 30, 0, 0, 0, 1)")
        .bind(&et_id)
        .bind(&account_id)
        .execute(pool).await.unwrap();

    // Mon-Fri 09:00-17:00
    for day in [1, 2, 3, 4, 5] {
        let rule_id = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO availability_rules (id, event_type_id, day_of_week, start_time, end_time) VALUES (?, ?, ?, '09:00', '17:00')")
            .bind(&rule_id)
            .bind(&et_id)
            .bind(day)
            .execute(pool).await.unwrap();
    }

    (user_id, account_id, et_id)
}

// --- Authorization helpers: can_manage_event_type / find_manageable_event_type_by_slug ---

/// Insert a user with a configurable role. Returns user_id.
async fn insert_role_user(pool: &SqlitePool, email: &str, role: &str) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    let username = email.split('@').next().unwrap_or("u").to_string();
    sqlx::query(
        "INSERT INTO users (id, email, name, role, auth_provider, username, enabled) \
             VALUES (?, ?, ?, ?, 'local', ?, 1)",
    )
    .bind(&id)
    .bind(email)
    .bind(email)
    .bind(role)
    .bind(&username)
    .execute(pool)
    .await
    .unwrap();
    id
}

/// Insert a personal event type owned by `user_id`. Creates the account row
/// if missing. Returns event_type_id.
async fn insert_personal_et(pool: &SqlitePool, user_id: &str, slug: &str) -> String {
    let account_id: Option<String> =
        sqlx::query_scalar("SELECT id FROM accounts WHERE user_id = ?")
            .bind(user_id)
            .fetch_optional(pool)
            .await
            .unwrap();
    let account_id = match account_id {
        Some(id) => id,
        None => {
            let id = uuid::Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO accounts (id, name, email, timezone, user_id) \
                     VALUES (?, 'A', 'a@x', 'UTC', ?)",
            )
            .bind(&id)
            .bind(user_id)
            .execute(pool)
            .await
            .unwrap();
            id
        }
    };
    let et_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO event_types (id, account_id, slug, title, duration_min, buffer_before, buffer_after, min_notice_min, enabled) \
             VALUES (?, ?, ?, 'P', 30, 0, 0, 0, 1)",
    )
    .bind(&et_id)
    .bind(&account_id)
    .bind(slug)
    .execute(pool)
    .await
    .unwrap();
    et_id
}

/// Insert a team and a team event type. `members` is a list of (user_id, role).
/// Returns (team_id, event_type_id).
async fn insert_team_with_et(
    pool: &SqlitePool,
    team_slug: &str,
    et_slug: &str,
    members: &[(&str, &str)],
) -> (String, String) {
    let team_id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO teams (id, name, slug, visibility) VALUES (?, ?, ?, 'public')")
        .bind(&team_id)
        .bind(team_slug)
        .bind(team_slug)
        .execute(pool)
        .await
        .unwrap();
    for (uid, role) in members {
        sqlx::query(
            "INSERT INTO team_members (team_id, user_id, role, source) \
                 VALUES (?, ?, ?, 'direct')",
        )
        .bind(&team_id)
        .bind(uid)
        .bind(role)
        .execute(pool)
        .await
        .unwrap();
    }
    // Each team event gets its own placeholder account to avoid colliding
    // with personal events under the unique(account_id, slug) constraint.
    let account_id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO accounts (id, name, email, timezone) VALUES (?, 't', 't@x', 'UTC')")
        .bind(&account_id)
        .execute(pool)
        .await
        .unwrap();
    let et_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO event_types (id, account_id, team_id, slug, title, duration_min, buffer_before, buffer_after, min_notice_min, enabled) \
             VALUES (?, ?, ?, ?, 'T', 30, 0, 0, 0, 1)",
    )
    .bind(&et_id)
    .bind(&account_id)
    .bind(&team_id)
    .bind(et_slug)
    .execute(pool)
    .await
    .unwrap();
    (team_id, et_id)
}

/// Seed a CalDAV source + busy calendar + one synced event under `account_id`.
/// `start_at`/`end_at` are compact iCal strings (e.g. "20260618T100000").
async fn seed_synced_event(
    pool: &SqlitePool,
    account_id: &str,
    start_at: &str,
    end_at: &str,
    timezone: &str,
    transp: &str,
) {
    let source_id = uuid::Uuid::new_v4().to_string();
    let cal_id = uuid::Uuid::new_v4().to_string();
    let event_id = uuid::Uuid::new_v4().to_string();
    let uid = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO caldav_sources (id, account_id, name, url, username) VALUES (?, ?, 'Src', 'https://x/dav', 'u')")
        .bind(&source_id).bind(account_id).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO calendars (id, source_id, href, display_name, is_busy) VALUES (?, ?, '/cal/', 'Cal', 1)")
        .bind(&cal_id).bind(&source_id).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO events (id, calendar_id, uid, summary, start_at, end_at, all_day, timezone, status, transp) VALUES (?, ?, ?, 'Busy', ?, ?, 0, ?, 'CONFIRMED', ?)")
        .bind(&event_id).bind(&cal_id).bind(&uid).bind(start_at).bind(end_at).bind(timezone).bind(transp)
        .execute(pool).await.unwrap();
}

async fn insert_booking(
    pool: &SqlitePool,
    et_id: &str,
    assigned_user_id: Option<&str>,
    start: NaiveDateTime,
    status: &str,
) {
    let end = start + Duration::minutes(30);
    sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token, assigned_user_id) VALUES (?, ?, ?, 'G', 'g@e.com', 'UTC', ?, ?, ?, ?, ?, ?)")
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(et_id)
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(start.format("%Y-%m-%dT%H:%M:%S").to_string())
        .bind(end.format("%Y-%m-%dT%H:%M:%S").to_string())
        .bind(status)
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(assigned_user_id)
        .execute(pool).await.unwrap();
}

// --- Shared bookable resources tests ---

/// Insert a resource with a fresh last_synced_at so sync_if_stale never
/// tries to fetch the feed over the network during tests.
async fn insert_resource(pool: &SqlitePool, name: &str) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO resources (id, name, feed_url, last_synced_at) \
             VALUES (?, ?, 'https://feed.invalid/cal.ics', datetime('now'))",
    )
    .bind(&id)
    .bind(name)
    .execute(pool)
    .await
    .unwrap();
    id
}

async fn attach_resource(pool: &SqlitePool, et_id: &str, resource_id: &str) {
    sqlx::query("INSERT INTO event_type_resources (event_type_id, resource_id) VALUES (?, ?)")
        .bind(et_id)
        .bind(resource_id)
        .execute(pool)
        .await
        .unwrap();
}

// --- Reschedule DB flow tests ---

/// Helper to insert a confirmed booking and return (booking_id, reschedule_token, cancel_token)
async fn insert_test_booking(
    pool: &SqlitePool,
    et_id: &str,
    start: &str,
    end: &str,
    status: &str,
) -> (String, String, String) {
    let booking_id = uuid::Uuid::new_v4().to_string();
    let cancel_token = uuid::Uuid::new_v4().to_string();
    let reschedule_token = uuid::Uuid::new_v4().to_string();
    let confirm_token = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token, confirm_token) VALUES (?, ?, ?, 'Guest', 'guest@example.com', 'UTC', ?, ?, ?, ?, ?, ?)"
    )
    .bind(&booking_id)
    .bind(et_id)
    .bind(format!("{}@calrs", uuid::Uuid::new_v4()))
    .bind(start)
    .bind(end)
    .bind(status)
    .bind(&cancel_token)
    .bind(&reschedule_token)
    .bind(&confirm_token)
    .execute(pool).await.unwrap();
    (booking_id, reschedule_token, cancel_token)
}

// --- HTTP integration tests ---

use axum::body::Body;
use http_body_util::BodyExt;
use tower::ServiceExt;

async fn setup_test_app() -> (Router, SqlitePool, String, String) {
    let pool = setup_test_db().await;
    let (user_id, _account_id, et_id) = seed_test_data(&pool).await;

    // Create a session for the test user
    let session_token = uuid::Uuid::new_v4().to_string();
    let expires_at = (Utc::now() + Duration::days(30))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    sqlx::query("INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)")
        .bind(&session_token)
        .bind(&user_id)
        .bind(&expires_at)
        .execute(&pool)
        .await
        .unwrap();

    let data_dir = std::env::temp_dir().join(format!("calrs_test_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&data_dir).unwrap();

    let router = create_router(pool.clone(), data_dir, [0u8; 32]).await;
    (router, pool, session_token, et_id)
}

async fn insert_test_user_with_session(
    pool: &SqlitePool,
    name: &str,
    email: &str,
    username: &str,
) -> (String, String) {
    let user_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO users (id, email, name, role, auth_provider, username, enabled) \
             VALUES (?, ?, ?, 'user', 'local', ?, 1)",
    )
    .bind(&user_id)
    .bind(email)
    .bind(name)
    .bind(username)
    .execute(pool)
    .await
    .unwrap();

    let session_token = uuid::Uuid::new_v4().to_string();
    let expires_at = (Utc::now() + Duration::days(30))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    sqlx::query("INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)")
        .bind(&session_token)
        .bind(&user_id)
        .bind(&expires_at)
        .execute(pool)
        .await
        .unwrap();

    (user_id, session_token)
}

fn get(uri: &str) -> axum::http::Request<Body> {
    axum::http::Request::builder()
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

fn get_authed(uri: &str, session: &str) -> axum::http::Request<Body> {
    axum::http::Request::builder()
        .uri(uri)
        .header("cookie", format!("__Host-calrs_session={}", session))
        .body(Body::empty())
        .unwrap()
}

fn booking_form_uri(invite: Option<&str>) -> String {
    let date = (Utc::now() + Duration::days(1)).format("%Y-%m-%d");
    let invite = invite
        .map(|token| format!("&invite={token}"))
        .unwrap_or_default();
    format!("/u/testuser/test-meeting/book?date={date}&time=10:00{invite}")
}

async fn body_string(response: axum::http::Response<Body>) -> String {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

// --- POST handler helpers ---

fn post_form(uri: &str, session: &str, csrf: &str, body: &str) -> axum::http::Request<Body> {
    axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header(
            "cookie",
            format!(
                "__Host-calrs_session={}; __Host-calrs_csrf={}",
                session, csrf
            ),
        )
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn post_form_unauthed(uri: &str, csrf: &str, body: &str) -> axum::http::Request<Body> {
    axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("cookie", format!("__Host-calrs_csrf={}", csrf))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn post_bare(uri: &str) -> axum::http::Request<Body> {
    axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::empty())
        .unwrap()
}

// --- Min-notice for guest cancel / reschedule ---

/// Format a `start_at` value `offset` from now, using the same shape
/// (`%Y-%m-%dT%H:%M:%S`) that booking handlers persist. Booking times
/// are stored as naive host-local timestamps; the notice check uses
/// `Local::now().naive_local()` so we mirror that here.
fn booking_start_at(offset: chrono::Duration) -> String {
    (Local::now().naive_local() + offset)
        .format("%Y-%m-%dT%H:%M:%S")
        .to_string()
}

fn booking_end_at(offset: chrono::Duration, duration_min: i64) -> String {
    (Local::now().naive_local() + offset + chrono::Duration::minutes(duration_min))
        .format("%Y-%m-%dT%H:%M:%S")
        .to_string()
}

async fn insert_booking_at(
    pool: &SqlitePool,
    et_id: &str,
    cancel_tok: &str,
    resched_tok: &str,
    offset: chrono::Duration,
) -> String {
    let booking_id = uuid::Uuid::new_v4().to_string();
    let start_at = booking_start_at(offset);
    let end_at = booking_end_at(offset, 30);
    sqlx::query(
        "INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid-notice', 'Guest', 'guest@test.com', 'UTC', ?, ?, 'confirmed', ?, ?)",
    )
    .bind(&booking_id)
    .bind(et_id)
    .bind(&start_at)
    .bind(&end_at)
    .bind(cancel_tok)
    .bind(resched_tok)
    .execute(pool)
    .await
    .unwrap();
    booking_id
}

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

// ====== XSS regression guards (#43) ======
//
// Three dashboard templates used to embed user-controlled strings inside
// inline onclick JS string literals using `\'{{ var }}\'` as a naïve
// escape. MiniJinja auto-escapes `'` to `&#x27;` but leaves backslashes
// untouched, so a payload like `\\'));alert(1);//` breaks out of the JS
// string and injects script. Fix was to move the value into a
// `data-confirm` attribute and read it via `this.dataset.confirm` so it's
// never re-parsed as JS.
//
// These tests render each template with a crafted payload and assert
// that (a) the onclick is the safe static form and (b) the payload only
// lands in data-confirm (HTML-escaped). They fire if anyone re-introduces
// a `{{ … }}` interpolation inside an onclick.

/// Pull the bytes of the `onclick="…"` attribute for the first `<button>`
/// whose attributes contain `class_marker`. Only considers button-element
/// attribute strings (between `<button` and the first `>` after it), so
/// CSS/JS elsewhere in the document that happens to mention the marker
/// doesn't throw off the scan. Returns None if no such button exists.
fn extract_onclick_for_button(html: &str, class_marker: &str) -> Option<String> {
    // Skip the prefix before the first `<button` (document boilerplate).
    let mut rest = html;
    while let Some(idx) = rest.find("<button") {
        let after = &rest[idx + "<button".len()..];
        let (attrs, tail) = after.split_once('>')?;
        if attrs.contains(class_marker) {
            if let Some(attr_rest) = attrs.split_once("onclick=\"") {
                if let Some((value, _)) = attr_rest.1.split_once('"') {
                    return Some(value.to_string());
                }
            }
        }
        rest = tail;
    }
    None
}

/// Sentences that interpolate markup are rendered through `t(...) | safe`,
/// which turns off autoescaping for the whole string. Every value spliced
/// into one must therefore be escaped explicitly. A guest picks their own
/// name, so forgetting it once is stored XSS on the host's dashboard.
#[test]
fn safe_interpolated_sentences_escape_their_values() {
    let mut env = minijinja::Environment::new();
    env.set_undefined_behavior(minijinja::UndefinedBehavior::Lenient);
    env.set_loader(minijinja::path_loader("templates"));
    crate::i18n::register(&mut env);

    let booking_row = context! {
        id => "b1",
        event_title => XSS_PAYLOAD_HTML,
        guest_name => XSS_PAYLOAD_HTML,
        guest_email => "guest@example.com",
        start_at => "2026-03-16 10:00",
    };
    let cases: Vec<(&str, minijinja::Value)> = vec![
        (
            "dashboard_bookings.html",
            context! {
                lang => "en", sidebar => context! {},
                bookings => vec![booking_row.clone()],
                pending_bookings => vec![booking_row.clone()],
                claimable_bookings => vec![booking_row.clone()],
            },
        ),
        (
            "dashboard_overview.html",
            context! {
                lang => "en", sidebar => context! {},
                pending_bookings => vec![booking_row.clone()],
            },
        ),
        (
            "overrides.html",
            context! { lang => "en", sidebar => context! {}, event_type_title => XSS_PAYLOAD_HTML },
        ),
        (
            "invite_form.html",
            context! { lang => "en", sidebar => context! {}, event_type_title => XSS_PAYLOAD_HTML },
        ),
        (
            "troubleshoot.html",
            context! { lang => "en", sidebar => context! {}, et_title => XSS_PAYLOAD_HTML },
        ),
        (
            "source_write_setup.html",
            context! { lang => "en", source_name => XSS_PAYLOAD_HTML },
        ),
        (
            "auth/register.html",
            context! { lang => "en", allowed_domains => XSS_PAYLOAD_HTML },
        ),
    ];

    for (name, ctx) in cases {
        let rendered = env
            .get_template(name)
            .unwrap_or_else(|e| panic!("{name} loads: {e}"))
            .render(ctx)
            .unwrap_or_else(|e| panic!("{name} renders: {e}"));
        assert!(
            !rendered.contains(XSS_PAYLOAD_HTML),
            "{name} emitted an unescaped interpolated value"
        );
        assert!(
            rendered.contains("&lt;script&gt;"),
            "{name} did not render the payload at all — the test context is wrong"
        );
    }
}

const XSS_PAYLOAD: &str = r#"\\'));alert(1);//"#;

/// The booking error page is the one screen a guest sees when something
/// goes wrong, so it must never fall back to English. Every argument to
/// the render helpers has to arrive already translated (or as a Fluent
/// key), which means no call site may pass a bare English sentence.
/// Fluent keys are kebab-case and contain no spaces; an English sentence
/// does. That is the whole check.
#[test]
fn booking_action_error_call_sites_pass_no_english() {
    const HELPERS: &[&str] = &[
        "render_booking_action_error_in(",
        "render_booking_action_error_html_in(",
        "render_booking_action_error_keys_in(",
    ];

    let src: String = web_source_files()
        .iter()
        .map(|file| {
            let src = std::fs::read_to_string(file).expect("read source");
            src.split("\nmod tests {")
                .next()
                .unwrap_or(&src)
                .to_string()
        })
        .collect::<Vec<_>>()
        .join("\n");

    let mut offenders = Vec::new();
    let mut checked = 0usize;
    for helper in HELPERS {
        let mut from = 0usize;
        while let Some(off) = src[from..].find(helper) {
            let at = from + off;
            from = at + helper.len();
            // Skip the definitions themselves.
            let line_start = src[..at].rfind('\n').map(|i| i + 1).unwrap_or(0);
            if src[line_start..at].contains("fn ") {
                continue;
            }
            // Collect the argument list up to the balancing paren.
            let mut depth = 0i32;
            let mut args = String::new();
            for c in src[at + helper.len() - 1..].chars() {
                args.push(c);
                match c {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
            }
            checked += 1;
            for literal in args.split('"').skip(1).step_by(2) {
                if literal.contains(' ') {
                    offenders.push(format!("{helper} … {literal:?}"));
                }
            }
        }
    }

    assert!(
        checked >= 20,
        "expected to find the error-page call sites, found {checked} — the scan broke"
    );
    assert!(
        offenders.is_empty(),
        "booking error page rendered from untranslated English:\n  {}",
        offenders.join("\n  ")
    );
}

/// Every host-facing page must pass `lang` into its render context. A
/// handler that forgets renders English regardless of the viewer's saved
/// preference, and nothing fails: the page still looks fine, just in the
/// wrong language. Three handlers shipped that way on this branch before
/// this test existed.
#[test]
fn every_host_render_site_passes_lang() {
    const HOST_TEMPLATES: &[&str] = &[
        "dashboard_overview.html",
        "dashboard_event_types.html",
        "dashboard_bookings.html",
        "dashboard_sources.html",
        "dashboard_teams.html",
        "dashboard_internal.html",
        "settings.html",
        "admin.html",
        "event_type_form.html",
        "invite_form.html",
        "source_form.html",
        "source_test.html",
        "source_write_setup.html",
        "team_form.html",
        "team_settings.html",
        "troubleshoot.html",
        "overrides.html",
        "auth/login.html",
        "auth/register.html",
    ];

    let mut offenders = Vec::new();
    let mut files = web_source_files();
    files.push(std::path::PathBuf::from("src/auth.rs"));
    for file in &files {
        let src = std::fs::read_to_string(file).expect("read source");
        let file = file.display();
        // Only the shipping code: the test module below renders templates
        // with deliberately minimal contexts.
        let src = src.split("\nmod tests {").next().unwrap_or(&src);
        let lines: Vec<&str> = src.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let Some(name) = line
                .split_once("get_template(\"")
                .and_then(|(_, rest)| rest.split_once('"'))
                .map(|(name, _)| name)
            else {
                continue;
            };
            if !HOST_TEMPLATES.contains(&name) {
                continue;
            }
            // The render call follows; take the context block after it.
            let Some(start) = (i..lines.len().min(i + 400)).find(|&j| {
                lines[j].contains("render(context!")
                    || lines[j].contains("render(minijinja::context!")
            }) else {
                continue;
            };
            let mut depth = 0i32;
            let mut block = String::new();
            for line in lines.iter().skip(start).take(150) {
                block.push_str(line);
                block.push('\n');
                depth += line.matches('{').count() as i32;
                depth -= line.matches('}').count() as i32;
                if depth <= 0 && block.lines().count() > 1 {
                    break;
                }
            }
            let passes_lang = block.contains("lang =>") || block.contains("lang,");
            if !passes_lang {
                offenders.push(format!("{file}:{} renders {name} without lang", start + 1));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "host pages rendered without a language:\n{}",
        offenders.join("\n")
    );
}

/// The `| escape` in a safe-filtered `t()` call is load-bearing, and the
/// render test above only covers the sites that exist today. This one is
/// structural: in any `t(...) | safe` call, every operand concatenated into
/// an argument must be a string literal, an `| escape`d expression, or a
/// nested `t()` (whose output is our own translation, not user data).
/// A new site that splices a bare variable in fails here.
#[test]
fn safe_filtered_translations_never_splice_bare_variables() {
    let mut offenders = Vec::new();
    for path in template_paths() {
        let src = std::fs::read_to_string(&path).expect("read template");
        for (n, line) in src.lines().enumerate() {
            if !(line.contains("t(") && line.contains("| safe")) {
                continue;
            }
            for operand in concat_operands(line) {
                let trimmed = operand.trim();
                let literal = trimmed.starts_with('\'') || trimmed.starts_with('"');
                let escaped = trimmed.contains("| escape") || trimmed.contains("|escape");
                let translated = trimmed.starts_with("t(") || trimmed.starts_with("(t(");
                if !(literal || escaped || translated) {
                    offenders.push(format!(
                        "{}:{}: `{}` is spliced into a | safe string without | escape",
                        path.display(),
                        n + 1,
                        trimmed
                    ));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "unescaped values in safe-filtered translations:\n{}",
        offenders.join("\n")
    );
}

/// Every operand of every argument of a `t(...)` call on this line: the
/// argument list is split on top-level commas, then each argument on `~`.
fn concat_operands(line: &str) -> Vec<String> {
    let mut operands = Vec::new();
    let Some(open) = line.find("t(") else {
        return operands;
    };
    let body = &line[open + 2..];

    let mut depth = 0i32;
    let mut quote: Option<char> = None;
    let mut current = String::new();
    for ch in body.chars() {
        match quote {
            Some(q) => {
                current.push(ch);
                if ch == q {
                    quote = None;
                }
            }
            None if ch == '\'' || ch == '"' => {
                current.push(ch);
                quote = Some(ch);
            }
            None if ch == '(' => {
                depth += 1;
                current.push(ch);
            }
            None if ch == ')' && depth > 0 => {
                depth -= 1;
                current.push(ch);
            }
            // End of the t(...) call.
            None if ch == ')' => break,
            None if (ch == ',' || ch == '~') && depth == 0 => {
                operands.push(std::mem::take(&mut current));
            }
            None => current.push(ch),
        }
    }
    operands.push(current);

    operands
        .into_iter()
        .map(|o| {
            let o = o.trim().trim_start_matches('(').trim();
            // Drop a leading `name=` so an argument is judged on its value,
            // not its keyword.
            match o.split_once('=') {
                Some((name, rest))
                    if !name.is_empty()
                        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') =>
                {
                    rest.trim().to_string()
                }
                _ => o.to_string(),
            }
        })
        .filter(|o| !o.is_empty())
        .collect()
}

/// All `.html` files under `templates/`, recursively.
fn template_paths() -> Vec<std::path::PathBuf> {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read templates dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "html") {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(std::path::Path::new("templates"), &mut out);
    out.sort();
    out
}

/// The shipping `.rs` files of the web module, for the source-scanning
/// guards above. Test code (`tests/`, `test_support.rs`, `*_tests.rs`)
/// is left out: it renders templates with deliberately minimal contexts.
fn web_source_files() -> Vec<std::path::PathBuf> {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read src/web dir") {
            let path = entry.expect("dir entry").path();
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            if path.is_dir() {
                if name != "tests" {
                    walk(&path, out);
                }
            } else if name.ends_with(".rs")
                && !name.ends_with("_tests.rs")
                && name != "test_support.rs"
            {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(std::path::Path::new("src/web"), &mut out);
    out.sort();
    out
}

const XSS_PAYLOAD_HTML: &str = "<script>alert(1)</script>";

#[test]
fn dashboard_event_types_delete_button_no_onclick_interpolation() {
    let mut env = minijinja::Environment::new();
    env.set_undefined_behavior(minijinja::UndefinedBehavior::Lenient);
    env.set_loader(minijinja::path_loader("templates"));
    crate::i18n::register(&mut env);
    let tmpl = env
        .get_template("dashboard_event_types.html")
        .expect("template loads");

    let rendered = tmpl
        .render(context! {
            sidebar => context! {},
            username => "alice",
            has_any => true,
            all_event_types => vec![context! {
                id => "et-1",
                slug => "intro",
                title => XSS_PAYLOAD,
                duration_min => 30,
                enabled => true,
                visibility => "public",
                can_manage => true,
                active_bookings => 0,
                is_team => false,
                edit_url => "/e/edit",
                toggle_url => "/e/toggle",
                overrides_url => "/e/overrides",
                embed_url => "/e/embed",
                delete_url => "/e/delete",
                view_url => "/e/view",
            }],
        })
        .expect("renders");

    let onclick = extract_onclick_for_button(&rendered, r#"class="danger""#)
        .expect("delete button onclick present");
    assert_eq!(
        onclick, "if(confirm(this.dataset.confirm)) this.nextElementSibling.submit();",
        "onclick must be the static safe form — no interpolation allowed",
    );
    // The payload should appear only inside the data-confirm attribute,
    // HTML-escaped. Backslashes pass through unchanged, apostrophes
    // become &#x27; — including the two the sentence itself puts around
    // the title, since the whole string now comes back from Fluent and is
    // escaped in one piece. The browser decodes them identically.
    assert!(
        rendered.contains(
            r#"data-confirm="Delete event type &#x27;\\&#x27;));alert(1);&#x2f;&#x2f;&#x27;"#
        ),
        "payload should be inside data-confirm only"
    );
}

#[test]
fn dashboard_sources_remove_button_no_onclick_interpolation() {
    let mut env = minijinja::Environment::new();
    env.set_undefined_behavior(minijinja::UndefinedBehavior::Lenient);
    env.set_loader(minijinja::path_loader("templates"));
    crate::i18n::register(&mut env);
    let tmpl = env
        .get_template("dashboard_sources.html")
        .expect("template loads");

    let rendered = tmpl
        .render(context! {
            sidebar => context! {},
            sources => vec![context! {
                id => "s-1",
                name => XSS_PAYLOAD,
                url => "https://example.com/dav",
                username => "alice",
                enabled => true,
                last_synced => "never",
                calendar_count => 0,
                event_count => 0,
                needs_write_setup => false,
            }],
        })
        .expect("renders");

    // The Remove button is the one containing "Remove" text AND the
    // error-text style. It's distinguishable from "Test" by the
    // var(--error-text) inline style.
    let onclick = extract_onclick_for_button(&rendered, "var(--error-text)")
        .expect("remove button onclick present");
    assert_eq!(
        onclick,
        "if(confirm(this.dataset.confirm)) this.closest('div').querySelector('.remove-form').submit();",
        "onclick must be the static safe form — no interpolation allowed",
    );
    assert!(
        rendered.contains(
            r#"data-confirm="Remove source &#x27;\\&#x27;));alert(1);&#x2f;&#x2f;&#x27;"#
        ),
        "payload should be inside data-confirm only"
    );
}

#[test]
fn team_settings_delete_button_no_onclick_interpolation() {
    let mut env = minijinja::Environment::new();
    env.set_undefined_behavior(minijinja::UndefinedBehavior::Lenient);
    env.set_loader(minijinja::path_loader("templates"));
    crate::i18n::register(&mut env);
    let tmpl = env
        .get_template("team_settings.html")
        .expect("template loads");

    let rendered = tmpl
        .render(context! {
            sidebar => context! {},
            team_id => "t-1",
            team_name => XSS_PAYLOAD,
            team_slug => "acme",
            team_description => "",
            team_avatar_path => minijinja::value::Value::from(None::<String>),
            team_visibility => "public",
            invite_token => minijinja::value::Value::from(None::<String>),
            members => Vec::<minijinja::Value>::new(),
            linked_groups => Vec::<minijinja::Value>::new(),
            available_groups => Vec::<minijinja::Value>::new(),
            can_admin => true,
            is_owner => true,
        })
        .expect("renders");

    let onclick = extract_onclick_for_button(&rendered, "border-color: var(--error-text)")
        .expect("delete team button onclick present");
    assert_eq!(
        onclick, "if(confirm(this.dataset.confirm)) this.nextElementSibling.submit();",
        "onclick must be the static safe form — no interpolation allowed",
    );
    assert!(
        rendered
            .contains(r#"data-confirm="Delete team &#x27;\\&#x27;));alert(1);&#x2f;&#x2f;&#x27;"#),
        "payload should be inside data-confirm only"
    );
}

fn host_today() -> NaiveDate {
    Utc::now().with_timezone(&Tz::UTC).naive_local().date()
}

/// A Monday roughly a month out: past any small horizon, and on a weekday
/// the seeded Mon-Fri availability covers.
fn far_future_monday() -> String {
    let mut d = host_today() + Duration::days(28);
    while d.weekday() != chrono::Weekday::Mon {
        d += Duration::days(1);
    }
    d.format("%Y-%m-%d").to_string()
}

fn book_body(csrf: &str) -> String {
    format!(
        "_csrf={}&date={}&time=10:00&name=Guest&email=guest%40test.com&tz=UTC",
        csrf,
        far_future_monday()
    )
}

async fn set_horizon(pool: &SqlitePool, et_id: &str, days: i32) {
    sqlx::query("UPDATE event_types SET booking_horizon_days = ? WHERE id = ?")
        .bind(days)
        .bind(et_id)
        .execute(pool)
        .await
        .unwrap();
}

/// Seed a team plus a team event type sharing the test account, with the
/// same Mon-Fri availability as the personal fixture.
async fn seed_team_event_type(pool: &SqlitePool) -> (String, String) {
    let (user_id, account_id): (String, String) = sqlx::query_as(
        "SELECT u.id, a.id FROM users u JOIN accounts a ON a.user_id = u.id WHERE u.username = 'testuser'",
    )
    .fetch_one(pool)
    .await
    .unwrap();

    let team_id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO teams (id, name, slug, visibility, created_by) VALUES (?, 'Horizon Team', 'horizon-team', 'public', ?)")
        .bind(&team_id)
        .bind(&user_id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO team_members (team_id, user_id, role, source) VALUES (?, ?, 'admin', 'direct')")
        .bind(&team_id)
        .bind(&user_id)
        .execute(pool)
        .await
        .unwrap();

    let et_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO event_types (id, account_id, slug, title, duration_min, buffer_before, buffer_after, min_notice_min, enabled, team_id, created_by_user_id) \
             VALUES (?, ?, 'team-sync', 'Team Sync', 30, 0, 0, 0, 1, ?, ?)",
    )
    .bind(&et_id)
    .bind(&account_id)
    .bind(&team_id)
    .bind(&user_id)
    .execute(pool)
    .await
    .unwrap();

    for day in [1, 2, 3, 4, 5] {
        sqlx::query("INSERT INTO availability_rules (id, event_type_id, day_of_week, start_time, end_time) VALUES (?, ?, ?, '09:00', '17:00')")
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(&et_id)
            .bind(day)
            .execute(pool)
            .await
            .unwrap();
    }

    (team_id, et_id)
}

// --- #209: guest emails sent on someone else's request keep the guest's language ---

/// One message as an anonymous loopback MTA received it.
struct CapturedMail {
    rcpt: Vec<String>,
    data: String,
}

/// Anonymous loopback MTA (no AUTH, no STARTTLS) that accepts any number
/// of connections and keeps every message, so a handler test can read
/// the emails it sent. calrs opens one connection per email.
async fn spawn_capturing_mta() -> (u16, Arc<std::sync::Mutex<Vec<CapturedMail>>>) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mails = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = mails.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let sink = sink.clone();
            tokio::spawn(async move {
                let (read_half, mut write) = stream.into_split();
                let mut reader = BufReader::new(read_half);
                let _ = write.write_all(b"220 fake.local ESMTP\r\n").await;
                let mut rcpt = Vec::new();
                loop {
                    let mut line = String::new();
                    match reader.read_line(&mut line).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                    let upper = line.trim_end().to_ascii_uppercase();
                    let reply: &[u8] = if upper.starts_with("EHLO") {
                        b"250-fake.local\r\n250 8BITMIME\r\n"
                    } else if upper.starts_with("RCPT TO") {
                        rcpt.push(line.trim_end().to_string());
                        b"250 OK\r\n"
                    } else if upper == "DATA" {
                        let _ = write.write_all(b"354 go ahead\r\n").await;
                        let mut data = String::new();
                        loop {
                            let mut body = String::new();
                            match reader.read_line(&mut body).await {
                                Ok(0) | Err(_) => break,
                                Ok(_) => {}
                            }
                            if body.trim_end() == "." {
                                break;
                            }
                            data.push_str(&body);
                        }
                        sink.lock().unwrap().push(CapturedMail {
                            rcpt: std::mem::take(&mut rcpt),
                            data,
                        });
                        b"250 queued\r\n"
                    } else if upper == "QUIT" {
                        let _ = write.write_all(b"221 bye\r\n").await;
                        break;
                    } else {
                        b"250 OK\r\n"
                    };
                    let _ = write.write_all(reply).await;
                }
            });
        }
    });
    (port, mails)
}

/// Point the instance's SMTP config at the capturing MTA.
async fn use_capturing_mta(pool: &SqlitePool, port: u16) {
    let password_enc = crate::crypto::encrypt_password(&[0u8; 32], "").unwrap();
    sqlx::query(
        "INSERT INTO smtp_config (id, host, port, username, password_enc, from_email, tls_mode, enabled) \
             VALUES (?, '127.0.0.1', ?, '', ?, 'noreply@test.com', 'none', 1)",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(port as i64)
    .bind(&password_enc)
    .execute(pool)
    .await
    .unwrap();
}

/// Undo quoted-printable transfer encoding so assertions can match the
/// text the recipient reads, accents included.
fn decode_quoted_printable(raw: &str) -> String {
    let joined = raw.replace("=\r\n", "").replace("=\n", "");
    let bytes = joined.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'=' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&joined[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The decoded body of the one email addressed to `email`. Booking emails
/// are sent from a background task (#236), so wait for it to arrive.
async fn mail_to(mails: &std::sync::Mutex<Vec<CapturedMail>>, email: &str) -> String {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        {
            let mails = mails.lock().unwrap();
            let found: Vec<&CapturedMail> = mails
                .iter()
                .filter(|m| m.rcpt.iter().any(|r| r.contains(email)))
                .collect();
            if !found.is_empty() || std::time::Instant::now() >= deadline {
                assert_eq!(found.len(), 1, "expected one email to {email}");
                return decode_quoted_printable(&found[0].data);
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

async fn insert_pending_french_booking(pool: &SqlitePool, et_id: &str, uid: &str) -> String {
    let booking_id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token, confirm_token, language) VALUES (?, ?, ?, 'Guest', 'guest@test.com', 'UTC', '2026-06-15T10:00:00', '2026-06-15T10:30:00', 'pending', ?, ?, ?, 'fr')")
        .bind(&booking_id)
        .bind(et_id)
        .bind(uid)
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(format!("confirm-{uid}"))
        .execute(pool)
        .await
        .unwrap();
    booking_id
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

// --- #221: guest emails come from the host, with Reply-To ---

/// The value of the first `name:` header of a captured message.
fn mail_header<'a>(mail: &'a str, name: &str) -> Option<&'a str> {
    let headers = mail.split("\r\n\r\n").next().unwrap_or(mail);
    let prefix = format!("{name}: ");
    headers
        .split("\r\n")
        .find_map(|line| line.strip_prefix(prefix.as_str()))
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

/// Pages declare the language they are rendered in, so browsers pick the
/// right spell-check dictionary (#209).
#[tokio::test]
async fn pages_declare_their_language_on_the_html_element() {
    let (app, _, _, _) = setup_test_app().await;
    let french = axum::http::Request::builder()
        .uri("/auth/login")
        .header("accept-language", "fr-FR,fr;q=0.9")
        .body(Body::empty())
        .unwrap();
    let body = body_string(app.clone().oneshot(french).await.unwrap()).await;
    assert!(body.contains("<html lang=\"fr\">"), "{body}");

    let body = body_string(app.oneshot(get("/auth/login")).await.unwrap()).await;
    assert!(body.contains("<html lang=\"en\">"), "{body}");
}

// --- #209: host, member and watcher emails follow each recipient's language ---

async fn set_user_language(pool: &SqlitePool, email: &str, language: &str) {
    sqlx::query("UPDATE users SET language = ? WHERE email = ?")
        .bind(language)
        .bind(email)
        .execute(pool)
        .await
        .unwrap();
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

// --- The stored booking language is the language the form was shown in ---

fn book_request(
    uri: &str,
    csrf: &str,
    cookie_extra: &str,
    accept: &str,
) -> axum::http::Request<Body> {
    axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header(
            "cookie",
            format!("__Host-calrs_csrf={}{}", csrf, cookie_extra),
        )
        .header("accept-language", accept)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(book_body(csrf)))
        .unwrap()
}

async fn stored_language(pool: &SqlitePool, guest_email: &str) -> Option<String> {
    sqlx::query_scalar("SELECT language FROM bookings WHERE guest_email = ?")
        .bind(guest_email)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn set_public_page_language(pool: &SqlitePool, mode: &str) {
    sqlx::query("UPDATE users SET public_page_language = ? WHERE email = 'test@example.com'")
        .bind(mode)
        .execute(pool)
        .await
        .unwrap();
}

fn get_with_language(uri: &str, accept: &str) -> axum::http::Request<Body> {
    axum::http::Request::builder()
        .uri(uri)
        .header("accept-language", accept)
        .body(Body::empty())
        .unwrap()
}

/// With "always my language", a user's booking page is shown in the
/// host's saved language (#76), so that is what the booking stores and
/// what the guest is emailed in, whatever the guest's browser says.
#[tokio::test]
async fn user_page_booking_stores_the_language_the_form_was_shown_in() {
    let _env = crate::test_support::ENV_LOCK.lock().await;
    let (app, pool, _, _) = setup_test_app().await;
    let (port, mails) = spawn_capturing_mta().await;
    use_capturing_mta(&pool, port).await;
    set_user_language(&pool, "test@example.com", "fr").await;
    set_public_page_language(&pool, "host").await;

    let form = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri(format!(
                    "/u/testuser/test-meeting/book?date={}&time=10:00",
                    far_future_monday()
                ))
                .header("accept-language", "en-US,en;q=0.9")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(body_string(form).await.contains("<html lang=\"fr\">"));

    let csrf = "csrf-page-lang-fr";
    let response = app
        .oneshot(book_request(
            "/u/testuser/test-meeting/book",
            csrf,
            "",
            "en-US,en;q=0.9",
        ))
        .await
        .unwrap();
    assert!(response.status() == 200 || response.status().is_redirection());

    assert_eq!(
        stored_language(&pool, "guest@test.com").await.as_deref(),
        Some("fr")
    );
    let guest = mail_to(&mails, "guest@test.com").await;
    assert!(guest.contains("Bonjour Guest,"), "{guest}");
    assert!(guest.contains("<html lang=\"fr\">"), "{guest}");
    let host = mail_to(&mails, "test@example.com").await;
    assert!(host.contains("Nouvelle réservation !"), "{host}");
}

/// A browser language calrs does not ship falls back like the page does:
/// on the page of a host who chose "always my language", French.
#[tokio::test]
async fn unsupported_browser_language_stores_the_page_language() {
    let _env = crate::test_support::ENV_LOCK.lock().await;
    let (app, pool, _, _) = setup_test_app().await;
    set_user_language(&pool, "test@example.com", "fr").await;
    set_public_page_language(&pool, "host").await;

    let csrf = "csrf-page-lang-ja";
    app.oneshot(book_request(
        "/u/testuser/test-meeting/book",
        csrf,
        "",
        "ja-JP,ja;q=0.9",
    ))
    .await
    .unwrap();
    assert_eq!(
        stored_language(&pool, "guest@test.com").await.as_deref(),
        Some("fr")
    );
}

/// Public guest pages store the browser's language, for an anonymous
/// guest and for a logged-in host with a saved preference booking on a
/// client's behalf alike: staff never stamp their own language on a
/// guest's booking.
#[tokio::test]
async fn browser_language_page_stores_the_browser_language() {
    let _env = crate::test_support::ENV_LOCK.lock().await;
    let (app, pool, session, _) = setup_test_app().await;
    set_user_language(&pool, "test@example.com", "fr").await;

    let csrf = "csrf-page-lang-anon";
    app.clone()
        .oneshot(book_request(
            "/test-meeting/book",
            csrf,
            "",
            "en-US,en;q=0.9",
        ))
        .await
        .unwrap();
    assert_eq!(
        stored_language(&pool, "guest@test.com").await.as_deref(),
        Some("en")
    );
    sqlx::query("DELETE FROM bookings")
        .execute(&pool)
        .await
        .unwrap();

    let csrf = "csrf-page-lang-en";
    let response = app
        .oneshot(book_request(
            "/test-meeting/book",
            csrf,
            &format!("; __Host-calrs_session={}", session),
            "en-US,en;q=0.9",
        ))
        .await
        .unwrap();
    assert!(response.status() == 200 || response.status().is_redirection());
    assert_eq!(
        stored_language(&pool, "guest@test.com").await.as_deref(),
        Some("en")
    );
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

/// Team pages follow the browser even for a logged-in visitor with a
/// saved preference: a German-preference user with an English browser
/// sees them in English, and the booking stores 'en'.
#[tokio::test]
async fn team_pages_follow_the_browser_not_a_logged_in_preference() {
    let _env = crate::test_support::ENV_LOCK.lock().await;
    let (app, pool, _, _) = setup_test_app().await;
    seed_team_event_type(&pool).await;
    let visitor = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO users (id, email, name, role, auth_provider, username, enabled, language) VALUES (?, 'visitor@test.com', 'Visitor', 'user', 'local', 'visitor', 1, 'de')")
        .bind(&visitor)
        .execute(&pool)
        .await
        .unwrap();
    let session = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)")
        .bind(&session)
        .bind(&visitor)
        .bind(
            (Utc::now() + Duration::days(1))
                .format("%Y-%m-%d %H:%M:%S")
                .to_string(),
        )
        .execute(&pool)
        .await
        .unwrap();
    let cookie = format!("__Host-calrs_session={}", session);

    for uri in [
        "/team/horizon-team".to_string(),
        "/team/horizon-team/team-sync".to_string(),
        format!(
            "/team/horizon-team/team-sync/book?date={}&time=10:00",
            far_future_monday()
        ),
    ] {
        let request = axum::http::Request::builder()
            .uri(&uri)
            .header("cookie", &cookie)
            .header("accept-language", "en-US,en;q=0.9")
            .body(Body::empty())
            .unwrap();
        let body = body_string(app.clone().oneshot(request).await.unwrap()).await;
        assert!(body.contains("<html lang=\"en\">"), "{uri}: {body}");
    }

    let csrf = "csrf-team-visitor-de";
    let response = app
        .oneshot(book_request(
            "/team/horizon-team/team-sync/book",
            csrf,
            &format!("; {}", cookie),
            "en-US,en;q=0.9",
        ))
        .await
        .unwrap();
    assert!(response.status() == 200 || response.status().is_redirection());
    assert_eq!(
        stored_language(&pool, "guest@test.com").await.as_deref(),
        Some("en")
    );
}

/// On a host-language `/u/` page, a rejected booking answers fully in the
/// page's language, not the browser's.
#[tokio::test]
async fn host_mode_booking_error_page_uses_the_page_language() {
    let _env = crate::test_support::ENV_LOCK.lock().await;
    let (app, pool, _, _) = setup_test_app().await;
    set_user_language(&pool, "test@example.com", "fr").await;
    set_public_page_language(&pool, "host").await;

    let csrf = "csrf-host-mode-error";
    let body = format!(
        "_csrf={}&date={}&time=10:00&name=Guest&email=not-an-email&tz=UTC",
        csrf,
        far_future_monday()
    );
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/u/testuser/test-meeting/book")
        .header("cookie", format!("__Host-calrs_csrf={}", csrf))
        .header("accept-language", "en-US,en;q=0.9")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();
    let page = body_string(app.oneshot(request).await.unwrap()).await;
    assert!(page.contains("<html lang=\"fr\">"), "{page}");
    assert!(page.contains("Détails de réservation invalides"), "{page}");
    assert!(
        page.contains("Veuillez saisir une adresse e-mail valide."),
        "{page}"
    );
    assert!(!page.contains("Invalid booking details"), "{page}");
}

// --- Public booking page language setting ---

/// By default a user's pages follow the visitor: a French-speaking host's
/// pages are English for an English browser, the booking stores 'en',
/// and only the host's own email is French.
#[tokio::test]
async fn user_pages_follow_the_visitor_by_default() {
    let _env = crate::test_support::ENV_LOCK.lock().await;
    let (app, pool, _, _) = setup_test_app().await;
    let (port, mails) = spawn_capturing_mta().await;
    use_capturing_mta(&pool, port).await;
    set_user_language(&pool, "test@example.com", "fr").await;

    for uri in [
        "/u/testuser".to_string(),
        "/u/testuser/test-meeting".to_string(),
        format!(
            "/u/testuser/test-meeting/book?date={}&time=10:00",
            far_future_monday()
        ),
    ] {
        let body = body_string(
            app.clone()
                .oneshot(get_with_language(&uri, "en-US,en;q=0.9"))
                .await
                .unwrap(),
        )
        .await;
        assert!(body.contains("<html lang=\"en\">"), "{uri}: {body}");
    }

    let csrf = "csrf-public-visitor";
    let response = app
        .oneshot(book_request(
            "/u/testuser/test-meeting/book",
            csrf,
            "",
            "en-US,en;q=0.9",
        ))
        .await
        .unwrap();
    assert!(response.status() == 200 || response.status().is_redirection());
    assert_eq!(
        stored_language(&pool, "guest@test.com").await.as_deref(),
        Some("en")
    );
    let guest = mail_to(&mails, "guest@test.com").await;
    assert!(guest.contains("Hi Guest,"), "{guest}");
    let host = mail_to(&mails, "test@example.com").await;
    assert!(host.contains("Nouvelle réservation !"), "{host}");
}

/// "Always my language" with no saved language falls back to the
/// visitor's.
#[tokio::test]
async fn host_mode_without_a_saved_language_follows_the_visitor() {
    let _env = crate::test_support::ENV_LOCK.lock().await;
    let (app, pool, _, _) = setup_test_app().await;
    set_public_page_language(&pool, "host").await;

    let body = body_string(
        app.clone()
            .oneshot(get_with_language(
                "/u/testuser/test-meeting",
                "de-DE,de;q=0.9",
            ))
            .await
            .unwrap(),
    )
    .await;
    assert!(body.contains("<html lang=\"de\">"), "{body}");

    let csrf = "csrf-public-host-none";
    app.oneshot(book_request(
        "/u/testuser/test-meeting/book",
        csrf,
        "",
        "de-DE,de;q=0.9",
    ))
    .await
    .unwrap();
    assert_eq!(
        stored_language(&pool, "guest@test.com").await.as_deref(),
        Some("de")
    );
}

async fn stored_public_page_language(pool: &SqlitePool) -> String {
    sqlx::query_scalar("SELECT public_page_language FROM users WHERE email = 'test@example.com'")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn settings_save_the_public_page_language_and_reject_unknown_values() {
    let _env = crate::test_support::ENV_LOCK.lock().await;
    let (app, pool, session, _) = setup_test_app().await;
    assert_eq!(stored_public_page_language(&pool).await, "visitor");

    let csrf = "csrf-settings-public-lang";
    let body = format!(
        "_csrf={}&name=Test+User&booking_email=&public_page_language=host",
        csrf
    );
    let response = app
        .clone()
        .oneshot(post_form("/dashboard/settings", &session, csrf, &body))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let page = body_string(response).await;
    assert!(page.contains("<option value=\"host\" selected>"), "{page}");
    assert_eq!(stored_public_page_language(&pool).await, "host");

    let body = format!(
        "_csrf={}&name=Test+User&booking_email=&public_page_language=guest",
        csrf
    );
    let response = app
        .oneshot(post_form("/dashboard/settings", &session, csrf, &body))
        .await
        .unwrap();
    let page = body_string(response).await;
    assert!(
        page.contains("Pick a valid public booking page language."),
        "{page}"
    );
    assert_eq!(stored_public_page_language(&pool).await, "host");
}

/// The host's approve page is in the host's saved language, like the
/// approval email that links to it, whatever the browser says.
#[tokio::test]
async fn approve_page_uses_the_host_language() {
    let _env = crate::test_support::ENV_LOCK.lock().await;
    let (app, pool, _, et_id) = setup_test_app().await;
    set_user_language(&pool, "test@example.com", "fr").await;
    insert_pending_french_booking(&pool, &et_id, "uid-host-page-lang").await;

    for uri in [
        "/booking/approve/confirm-uid-host-page-lang",
        "/booking/decline/confirm-uid-host-page-lang",
    ] {
        let page = body_string(
            app.clone()
                .oneshot(get_with_language(uri, "en-US,en;q=0.9"))
                .await
                .unwrap(),
        )
        .await;
        assert!(page.contains("<html lang=\"fr\">"), "{uri}: {page}");
    }
}

/// A collective booking has several approvers and the shared link cannot
/// tell which one clicked, so its approve page follows the browser, even
/// when the owner has a saved language.
#[tokio::test]
async fn collective_approve_page_follows_the_browser() {
    let _env = crate::test_support::ENV_LOCK.lock().await;
    let (app, pool, _, et_id) = setup_test_app().await;
    set_user_language(&pool, "test@example.com", "fr").await;
    let team_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO teams (id, name, slug, visibility) VALUES (?, 'Crew', 'crew', 'public')",
    )
    .bind(&team_id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("UPDATE event_types SET team_id = ?, scheduling_mode = 'collective' WHERE id = ?")
        .bind(&team_id)
        .bind(&et_id)
        .execute(&pool)
        .await
        .unwrap();
    insert_pending_french_booking(&pool, &et_id, "uid-collective-page-lang").await;

    let page = body_string(
        app.oneshot(get_with_language(
            "/booking/approve/confirm-uid-collective-page-lang",
            "de-DE,de;q=0.9",
        ))
        .await
        .unwrap(),
    )
    .await;
    assert!(page.contains("<html lang=\"de\">"), "{page}");
}

/// The claim page is in the claiming watcher's saved language, like the
/// claim email.
#[tokio::test]
async fn claim_page_uses_the_watcher_language() {
    let _env = crate::test_support::ENV_LOCK.lock().await;
    let (app, pool, _, et_id) = setup_test_app().await;
    let booking_id = insert_pending_french_booking(&pool, &et_id, "uid-claim-page-lang").await;
    let watcher = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO users (id, email, name, role, auth_provider, username, enabled, language) VALUES (?, 'watcher@test.com', 'Watcher', 'user', 'local', 'watcher', 1, 'de')")
        .bind(&watcher)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO booking_claim_tokens (id, booking_id, user_id, token, expires_at) VALUES (?, ?, ?, 'claim-tok-de', datetime('now', '+7 days'))")
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&booking_id)
        .bind(&watcher)
        .execute(&pool)
        .await
        .unwrap();

    let page = body_string(
        app.oneshot(get_with_language(
            &format!("/booking/claim/{}?token=claim-tok-de", booking_id),
            "en-US,en;q=0.9",
        ))
        .await
        .unwrap(),
    )
    .await;
    assert!(page.contains("<html lang=\"de\">"), "{page}");
}

/// The legacy single-user pages honour the owner's public page language
/// exactly like `/u/`.
#[tokio::test]
async fn legacy_pages_honour_the_owner_page_language() {
    let _env = crate::test_support::ENV_LOCK.lock().await;
    let (app, pool, _, _) = setup_test_app().await;
    set_user_language(&pool, "test@example.com", "fr").await;
    set_public_page_language(&pool, "host").await;

    for uri in [
        "/test-meeting".to_string(),
        format!("/test-meeting/book?date={}&time=10:00", far_future_monday()),
    ] {
        let page = body_string(
            app.clone()
                .oneshot(get_with_language(&uri, "en-US,en;q=0.9"))
                .await
                .unwrap(),
        )
        .await;
        assert!(page.contains("<html lang=\"fr\">"), "{uri}: {page}");
    }

    let csrf = "csrf-legacy-host-mode";
    let response = app
        .oneshot(book_request(
            "/test-meeting/book",
            csrf,
            "",
            "en-US,en;q=0.9",
        ))
        .await
        .unwrap();
    assert!(response.status() == 200 || response.status().is_redirection());
    assert_eq!(
        stored_language(&pool, "guest@test.com").await.as_deref(),
        Some("fr")
    );
}

/// Give `user_id` a basic-auth CalDAV source on `base` that writes to
/// `/dav/cal/`.
async fn seed_write_source(pool: &SqlitePool, user_id: &str, base: &str) -> String {
    let account_id: String = sqlx::query_scalar("SELECT id FROM accounts WHERE user_id = ?")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .unwrap();
    let source_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO caldav_sources (id, account_id, name, url, username, password_enc, enabled, write_calendar_href) \
         VALUES (?, ?, 'Work calendar', ?, 'u', ?, 1, '/dav/cal/')",
    )
    .bind(&source_id)
    .bind(&account_id)
    .bind(base)
    .bind(crate::crypto::encrypt_password(&[0u8; 32], "p").unwrap())
    .execute(pool)
    .await
    .unwrap();
    source_id
}

/// A UTC instant as stored on a version 1 booking.
fn utc_stamp(t: chrono::DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%SZ").to_string()
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
