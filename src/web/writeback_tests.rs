// Calendar write-back failures: verify, record, retry (#162). Included into
// `web::tests`, so it shares that module's helpers.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum DavMode {
    /// Accept writes and keep them.
    Ok,
    /// Answer 201 to a PUT and keep nothing: the Yandex case from #162.
    Drop,
    /// Refuse writes with a 400.
    Reject,
}

/// A tiny CalDAV collection on loopback: PUT, HEAD and DELETE by path.
struct MockDav {
    mode: std::sync::Mutex<DavMode>,
    stored: std::sync::Mutex<std::collections::HashSet<String>>,
    puts: std::sync::atomic::AtomicUsize,
}

impl MockDav {
    fn set_mode(&self, mode: DavMode) {
        *self.mode.lock().unwrap() = mode;
    }
    fn puts(&self) -> usize {
        self.puts.load(std::sync::atomic::Ordering::SeqCst)
    }
    fn stored(&self) -> usize {
        self.stored.lock().unwrap().len()
    }
}

/// Start a mock CalDAV server and return its base URL.
async fn spawn_mock_dav(mode: DavMode) -> (String, Arc<MockDav>) {
    use axum::http::{Method, StatusCode, Uri};
    let dav = Arc::new(MockDav {
        mode: std::sync::Mutex::new(mode),
        stored: std::sync::Mutex::new(std::collections::HashSet::new()),
        puts: std::sync::atomic::AtomicUsize::new(0),
    });
    let state = dav.clone();
    let app = Router::new().fallback(move |method: Method, uri: Uri| {
        let dav = state.clone();
        async move {
            let path = uri.path().to_string();
            if method == Method::PUT {
                dav.puts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mode = *dav.mode.lock().unwrap();
                match mode {
                    DavMode::Reject => StatusCode::BAD_REQUEST,
                    DavMode::Drop => StatusCode::CREATED,
                    DavMode::Ok => {
                        dav.stored.lock().unwrap().insert(path);
                        StatusCode::CREATED
                    }
                }
            } else if method == Method::HEAD {
                if dav.stored.lock().unwrap().contains(&path) {
                    StatusCode::OK
                } else {
                    StatusCode::NOT_FOUND
                }
            } else if method == Method::DELETE {
                dav.stored.lock().unwrap().remove(&path);
                StatusCode::NO_CONTENT
            } else {
                StatusCode::METHOD_NOT_ALLOWED
            }
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://127.0.0.1:{port}/dav/"), dav)
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

/// A host with a write source on a fresh mock server, and a confirmed
/// booking ten days out. Returns (pool, mock, host id, booking id, uid).
async fn writeback_fixture(
    mode: DavMode,
) -> (SqlitePool, Arc<MockDav>, String, String, String) {
    let pool = setup_test_db().await;
    let host = insert_role_user(&pool, "host@wb.test", "user").await;
    let et_id = insert_personal_et(&pool, &host, "wb").await;
    let (base, dav) = spawn_mock_dav(mode).await;
    seed_write_source(&pool, &host, &base).await;
    let id = insert_v1_booking(
        &pool,
        &et_id,
        "guest@wb.test",
        Utc::now() + Duration::days(10),
        30,
        "confirmed",
        &[],
    )
    .await;
    let uid = format!("uid-{id}");
    (pool, dav, host, id, uid)
}

#[allow(clippy::type_complexity)]
async fn writeback_state(
    pool: &SqlitePool,
    id: &str,
) -> (Option<String>, i64, Option<String>, Option<String>, String) {
    sqlx::query_as(
        "SELECT writeback_error, writeback_attempts, writeback_next_attempt_at, caldav_calendar_href, status \
         FROM bookings WHERE id = ?",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap()
}

/// Push the booking the way a booking handler does.
async fn push_fresh(pool: &SqlitePool, host: &str, uid: &str) {
    let (details, _) = writeback::writeback_details(pool, uid).await.unwrap();
    caldav_push_booking(pool, &[0u8; 32], host, uid, &details).await;
}

#[test]
fn retry_schedule_backs_off_and_stops() {
    let now = Utc::now();
    assert_eq!(
        writeback::next_attempt_at(1, now),
        Some(now + Duration::minutes(5))
    );
    assert_eq!(
        writeback::next_attempt_at(2, now),
        Some(now + Duration::minutes(15))
    );
    assert_eq!(
        writeback::next_attempt_at(writeback::MAX_ATTEMPTS - 1, now),
        Some(now + Duration::minutes(480))
    );
    assert_eq!(writeback::next_attempt_at(writeback::MAX_ATTEMPTS, now), None);
    assert_eq!(writeback::next_attempt_at(0, now), None);
}

/// The #162 repro: the server accepts the PUT, the event is not there. The
/// booking stays confirmed, the failure is recorded and a retry scheduled.
#[tokio::test]
async fn unreadable_writeback_is_recorded_and_the_booking_stays_confirmed() {
    let (pool, dav, host, id, uid) = writeback_fixture(DavMode::Drop).await;
    push_fresh(&pool, &host, &uid).await;

    let (error, attempts, next, href, status) = writeback_state(&pool, &id).await;
    assert_eq!(status, "confirmed");
    let error = error.expect("the failure must be recorded");
    assert!(error.contains("not readable back"), "{error}");
    assert!(error.contains("Work calendar"), "names the source: {error}");
    assert_eq!(attempts, 1);
    assert!(next.is_some(), "a retry is scheduled");
    assert_eq!(
        href.as_deref(),
        Some("/dav/cal/"),
        "the write was accepted, so cancellation must still try to delete it"
    );
    assert_eq!(dav.puts(), 1);
}

/// A refused write is recorded too, and does not claim an href: there is
/// nothing on the calendar for a cancellation to delete.
#[tokio::test]
async fn refused_writeback_is_recorded_without_an_href() {
    let (pool, _dav, host, id, uid) = writeback_fixture(DavMode::Reject).await;
    push_fresh(&pool, &host, &uid).await;

    let (error, attempts, _, href, _) = writeback_state(&pool, &id).await;
    assert!(error.unwrap().contains("400"));
    assert_eq!(attempts, 1);
    assert_eq!(href, None);
}

#[tokio::test]
async fn verified_writeback_records_nothing() {
    let (pool, dav, host, id, uid) = writeback_fixture(DavMode::Ok).await;
    push_fresh(&pool, &host, &uid).await;

    let (error, attempts, next, href, _) = writeback_state(&pool, &id).await;
    assert_eq!(error, None);
    assert_eq!(attempts, 0);
    assert_eq!(next, None);
    assert_eq!(href.as_deref(), Some("/dav/cal/"));
    assert_eq!(dav.stored(), 1);
}

/// A retry that lands clears the failure, and retrying never duplicates the
/// event: the PUT is keyed on the booking uid.
#[tokio::test]
async fn retry_success_clears_the_error_without_duplicating() {
    let (pool, dav, host, id, uid) = writeback_fixture(DavMode::Drop).await;
    push_fresh(&pool, &host, &uid).await;
    assert!(writeback_state(&pool, &id).await.0.is_some());

    // Not due yet: nothing happens.
    assert_eq!(
        writeback::retry_failed_writebacks(&pool, &[0u8; 32], Utc::now()).await,
        0
    );

    dav.set_mode(DavMode::Ok);
    let later = Utc::now() + Duration::minutes(10);
    assert_eq!(
        writeback::retry_failed_writebacks(&pool, &[0u8; 32], later).await,
        1
    );
    let (error, attempts, next, _, status) = writeback_state(&pool, &id).await;
    assert_eq!(error, None);
    assert_eq!(attempts, 0);
    assert_eq!(next, None);
    assert_eq!(status, "confirmed");
    assert_eq!(dav.stored(), 1);

    // Nothing left to retry, and a second push replaces the same event.
    assert_eq!(
        writeback::retry_failed_writebacks(&pool, &[0u8; 32], later).await,
        0
    );
    push_fresh(&pool, &host, &uid).await;
    assert_eq!(dav.stored(), 1, "a re-push must not add a second event");
}

/// A booking cancelled (or declined) after its write-back failed is never
/// pushed again: retrying would put a cancelled meeting on the calendar.
#[tokio::test]
async fn cancelled_and_past_bookings_are_not_retried() {
    let (pool, dav, host, id, uid) = writeback_fixture(DavMode::Reject).await;
    push_fresh(&pool, &host, &uid).await;
    sqlx::query("UPDATE bookings SET status = 'cancelled' WHERE id = ?")
        .bind(&id)
        .execute(&pool)
        .await
        .unwrap();
    dav.set_mode(DavMode::Ok);
    let later = Utc::now() + Duration::hours(1);
    assert_eq!(
        writeback::retry_failed_writebacks(&pool, &[0u8; 32], later).await,
        0
    );
    assert_eq!(dav.puts(), 1, "only the original push");

    // Same for a confirmed booking whose start has passed.
    sqlx::query("UPDATE bookings SET status = 'confirmed' WHERE id = ?")
        .bind(&id)
        .execute(&pool)
        .await
        .unwrap();
    let after_start = Utc::now() + Duration::days(11);
    assert_eq!(
        writeback::retry_failed_writebacks(&pool, &[0u8; 32], after_start).await,
        0
    );
    assert_eq!(dav.puts(), 1);
}

/// Retries continue the attempt count and stop once it is used up.
#[tokio::test]
async fn retries_stop_after_the_last_attempt() {
    let (pool, dav, host, id, uid) = writeback_fixture(DavMode::Reject).await;
    push_fresh(&pool, &host, &uid).await;
    for _ in 1..writeback::MAX_ATTEMPTS {
        let later = Utc::now() + Duration::days(1);
        assert_eq!(
            writeback::retry_failed_writebacks(&pool, &[0u8; 32], later).await,
            1
        );
    }
    let (error, attempts, next, _, status) = writeback_state(&pool, &id).await;
    assert!(error.is_some());
    assert_eq!(attempts, writeback::MAX_ATTEMPTS);
    assert_eq!(next, None, "no retry after the last attempt");
    assert_eq!(status, "confirmed");
    assert_eq!(
        writeback::retry_failed_writebacks(&pool, &[0u8; 32], Utc::now() + Duration::days(2))
            .await,
        0
    );
    assert_eq!(dav.puts() as i64, writeback::MAX_ATTEMPTS);
}
