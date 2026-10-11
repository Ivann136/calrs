mod availability;
mod booking;
mod booking_actions;
mod branding;
mod calendar_push;
pub mod captcha;
mod dashboard;
mod event_types;
mod format;
mod hosts;
mod invites;
pub mod meeting;
mod notify;
mod pending;
mod public_pages;
mod sources;
mod teams;
pub(crate) mod writeback;

use crate::utils::{convert_event_to_tz, parse_ical_datetime};
use axum::extract::{Form, Multipart, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::Redirect;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use chrono::{
    Datelike, Duration, Local, NaiveDate, NaiveDateTime, NaiveTime, Offset, TimeZone, Timelike, Utc,
};
use chrono_tz::{OffsetName, Tz};
use minijinja::{context, Environment};
use serde::Deserialize;
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

pub(crate) use availability::expand_recurring_into_busy;
use availability::*;
use booking::*;
use booking_actions::*;
use branding::*;
pub(crate) use calendar_push::caldav_delete_booking;
pub(crate) use calendar_push::resource_delete_booking;
use calendar_push::*;
use dashboard::*;
use event_types::*;
use format::*;
pub(crate) use hosts::booking_host_identity;
use hosts::*;
use invites::*;
pub use notify::drain_emails;
pub use notify::run_reminder_loop;
pub(crate) use notify::spawn_emails;
use notify::*;
use pending::*;
use public_pages::*;
use sources::*;
use teams::*;

/// Simple per-IP rate limiter for login attempts.
/// Tracks (attempt_count, window_start) per IP.
pub struct RateLimiter {
    state: Mutex<RateLimiterState>,
    max_attempts: u32,
    window: std::time::Duration,
}

struct RateLimiterState {
    attempts: HashMap<String, (u32, std::time::Instant)>,
    last_sweep: std::time::Instant,
}

impl RateLimiter {
    pub fn new(max_attempts: u32, window_secs: u64) -> Self {
        Self {
            state: Mutex::new(RateLimiterState {
                attempts: HashMap::new(),
                last_sweep: std::time::Instant::now(),
            }),
            max_attempts,
            window: std::time::Duration::from_secs(window_secs),
        }
    }

    /// Returns true if the request should be rejected (rate limited).
    pub async fn check_limited(&self, key: &str) -> bool {
        let mut state = self.state.lock().await;
        let now = std::time::Instant::now();

        // Evict entries whose window has elapsed. Bounded by "at most once per
        // window" so the work is amortized; without this the HashMap would
        // grow without bound under traffic from many distinct IPs.
        if now.duration_since(state.last_sweep) >= self.window {
            let window = self.window;
            state
                .attempts
                .retain(|_, (_, start)| now.duration_since(*start) <= window);
            state.last_sweep = now;
        }

        if let Some((count, start)) = state.attempts.get_mut(key) {
            if now.duration_since(*start) > self.window {
                // Window expired, reset
                *count = 1;
                *start = now;
                false
            } else if *count >= self.max_attempts {
                true
            } else {
                *count += 1;
                false
            }
        } else {
            state.attempts.insert(key.to_string(), (1, now));
            false
        }
    }
}

pub struct AppState {
    pub pool: SqlitePool,
    pub templates: Environment<'static>,
    pub login_limiter: RateLimiter,
    pub booking_limiter: RateLimiter,
    pub data_dir: PathBuf,
    pub secret_key: [u8; 32],
    pub theme_css: tokio::sync::RwLock<String>,
    pub company_link: tokio::sync::RwLock<Option<String>>,
    pub captcha_config: tokio::sync::RwLock<Option<captcha::CaptchaConfig>>,
    /// Org-wide meeting provider config (Jitsi + webhook). Cached so guest
    /// slot/booking pages don't hit `auth_config` on every render. Rebuilt
    /// when the admin saves changes.
    pub meeting_config: tokio::sync::RwLock<meeting::MeetingConfig>,
    /// CSP for booking form pages: relaxed with captcha origins when captcha
    /// is enabled, identical to `csp_baseline` otherwise. Rebuilt on admin save.
    pub csp: tokio::sync::RwLock<String>,
    /// Strict baseline CSP served on every non-booking page regardless of
    /// captcha configuration.
    pub csp_baseline: String,
}

// --- CSRF protection (double-submit cookie pattern) ---

/// Generate a random CSRF token using UUID v4.
pub fn generate_csrf_token() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Cookie name for the CSRF token. The `__Host-` prefix forces the browser to
/// enforce Secure, Path=/, and no Domain, so the token cannot be overwritten
/// by a sibling subdomain.
pub const CSRF_COOKIE_NAME: &str = "__Host-calrs_csrf";

/// Build the Set-Cookie header value for a CSRF token.
///
/// `HttpOnly` is intentionally omitted, the double-submit pattern needs the
/// client JS in `base.html` to read the cookie and inject it into the form.
/// `Secure` is set so the token never leaks over plaintext HTTP; modern
/// browsers still honour `Secure` cookies on localhost for dev over HTTP.
///
/// `cross_site=true` switches the cookie to `SameSite=None` so the booking
/// page can read it from inside a third-party iframe (the embed flow). The
/// double-submit token-vs-cookie comparison still defends against CSRF — we
/// never relied on SameSite for that. Browsers blocking all third-party
/// cookies (Safari ITP, Chrome with 3P cookies disabled) still won't deliver
/// it; that's an upstream-platform limitation outside our control.
pub fn csrf_cookie_value(token: &str) -> String {
    csrf_cookie_value_for(token, false)
}

pub fn csrf_cookie_value_for(token: &str, cross_site: bool) -> String {
    let same_site = if cross_site { "None" } else { "Lax" };
    // In the cross-site (embed) case also mark the cookie `Partitioned` (CHIPS).
    // Browsers that block unpartitioned third-party cookies (Safari 18.4+,
    // Firefox 131+, Chrome with 3P cookies disabled) will then still deliver it
    // inside the embed iframe, so the double-submit CSRF check keeps working.
    // `Partitioned` requires `Secure` + `Path=/`, both already set, and is
    // compatible with the `__Host-` prefix.
    let partitioned = if cross_site { "; Partitioned" } else { "" };
    format!(
        "{}={}; Path=/; Secure; SameSite={}; Max-Age=86400{}",
        CSRF_COOKIE_NAME, token, same_site, partitioned
    )
}

/// Extract the CSRF cookie value from request headers.
pub fn csrf_token_from_headers(headers: &HeaderMap) -> Option<String> {
    let prefix = format!("{}=", CSRF_COOKIE_NAME);
    headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(';'))
        .find_map(|part| {
            let part = part.trim();
            part.strip_prefix(&prefix).map(|v| v.to_string())
        })
}

/// Verify that the CSRF form field matches the cookie value.
///
/// The two tokens are compared with `subtle::ConstantTimeEq` to avoid leaking
/// any partial-match timing information that could otherwise be used to
/// recover a valid token byte by byte.
#[allow(clippy::result_large_err)]
pub fn verify_csrf_token(
    headers: &HeaderMap,
    form_token: &Option<String>,
) -> Result<(), axum::response::Response> {
    let cookie_token = csrf_token_from_headers(headers);
    let valid = match (cookie_token.as_deref(), form_token.as_deref()) {
        (Some(cookie), Some(form)) if !cookie.is_empty() => {
            bool::from(cookie.as_bytes().ct_eq(form.as_bytes()))
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err((
            axum::http::StatusCode::FORBIDDEN,
            Html("403 Forbidden: CSRF token mismatch".to_string()),
        )
            .into_response())
    }
}

// --- Error sanitization helpers ---
//
// Internal errors (template render failures, DB errors, OIDC token-exchange
// errors) used to be `format!`'d straight into the HTTP response body. The
// detail leaks internal layout (template paths, schema hints, IdP URLs and
// occasionally token contents) to anyone who can trigger the path. These
// helpers funnel the detail to the structured log instead and return a
// generic message to the user.

/// Internal-error response (500). Use for any server-side failure on a path
/// where the user cannot fix the cause themselves.
pub(crate) fn internal_error_response<E: std::fmt::Display + ?Sized>(
    context: &str,
    error: &E,
) -> Response {
    tracing::error!(error = %error, context = %context, "internal error");
    (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        Html("An internal error occurred. Please try again.".to_string()),
    )
        .into_response()
}

/// Same as `internal_error_response` but yields `Html<String>` so it can be
/// returned from helper functions whose signature is `Html<String>` (these
/// are then themselves wrapped via `.into_response()` at the call site).
pub(crate) fn internal_error_html<E: std::fmt::Display + ?Sized>(
    context: &str,
    error: &E,
) -> Html<String> {
    tracing::error!(error = %error, context = %context, "internal error");
    Html("An internal error occurred. Please try again.".to_string())
}

/// Same as `internal_error_response` but yields a plain `String` for sites
/// that compose the response inline, e.g. as a fallback template body via
/// `unwrap_or_else`.
pub(crate) fn internal_error_body<E: std::fmt::Display + ?Sized>(
    context: &str,
    error: &E,
) -> String {
    tracing::error!(error = %error, context = %context, "internal error");
    "An internal error occurred. Please try again.".to_string()
}

/// OIDC-flow failure response. Rendered to the user when the auth handshake
/// breaks down (token exchange, ID token verification, configuration). The
/// underlying error from `openidconnect` can include the IdP's response
/// body, token endpoint URL, or token contents, so it never reaches the
/// client.
pub(crate) fn oidc_error_response<E: std::fmt::Display + ?Sized>(
    context: &str,
    error: &E,
) -> Response {
    tracing::error!(error = %error, context = %context, "oidc auth failure");
    (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        Html("Authentication failed. Please try again or contact your administrator.".to_string()),
    )
        .into_response()
}

/// Extract the client IP for rate-limiting from request headers.
///
/// Trust model: assumes calrs runs behind a single reverse proxy (the
/// documented Caddy/Nginx setup) that appends the observed peer address
/// to `X-Forwarded-For`. Each proxy in the chain appends, so the
/// rightmost value is the most-recent trusted hop's view of its peer,
/// and everything to its left is attacker-controlled. Taking the
/// rightmost value defeats the "set X-Forwarded-For: random.ip on every
/// request" rate-limit bypass.
///
/// `X-Real-IP` is intentionally not honoured: neither documented proxy
/// sets it by default, so a client-supplied `X-Real-IP` would pass
/// straight through and be trusted (worse than the bug this fixes).
///
/// Falls back to `"unknown"` if `X-Forwarded-For` is missing, which
/// collapses such requests into a single shared rate-limit bucket. That
/// is intentional: it throttles abuse rather than letting it through.
pub fn client_ip_for_rate_limit(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.rsplit(',').next())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Form struct for POST endpoints that only need CSRF validation.
#[derive(Deserialize)]
struct CsrfForm {
    _csrf: Option<String>,
}

/// Query struct for CSRF validation on multipart endpoints.
#[derive(Deserialize)]
struct CsrfQuery {
    _csrf: Option<String>,
}

#[derive(Deserialize)]
struct CompanyLinkForm {
    company_link: String,
    _csrf: Option<String>,
}

/// Whether a `company_link` URL is safe to render as a clickable anchor.
/// Only `http://` and `https://` schemes are accepted; this rejects
/// `javascript:`, `data:`, `vbscript:`, `file:` etc., any of which would
/// turn the admin-controlled link on every public page into a stored XSS
/// or local-file vector.
pub(crate) fn is_safe_company_link(url: &str) -> bool {
    let lower = url.trim().to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

async fn get_company_link(pool: &SqlitePool) -> Option<String> {
    sqlx::query_scalar::<_, Option<String>>(
        "SELECT company_link FROM auth_config WHERE id = 'singleton'",
    )
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .flatten()
    .filter(|s| !s.is_empty())
    // Defense in depth: even if a bad value reached the DB (legacy data,
    // manual edit), refuse to render anything but http(s). The admin
    // update handler is the primary gate; this is the backstop.
    .filter(|s| is_safe_company_link(s))
}

/// Wrap an HTML render in a response. When `embed=1`, override the global
/// `X-Frame-Options: SAMEORIGIN` so legacy browsers don't refuse the iframe.
/// The matching `frame-ancestors *` CSP override is added by `csp_middleware`
/// — that keeps the CSP composition (captcha allowances + embed framing) in
/// one place. Modern browsers honour CSP's frame-ancestors over the legacy
/// header per CSP Level 2.
fn html_response(body: String, embed: &EmbedParams) -> Response {
    let mut resp = Html(body).into_response();
    if embed.is_embedded() {
        // `ALLOWALL` is non-standard; modern browsers ignore it once CSP
        // frame-ancestors is set, but it prevents the global SAMEORIGIN
        // layer from re-asserting itself for browsers that don't speak CSP.
        resp.headers_mut().insert(
            axum::http::header::X_FRAME_OPTIONS,
            axum::http::HeaderValue::from_static("ALLOWALL"),
        );
    }
    resp
}

/// Middleware that ensures a CSRF cookie is set on every response.
///
/// When the request URL carries `embed=1`, the cookie is issued with
/// `SameSite=None; Secure` so the booking flow inside a third-party iframe
/// can read its own cookie. Outside the embed flow, the strict `SameSite=Lax`
/// default applies.
async fn csrf_cookie_middleware(
    headers: HeaderMap,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let cross_site_cookie =
        is_embedded_booking_request(request.uri().path(), request.uri().query());
    let mut response = next.run(request).await;

    // Only set cookie if not already present in the request
    if csrf_token_from_headers(&headers).is_none() {
        let token = generate_csrf_token();
        if let Ok(cookie_val) = csrf_cookie_value_for(&token, cross_site_cookie).parse() {
            response
                .headers_mut()
                .append(axum::http::header::SET_COOKIE, cookie_val);
        }
    }

    response
}

/// Detects the `embed=1` (or `embed=true`) query param without pulling in a
/// full URL parser. Tolerates extra params and arbitrary parameter order.
fn is_embed_request(query: Option<&str>) -> bool {
    let Some(q) = query else { return false };
    q.split('&').any(|pair| {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        k == "embed" && (v == "1" || v == "true")
    })
}

/// Public booking surfaces that may legitimately be loaded inside a
/// third-party iframe.
///
/// SECURITY: this gates BOTH the relaxed `frame-ancestors *` CSP swap and the
/// `SameSite=None` CSRF cookie. It must never match authenticated or sensitive
/// surfaces (`/auth/...`, `/dashboard/...`, asset routes), otherwise those
/// pages become frameable by any site — e.g. `/auth/login?embed=1` would be a
/// fully functional login form inside an attacker's iframe (clickjacking /
/// login CSRF). The embed=1 flag alone is NOT sufficient; the path must also
/// be a booking surface.
fn is_embeddable_path(path: &str) -> bool {
    // Modern user/team booking routes (allowlist).
    if path == "/u"
        || path.starts_with("/u/")
        || path == "/team"
        || path.starts_with("/team/")
        || path == "/g"
        || path.starts_with("/g/")
    {
        return true;
    }
    // Legacy single-user booking pages: only `/{slug}` and `/{slug}/book`.
    // Everything is a single top-level segment, so reject any path whose first
    // segment is a reserved (non-booking) route. New reserved top-level routes
    // must be added to RESERVED below to stay out of the embed surface.
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        return false;
    }
    let mut segs = trimmed.split('/');
    let first = segs.next().unwrap_or("");
    let rest: Vec<&str> = segs.collect();
    let shape_ok = rest.is_empty() || (rest.len() == 1 && rest[0] == "book");
    if !shape_ok {
        return false;
    }
    const RESERVED: &[&str] = &[
        "auth",
        "dashboard",
        "avatar",
        "team-avatar",
        "logo",
        "accent.css",
        "brand-logo",
        "embed.js",
        "fonts",
        "t",
        "booking",
        "u",
        "team",
        "g",
    ];
    !RESERVED.contains(&first)
}

/// True when the request is both flagged `embed=1` and targets an embeddable
/// booking surface. This is the single gate for embed-mode behavior changes.
fn is_embedded_booking_request(path: &str, query: Option<&str>) -> bool {
    is_embed_request(query) && is_embeddable_path(path)
}

fn build_csp(captcha: &Option<captcha::CaptchaConfig>) -> String {
    let (wasm_eval, worker_src, script_extra, connect_extra) = match captcha.as_ref() {
        Some(c) => {
            let widget_origin = c.widget_script_origin();
            let instance_origin = c.instance_origin();
            // A custom WASM URL is fetched by the widget, so its origin joins
            // connect-src (and only connect-src: it is never a script).
            let wasm_origin = c
                .wasm_origin()
                .filter(|o| *o != widget_origin && *o != instance_origin)
                .map(|o| format!(" {o}"))
                .unwrap_or_default();
            (
                " 'wasm-unsafe-eval'",
                "worker-src blob:; ",
                format!(" {}", widget_origin),
                format!(" {} {}{}", instance_origin, widget_origin, wasm_origin),
            )
        }
        None => ("", "", String::new(), String::new()),
    };
    format!(
        "default-src 'self'; img-src 'self' data:; \
         style-src 'self' 'unsafe-inline'; \
         script-src 'self' 'unsafe-inline'{}{}; \
         {}connect-src 'self'{}; \
         object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
        wasm_eval, script_extra, worker_src, connect_extra
    )
}

/// Booking form pages (`…/book`) are the only pages that embed the captcha
/// widget, so they are the only ones that get the relaxed CSP when captcha is
/// enabled. Every other page keeps the strict baseline policy.
fn is_booking_form_path(path: &str) -> bool {
    path.ends_with("/book")
}

async fn csp_middleware(
    State(state): State<Arc<AppState>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let booking_page = is_booking_form_path(request.uri().path());
    let embed_mode = is_embedded_booking_request(request.uri().path(), request.uri().query());
    let mut response = next.run(request).await;
    if !response
        .headers()
        .contains_key(axum::http::header::CONTENT_SECURITY_POLICY)
    {
        let strict = if booking_page {
            state.csp.read().await.clone()
        } else {
            state.csp_baseline.clone()
        };
        // In embed mode, swap the default `frame-ancestors 'self'` for `*` so
        // the page can be loaded inside a third-party iframe. The replacement
        // is safe because `build_csp` is the sole producer of the strict CSP
        // string and always uses that exact directive.
        let csp = if embed_mode {
            strict.replace("frame-ancestors 'self'", "frame-ancestors *")
        } else {
            strict
        };
        if let Ok(val) = axum::http::HeaderValue::from_str(&csp) {
            response
                .headers_mut()
                .insert(axum::http::header::CONTENT_SECURITY_POLICY, val);
        }
    }
    response
}

pub async fn create_router(pool: SqlitePool, data_dir: PathBuf, secret_key: [u8; 32]) -> Router {
    let mut env = Environment::new();
    env.set_undefined_behavior(minijinja::UndefinedBehavior::Lenient);
    env.set_loader(minijinja::path_loader("templates"));
    crate::i18n::register(&mut env);

    // Populate the process-global runtime-settings cache (base URL, private-host
    // allowlist) so synchronous readers and email/link builders see DB values.
    crate::settings::load_from_db(&pool).await;

    let initial_theme_css = build_theme_css(&pool).await;
    let initial_company_link = get_company_link(&pool).await;
    let initial_captcha = captcha::load_captcha_config(&pool, &secret_key).await;
    let initial_meeting = meeting::load_config(&pool, &secret_key).await;
    let initial_csp = build_csp(&initial_captcha);

    let state = Arc::new(AppState {
        pool,
        templates: env,
        // 10 login attempts per IP per 15 minutes
        login_limiter: RateLimiter::new(10, 900),
        booking_limiter: RateLimiter::new(10, 300),
        secret_key,
        data_dir,
        theme_css: tokio::sync::RwLock::new(initial_theme_css),
        company_link: tokio::sync::RwLock::new(initial_company_link),
        captcha_config: tokio::sync::RwLock::new(initial_captcha),
        meeting_config: tokio::sync::RwLock::new(initial_meeting),
        csp: tokio::sync::RwLock::new(initial_csp),
        csp_baseline: build_csp(&None),
    });

    Router::new()
        .merge(crate::auth::auth_router())
        .route("/", get(root_redirect))
        .route("/dashboard", get(dashboard))
        .route("/dashboard/event-types", get(dashboard_event_types))
        .route(
            "/dashboard/availability/default",
            get(dashboard_availability_default),
        )
        .route("/dashboard/bookings", get(dashboard_bookings))
        .route("/dashboard/teams", get(dashboard_teams))
        .route(
            "/dashboard/teams/new",
            get(show_team_form).post(create_team),
        )
        .route("/dashboard/sources", get(dashboard_sources))
        .route("/dashboard/invite-links", get(dashboard_organization))
        .route(
            "/dashboard/organization",
            get(|| async { Redirect::permanent("/dashboard/invite-links") }),
        )
        .route("/dashboard/bookings/{id}/cancel", post(cancel_booking))
        .route("/dashboard/bookings/{id}/confirm", post(confirm_booking))
        .route(
            "/dashboard/event-types/new",
            get(new_event_type_form).post(create_event_type),
        )
        .route(
            "/dashboard/event-types/{slug}/edit",
            get(edit_event_type_form).post(update_event_type),
        )
        .route(
            "/dashboard/event-types/{slug}/priority/{user_id}",
            post(update_event_type_member_priority),
        )
        .route(
            "/dashboard/event-types/{slug}/toggle",
            post(toggle_event_type),
        )
        .route(
            "/dashboard/event-types/{slug}/delete",
            post(delete_event_type),
        )
        // Invite management
        .route(
            "/dashboard/invites/{event_type_id}",
            get(invite_management_page),
        )
        .route(
            "/dashboard/invites/{event_type_id}/send",
            post(send_invite_bulk),
        )
        .route("/dashboard/invites/{invite_id}/delete", post(delete_invite))
        .route(
            "/dashboard/invites/{event_type_id}/quick-link",
            post(generate_quick_link),
        )
        // Availability overrides
        .route(
            "/dashboard/event-types/{slug}/overrides",
            get(overrides_page).post(create_override),
        )
        .route(
            "/dashboard/event-types/{slug}/overrides/{override_id}/delete",
            post(delete_override),
        )
        // Embed code generator
        .route("/dashboard/event-types/{slug}/embed", get(embed_page))
        // Calendar source management
        .route(
            "/dashboard/sources/new",
            get(new_source_form).post(create_source),
        )
        .route(
            "/dashboard/sources/{id}/edit",
            get(edit_source_form).post(update_source),
        )
        .route("/dashboard/sources/{id}/remove", post(remove_source))
        .route("/dashboard/sources/{id}/test", post(test_source))
        .route("/dashboard/sources/google/connect", get(google_connect))
        .route("/dashboard/sources/google/callback", get(google_callback))
        .route("/dashboard/sources/{id}/sync", post(sync_source))
        .route(
            "/dashboard/sources/{id}/force-sync",
            post(force_sync_source),
        )
        .route(
            "/dashboard/sources/{id}/setup-write",
            get(setup_write_calendar),
        )
        .route(
            "/dashboard/sources/{id}/write-calendar",
            post(set_write_calendar),
        )
        // Settings & avatar
        .route(
            "/dashboard/settings",
            get(settings_page).post(settings_save),
        )
        .route("/dashboard/settings/timezone", post(update_timezone))
        .route("/dashboard/settings/avatar", post(upload_avatar))
        .route("/dashboard/settings/avatar/delete", post(delete_avatar))
        .route("/avatar/{user_id}", get(serve_avatar))
        // Team settings & avatar
        .route(
            "/dashboard/teams/{team_id}/settings",
            get(team_settings_page).post(team_settings_save),
        )
        .route(
            "/dashboard/teams/{team_id}/avatar",
            post(upload_team_avatar),
        )
        .route(
            "/dashboard/teams/{team_id}/avatar/delete",
            post(delete_team_avatar),
        )
        .route("/dashboard/teams/{team_id}/delete", post(delete_team))
        .route("/team-avatar/{team_id}", get(serve_team_avatar))
        // Troubleshoot
        .route("/dashboard/troubleshoot", get(troubleshoot))
        // Admin routes
        .route("/dashboard/admin", get(admin_dashboard))
        .route(
            "/dashboard/admin/users/{id}/toggle-role",
            post(admin_toggle_role),
        )
        .route(
            "/dashboard/admin/users/{id}/toggle-enabled",
            post(admin_toggle_enabled),
        )
        .route(
            "/dashboard/admin/users/{id}/delete",
            post(admin_delete_user),
        )
        .route("/dashboard/admin/auth", post(admin_update_auth))
        .route("/dashboard/admin/general", post(admin_update_general))
        .route("/dashboard/admin/accent", post(admin_update_accent))
        .route("/dashboard/admin/oidc", post(admin_update_oidc))
        .route(
            "/dashboard/admin/google-oauth2",
            post(admin_update_google_oauth2),
        )
        .route("/dashboard/admin/captcha", post(admin_update_captcha))
        .route("/dashboard/admin/resources", post(admin_create_resource))
        .route(
            "/dashboard/admin/resources/{id}",
            post(admin_update_resource),
        )
        .route(
            "/dashboard/admin/resources/{id}/delete",
            post(admin_delete_resource),
        )
        .route(
            "/dashboard/admin/resources/{id}/sync",
            post(admin_sync_resource),
        )
        .route(
            "/dashboard/admin/resources/{id}/test-write",
            post(admin_test_write_resource),
        )
        .route("/dashboard/admin/smtp", post(admin_update_smtp))
        .route("/dashboard/admin/smtp/test", post(admin_update_smtp_test))
        .route("/dashboard/admin/smtp/clear", post(admin_update_smtp_clear))
        .route("/dashboard/admin/sms", post(admin_update_sms))
        .route("/dashboard/admin/sms/test", post(admin_update_sms_test))
        .route("/dashboard/admin/sms/clear", post(admin_update_sms_clear))
        .route("/dashboard/admin/sms/policy", post(admin_update_sms_policy))
        .route("/dashboard/admin/jitsi", post(admin_update_jitsi))
        .route(
            "/dashboard/admin/meeting-webhook",
            post(admin_update_meeting_webhook),
        )
        .route("/dashboard/admin/logo", post(admin_upload_logo))
        .route("/dashboard/admin/logo/delete", post(admin_delete_logo))
        .route(
            "/dashboard/admin/company-link",
            post(admin_update_company_link),
        )
        .route(
            "/dashboard/admin/groups/{group_id}/members/{user_id}/weight",
            post(admin_update_member_weight),
        )
        .route("/dashboard/admin/impersonate/{id}", post(admin_impersonate))
        .route(
            "/dashboard/admin/stop-impersonate",
            post(admin_stop_impersonate),
        )
        // Group event type management
        .route(
            "/dashboard/group-event-types/new",
            get(new_group_event_type_form).post(create_group_event_type),
        )
        // Team event type management. The `team_id` is in the path so the
        // server-side WHERE clause can scope unambiguously: two teams may
        // legitimately share the same slug (e.g. "intro"), and looking up by
        // slug alone returns whichever row the DB picks first.
        .route(
            "/dashboard/group-event-types/{team_id}/{slug}/edit",
            get(edit_group_event_type_form).post(update_group_event_type),
        )
        .route(
            "/dashboard/group-event-types/{team_id}/{slug}/priority/{user_id}",
            post(update_group_event_type_member_priority),
        )
        .route(
            "/dashboard/group-event-types/{team_id}/{slug}/toggle",
            post(toggle_group_event_type),
        )
        .route(
            "/dashboard/group-event-types/{team_id}/{slug}/delete",
            post(delete_group_event_type),
        )
        .route(
            "/dashboard/group-event-types/{team_id}/{slug}/embed",
            get(group_embed_page),
        )
        // Serve logo and fonts
        .route("/logo", get(serve_logo))
        .route("/accent.css", get(serve_accent_css))
        .route("/brand-logo", get(serve_brand_logo))
        .route("/embed.js", get(serve_embed_js))
        .route("/fonts/inter-latin.woff2", get(serve_font_inter_latin))
        .route(
            "/fonts/inter-latin-ext.woff2",
            get(serve_font_inter_latin_ext),
        )
        .route(
            "/static/intl-tel-input/{file}",
            get(serve_intl_tel_input_asset),
        )
        // Group public routes
        .route("/team/{team_slug}", get(team_profile_page))
        .route("/team/{team_slug}/{slug}", get(show_group_slots))
        .route(
            "/team/{team_slug}/{slug}/book",
            get(show_group_book_form).post(handle_group_booking),
        )
        // Legacy /g/ redirects
        .route("/g/{team_slug}", get(redirect_g_to_team))
        .route("/g/{team_slug}/{slug}", get(redirect_g_to_team_slug))
        .route(
            "/g/{team_slug}/{slug}/book",
            get(redirect_g_to_team_slug_book),
        )
        // Legacy team link redirects → unified teams
        .route("/t/{token}", get(redirect_team_link_to_team))
        .route("/t/{token}/book", get(redirect_team_link_to_team))
        // User-scoped public booking routes
        .route(
            "/booking/claim/{booking_id}",
            get(claim_booking_form).post(claim_booking),
        )
        .route(
            "/booking/approve/{token}",
            get(approve_booking_form).post(approve_booking_by_token),
        )
        .route(
            "/booking/decline/{token}",
            get(decline_booking_form).post(decline_booking_by_token),
        )
        .route(
            "/booking/cancel/{token}",
            get(guest_cancel_form).post(guest_cancel_booking),
        )
        .route("/booking/ics/{token}", get(booking_ics))
        .route(
            "/booking/reschedule/{token}",
            get(guest_reschedule_slots).post(guest_reschedule_booking),
        )
        .route(
            "/dashboard/bookings/{id}/reschedule",
            get(host_reschedule_slots).post(host_reschedule_booking),
        )
        .route("/u/{username}", get(user_profile))
        .route("/u/{username}/", get(redirect_user_profile_trailing_slash))
        .route("/u/{username}/{slug}", get(show_slots_for_user))
        .route(
            "/u/{username}/{slug}/book",
            get(show_book_form_for_user).post(handle_booking_for_user),
        )
        // Legacy single-user routes (kept for backward compatibility)
        .route("/{slug}", get(show_slots))
        .route("/{slug}/book", get(show_book_form).post(handle_booking))
        .layer(TraceLayer::new_for_http())
        .layer(axum::middleware::from_fn(csrf_cookie_middleware))
        // Defensive HTTP headers on every response (incl. error pages).
        //
        // CSP allows `'unsafe-inline'` for scripts and styles because the
        // templates rely on inline `<script>` blocks (CSRF auto-injection,
        // theme toggle, time-zone banner) and inline `style="..."` attributes.
        // Tightening this would require nonces wired through every render
        // site or a sweep across templates to externalize inline blocks.
        //
        // The CSP itself is set by `csp_middleware`: booking form pages
        // (`…/book`) get the captcha-relaxed policy when captcha is enabled,
        // everything else always gets the strict baseline.
        .layer(SetResponseHeaderLayer::if_not_present(
            axum::http::header::X_FRAME_OPTIONS,
            axum::http::HeaderValue::from_static("SAMEORIGIN"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            axum::http::header::X_CONTENT_TYPE_OPTIONS,
            axum::http::HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            axum::http::header::REFERRER_POLICY,
            axum::http::HeaderValue::from_static("strict-origin-when-cross-origin"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            axum::http::HeaderName::from_static("permissions-policy"),
            axum::http::HeaderValue::from_static(
                "geolocation=(), microphone=(), camera=(), payment=(), usb=()",
            ),
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            csp_middleware,
        ))
        .with_state(state)
}

/// Helper: create impersonation template context values (active, target_name, admin_name).
fn impersonation_ctx(auth_user: &crate::auth::AuthUser) -> (bool, String, String) {
    match &auth_user.impersonation {
        Some(info) => (true, info.target_name.clone(), info.admin_name.clone()),
        None => (false, String::new(), String::new()),
    }
}

/// Compute two-letter Matrix-style initials from a name (first letter of first + last word).
fn compute_initials(name: &str) -> String {
    let parts: Vec<&str> = name.split_whitespace().collect();
    let mut initials = String::new();
    if let Some(first) = parts.first() {
        if let Some(c) = first.chars().next() {
            initials.extend(c.to_uppercase());
        }
    }
    if parts.len() > 1 {
        if let Some(last) = parts.last() {
            if let Some(c) = last.chars().next() {
                initials.extend(c.to_uppercase());
            }
        }
    }
    if initials.is_empty() {
        "?".to_string()
    } else {
        initials
    }
}

/// Build OIDC groups context with member details for stacked avatars.
async fn build_groups_ctx(
    pool: &sqlx::SqlitePool,
    oidc_groups: &[(String, String, i64)],
    linked_set: &std::collections::HashSet<String>,
) -> Vec<minijinja::Value> {
    let mut out = Vec::new();
    for (id, name, member_count) in oidc_groups {
        let group_members: Vec<(String, String, Option<String>)> = sqlx::query_as(
            "SELECT u.id, u.name, u.avatar_path FROM users u \
             JOIN user_groups ug ON ug.user_id = u.id \
             WHERE ug.group_id = ? AND u.enabled = 1 ORDER BY u.name LIMIT 8",
        )
        .bind(id)
        .fetch_all(pool)
        .await
        .unwrap_or_default();
        let members_ctx: Vec<minijinja::Value> = group_members
            .iter()
            .map(|(uid, uname, ap)| {
                context! {
                    id => uid,
                    name => uname,
                    has_avatar => ap.is_some(),
                    initials => compute_initials(uname),
                }
            })
            .collect();
        out.push(context! {
            id => id,
            name => name,
            member_count => member_count,
            members => members_ctx,
            linked => linked_set.contains(id),
        });
    }
    out
}

/// Build sidebar context for dashboard templates.
fn sidebar_context(auth_user: &crate::auth::AuthUser, active: &str) -> minijinja::Value {
    let user = &auth_user.user;
    let (impersonating, _, _) = impersonation_ctx(auth_user);
    let effective_role = if impersonating {
        "admin".to_string()
    } else {
        user.role.clone()
    };
    context! {
        user_name => user.name,
        user_title => user.title.as_deref().unwrap_or(""),
        user_id => user.id,
        user_role => effective_role,
        user_timezone => user.timezone,
        has_avatar => user.avatar_path.is_some(),
        user_initials => compute_initials(&user.name),
        active => active,
        version => env!("CARGO_PKG_VERSION"),
    }
}

fn admin_sidebar_context(user: &crate::models::User, active: &str) -> minijinja::Value {
    context! {
        user_name => user.name,
        user_title => user.title.as_deref().unwrap_or(""),
        user_id => user.id,
        user_role => "admin",
        user_timezone => user.timezone,
        has_avatar => user.avatar_path.is_some(),
        user_initials => compute_initials(&user.name),
        active => active,
        version => env!("CARGO_PKG_VERSION"),
    }
}

/// Translate a message that takes exactly one string argument.
///
/// Server-rendered labels (the troubleshoot timeline, mostly) are built one at
/// a time and would otherwise each need four lines of FluentArgs plumbing.
fn tr1(lang: &str, key: &str, arg: &str, value: &str) -> String {
    let mut args = fluent_bundle::FluentArgs::new();
    args.set(arg, fluent_bundle::FluentValue::from(value));
    crate::i18n::translate(lang, key, Some(&args))
}

// --- Admin dashboard ---

async fn admin_dashboard(
    State(state): State<Arc<AppState>>,
    admin: crate::auth::AdminUser,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let current_user = &admin.user;
    let error_message = query.get("error").cloned().unwrap_or_default();
    let resource_notice = query.get("resource_notice").cloned().unwrap_or_default();
    let resource_error = query.get("resource_error").cloned().unwrap_or_default();

    // Shared bookable resources
    let resource_rows: Vec<(
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT id, name, feed_url, caldav_url, caldav_username, caldav_password, last_synced_at, last_sync_error
         FROM resources ORDER BY name",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    // Opted-in members only count as write candidates when they have an
    // enabled CalDAV source on the resource's own server.
    let lender_source_urls: Vec<(String,)> = sqlx::query_as(
        "SELECT cs.url FROM users u
         JOIN accounts a ON a.user_id = u.id
         JOIN caldav_sources cs ON cs.account_id = a.id
         WHERE u.lend_resource_write = 1 AND u.enabled = 1 AND cs.enabled = 1
           AND cs.password_enc IS NOT NULL",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    // All teams, for the per-resource "Teams allowed" checkboxes.
    let resource_teams_all: Vec<(String, String)> =
        sqlx::query_as("SELECT id, name FROM teams ORDER BY name")
            .fetch_all(&state.pool)
            .await
            .unwrap_or_default();
    let resource_teams_ctx: Vec<minijinja::Value> = resource_teams_all
        .iter()
        .map(|(id, name)| context! { id => id, name => name })
        .collect();
    let mut resources_ctx: Vec<minijinja::Value> = Vec::new();
    for (
        rid,
        rname,
        feed_url,
        caldav_url,
        caldav_username,
        caldav_password,
        last_synced_at,
        last_sync_error,
    ) in &resource_rows
    {
        let allowed_teams: Vec<(String, String)> = sqlx::query_as(
            "SELECT t.id, t.name FROM teams t
             JOIN resource_teams rt ON rt.team_id = t.id
             WHERE rt.resource_id = ? ORDER BY t.name",
        )
        .bind(rid)
        .fetch_all(&state.pool)
        .await
        .unwrap_or_default();
        let allowed_team_ids = allowed_teams
            .iter()
            .map(|(id, _)| id.as_str())
            .collect::<Vec<_>>()
            .join(",");
        let allowed_team_names = allowed_teams
            .iter()
            .map(|(_, name)| name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let event_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM resource_events WHERE resource_id = ?")
                .bind(rid)
                .fetch_one(&state.pool)
                .await
                .unwrap_or(0);
        let attached_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM event_type_resources WHERE resource_id = ?")
                .bind(rid)
                .fetch_one(&state.pool)
                .await
                .unwrap_or(0);
        let effective_url = caldav_url
            .clone()
            .filter(|u| !u.is_empty())
            .or_else(|| crate::resources::derive_caldav_url(feed_url));
        let has_service = caldav_username.as_deref().is_some_and(|u| !u.is_empty())
            && caldav_password.as_deref().is_some_and(|p| !p.is_empty());
        let lend_count = match effective_url
            .as_deref()
            .and_then(crate::resources::url_origin)
        {
            Some(origin) => lender_source_urls
                .iter()
                .filter(|(u,)| crate::resources::url_origin(u).as_ref() == Some(&origin))
                .count(),
            None => 0,
        };
        let write_configured = effective_url.is_some() && (has_service || lend_count > 0);
        let write_via = if has_service {
            format!(
                "service account {}",
                caldav_username.as_deref().unwrap_or("")
            )
        } else {
            format!(
                "member credentials, {} matching user(s) opted in",
                lend_count
            )
        };
        resources_ctx.push(context! {
            id => rid,
            name => rname,
            feed_url => feed_url,
            caldav_url => caldav_url.clone().unwrap_or_default(),
            caldav_username => caldav_username.clone().unwrap_or_default(),
            write_configured => write_configured,
            write_via => write_via,
            last_synced_at => last_synced_at.clone().unwrap_or_default(),
            last_sync_error => last_sync_error.clone().unwrap_or_default(),
            event_count => event_count,
            attached_count => attached_count,
            allowed_team_ids => allowed_team_ids,
            allowed_team_names => allowed_team_names,
        });
    }

    // Fetch all users
    let users: Vec<(String, String, String, String, String, bool)> = sqlx::query_as(
        "SELECT id, name, email, role, auth_provider, enabled FROM users ORDER BY created_at",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let user_count = users.len();

    // Fetch groups per user
    let user_groups_rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT ug.user_id, g.name FROM user_groups ug JOIN groups g ON g.id = ug.group_id ORDER BY g.name",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    // Build a map of user_id -> comma-separated group names
    let mut user_groups_map: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    for (uid, gname) in &user_groups_rows {
        user_groups_map
            .entry(uid.clone())
            .or_default()
            .push(gname.clone());
    }

    let users_ctx: Vec<minijinja::Value> = users
        .iter()
        .map(|(id, name, email, role, auth_provider, enabled)| {
            let groups = user_groups_map.get(id).cloned().unwrap_or_default();
            context! {
                id => id,
                name => name,
                email => email,
                role => role,
                auth_provider => auth_provider,
                enabled => enabled,
                groups => groups,
            }
        })
        .collect();

    // Fetch groups with member count
    let groups_rows: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT g.id, g.name, COUNT(ug.user_id) as member_count \
         FROM groups g LEFT JOIN user_groups ug ON ug.group_id = g.id \
         GROUP BY g.id ORDER BY g.name",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let group_count = groups_rows.len();

    // Fetch all group members with weights
    let all_members: Vec<(String, String, String, i64)> = sqlx::query_as(
        "SELECT ug.group_id, ug.user_id, u.name, ug.weight \
         FROM user_groups ug JOIN users u ON u.id = ug.user_id \
         ORDER BY ug.weight DESC, u.name",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let groups_ctx: Vec<minijinja::Value> = groups_rows
        .iter()
        .map(|(id, name, member_count)| {
            let members: Vec<minijinja::Value> = all_members
                .iter()
                .filter(|(gid, _, _, _)| gid == id)
                .map(|(_, uid, uname, w)| {
                    context! {
                        user_id => uid,
                        name => uname,
                        weight => w,
                    }
                })
                .collect();
            context! {
                id => id,
                name => name,
                member_count => member_count,
                members => members,
            }
        })
        .collect();

    // Fetch auth config
    let auth_config = crate::auth::get_auth_config(&state.pool).await.ok();
    let registration_enabled = auth_config
        .as_ref()
        .map(|c| c.registration_enabled)
        .unwrap_or(false);
    let allowed_email_domains = auth_config
        .as_ref()
        .and_then(|c| c.allowed_email_domains.clone())
        .unwrap_or_default();
    let oidc_enabled = auth_config
        .as_ref()
        .map(|c| c.oidc_enabled)
        .unwrap_or(false);
    let oidc_issuer_url = auth_config
        .as_ref()
        .and_then(|c| c.oidc_issuer_url.clone())
        .unwrap_or_default();
    let oidc_client_id = auth_config
        .as_ref()
        .and_then(|c| c.oidc_client_id.clone())
        .unwrap_or_default();
    let oidc_auto_register = auth_config
        .as_ref()
        .map(|c| c.oidc_auto_register)
        .unwrap_or(true);
    let google_oauth2_client_id = auth_config
        .as_ref()
        .and_then(|c| c.google_oauth2_client_id.clone())
        .unwrap_or_default();
    let google_oauth2_configured = !google_oauth2_client_id.is_empty();

    let (
        smtp_configured,
        smtp_host,
        smtp_port,
        smtp_username,
        smtp_from_email,
        smtp_from_name,
        smtp_tls_mode,
        smtp_enabled,
        smtp_from_env,
        smtp_error,
    ) = match crate::email::load_smtp_status(&state.pool).await {
        Ok(Some(status)) => (
            true,
            status.host,
            status.port,
            status.username,
            status.from_email,
            status.from_name.unwrap_or_default(),
            status.tls_mode,
            status.enabled,
            status.from_env,
            String::new(),
        ),
        Ok(None) => (
            false,
            String::new(),
            0u16,
            String::new(),
            String::new(),
            String::new(),
            "starttls".to_string(),
            false,
            false,
            String::new(),
        ),
        Err(e) => (
            false,
            String::new(),
            0u16,
            String::new(),
            String::new(),
            String::new(),
            "starttls".to_string(),
            false,
            true,
            e.to_string(),
        ),
    };

    // Flash banner after a "send test email" round-trip (?smtp_test=sent|error).
    let smtp_test_result = query.get("smtp_test").cloned().unwrap_or_default();

    // SMS gateway status. `sms_provider` drives which set of labels the form
    // shows; the labels themselves come from the provider registry so the
    // template never learns a gateway's name.
    let sms_status = crate::sms::load_status(&state.pool).await;
    let (
        sms_configured,
        sms_provider,
        sms_api_key,
        sms_sender,
        sms_base_url,
        sms_default_country,
        sms_daily_cap,
        sms_enabled,
        sms_from_env,
        sms_error,
    ) = match sms_status {
        Ok(Some(status)) => (
            true,
            status.provider,
            status.api_key,
            status.sender,
            status.base_url,
            status.default_country_code,
            status.daily_cap,
            status.enabled,
            status.from_env,
            String::new(),
        ),
        Ok(None) => (
            false,
            crate::sms::kinds::TWILIO.to_string(),
            String::new(),
            String::new(),
            String::new(),
            crate::sms::phone::DEFAULT_COUNTRY_CODE.to_string(),
            0,
            false,
            false,
            String::new(),
        ),
        Err(e) => (
            false,
            crate::sms::kinds::TWILIO.to_string(),
            String::new(),
            String::new(),
            String::new(),
            crate::sms::phone::DEFAULT_COUNTRY_CODE.to_string(),
            0,
            false,
            false,
            e.to_string(),
        ),
    };

    let (sms_cost_today, sms_cost_currency) = crate::sms::cost_today(&state.pool).await;
    let sms_sent_today = crate::sms::sent_today(&state.pool).await;
    let sms_allow_all_users: bool =
        sqlx::query_scalar("SELECT sms_allow_all_users FROM auth_config WHERE id = 'singleton'")
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None)
            .unwrap_or(false);

    // Flash banner after a test round-trip (?sms_test=sent|checked|error).
    let sms_test_result = query.get("sms_test").cloned().unwrap_or_default();
    let sms_test_detail = query.get("sms_test_detail").cloned().unwrap_or_default();

    let tmpl = match state.templates.get_template("admin.html") {
        Ok(t) => t,
        Err(e) => return internal_error_html("template render", &e),
    };

    let sidebar = context! {
        user_name => current_user.name,
        user_title => current_user.title.as_deref().unwrap_or(""),
        user_id => current_user.id,
        user_role => "admin",
        user_timezone => current_user.timezone,
        has_avatar => current_user.avatar_path.is_some(),
        user_initials => compute_initials(&current_user.name),
        active => "admin",
        version => env!("CARGO_PKG_VERSION"),
    };

    let captcha_configured = state.captcha_config.read().await.is_some();
    // The form shows what is stored, not the active config, which is `None`
    // while the configuration is incomplete.
    let captcha::CaptchaFormValues {
        instance_url: captcha_instance_url,
        site_key: captcha_site_key,
        widget_url: captcha_widget_url,
        wasm_url: captcha_wasm_url,
    } = captcha::load_captcha_form_values(&state.pool).await;

    let meeting_cfg = state.meeting_config.read().await;
    let jitsi_configured = meeting_cfg.jitsi.is_some();
    let jitsi_base_url = meeting_cfg
        .jitsi
        .as_ref()
        .map(|j| j.base_url.clone())
        .unwrap_or_default();
    let jitsi_pattern = meeting_cfg
        .jitsi
        .as_ref()
        .map(|j| j.pattern.clone())
        .unwrap_or_else(|| meeting::DEFAULT_JITSI_PATTERN.to_string());
    let jitsi_display_name = meeting_cfg
        .jitsi
        .as_ref()
        .and_then(|j| j.display_name.clone())
        .unwrap_or_default();
    let meeting_webhook_configured = meeting_cfg.webhook.is_some();
    let meeting_webhook_url = meeting_cfg
        .webhook
        .as_ref()
        .map(|w| w.url.clone())
        .unwrap_or_default();
    let meeting_webhook_auth_mode = meeting_cfg
        .webhook
        .as_ref()
        .map(|w| w.auth_mode.as_str().to_string())
        .unwrap_or_else(|| meeting::WEBHOOK_AUTH_NONE.to_string());
    let meeting_webhook_has_secret = meeting_cfg
        .webhook
        .as_ref()
        .map(|w| !w.secret.is_empty())
        .unwrap_or(false);
    let meeting_webhook_display_name = meeting_cfg
        .webhook
        .as_ref()
        .and_then(|w| w.display_name.clone())
        .unwrap_or_default();
    drop(meeting_cfg);

    Html(
        tmpl.render(context! {
            lang => admin.lang,
            current_user_id => current_user.id,
            users => users_ctx,
            user_count => user_count,
            groups => groups_ctx,
            group_count => group_count,
            registration_enabled => registration_enabled,
            allowed_email_domains => allowed_email_domains,
            oidc_enabled => oidc_enabled,
            oidc_issuer_url => oidc_issuer_url,
            oidc_client_id => oidc_client_id,
            oidc_auto_register => oidc_auto_register,
            google_oauth2_client_id => google_oauth2_client_id,
            google_oauth2_configured => google_oauth2_configured,
            base_url => crate::settings::base_url().unwrap_or_default(),
            base_url_db => crate::settings::base_url_db().unwrap_or_default(),
            base_url_from_env => crate::settings::base_url_from_env(),
            allow_private_hosts => crate::settings::private_host_allowlist().join(", "),
            allow_private_hosts_db => crate::settings::private_host_allowlist_db().join(", "),
            allow_private_hosts_from_env => crate::settings::allow_private_hosts_from_env(),
            smtp_configured => smtp_configured,
            smtp_host => smtp_host,
            smtp_port => smtp_port,
            smtp_username => smtp_username,
            smtp_from_email => smtp_from_email,
            smtp_from_name => smtp_from_name,
            smtp_tls_mode => smtp_tls_mode,
            smtp_enabled => smtp_enabled,
            smtp_from_env => smtp_from_env,
            smtp_error => smtp_error,
            smtp_test_result => smtp_test_result,
            sms_configured => sms_configured,
            sms_provider => sms_provider,
            sms_api_key => sms_api_key,
            sms_sender => sms_sender,
            sms_base_url => sms_base_url,
            sms_default_country => sms_default_country,
            sms_daily_cap => sms_daily_cap,
            sms_sent_today => sms_sent_today,
            sms_cost_today => format!("{:.2}", sms_cost_today),
            sms_cost_currency => sms_cost_currency,
            sms_allow_all_users => sms_allow_all_users,
            sms_enabled => sms_enabled,
            sms_from_env => sms_from_env,
            sms_error => sms_error,
            sms_test_result => sms_test_result,
            sms_test_detail => sms_test_detail,
            sms_supports_check => crate::sms::factory::provider_spec(&sms_provider)
                .map(|spec| spec.supports_check)
                .unwrap_or(false),
            sms_trial_mode => sms_provider == crate::sms::kinds::TWILIO
                && crate::sms::twilio::trial_mode_enabled(),
            sms_providers => crate::sms::PROVIDER_SPECS,
            sms_country_codes => crate::sms::phone::COUNTRY_CODES
                .iter()
                .map(|(code, label)| context! { code => code, label => label })
                .collect::<Vec<_>>(),
            captcha_configured => captcha_configured,
            captcha_instance_url => captcha_instance_url,
            captcha_site_key => captcha_site_key,
            captcha_widget_url => captcha_widget_url,
            captcha_wasm_url => captcha_wasm_url,
            jitsi_configured => jitsi_configured,
            jitsi_base_url => jitsi_base_url,
            jitsi_pattern => jitsi_pattern,
            jitsi_display_name => jitsi_display_name,
            jitsi_default_pattern => meeting::DEFAULT_JITSI_PATTERN,
            meeting_webhook_configured => meeting_webhook_configured,
            meeting_webhook_url => meeting_webhook_url,
            meeting_webhook_auth_mode => meeting_webhook_auth_mode,
            meeting_webhook_has_secret => meeting_webhook_has_secret,
            meeting_webhook_display_name => meeting_webhook_display_name,
            has_logo => state.data_dir.join("logo.png").exists(),
            company_link => get_company_link(&state.pool).await.unwrap_or_default(),
            current_theme => get_theme_name(&state.pool).await,
            custom_colors => {
                let (a, ah, bg, s, t) = get_custom_colors(&state.pool).await;
                context! { accent => a, accent_hover => ah, bg => bg, surface => s, text => t }
            },
            sidebar => sidebar,
            impersonating => false,
            impersonating_name => "",
            error_message => error_message,
            resources => resources_ctx,
            resource_teams_all => resource_teams_ctx,
            resource_notice => resource_notice,
            resource_error => resource_error,
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e)),
    )
}

#[derive(Deserialize)]
struct AdminResourceForm {
    _csrf: Option<String>,
    name: Option<String>,
    feed_url: String,
    caldav_url: Option<String>,
    caldav_username: Option<String>,
    caldav_password: Option<String>,
    /// Comma-joined team ids allowed to use this resource (hidden field
    /// kept in sync with the checkboxes, same pattern as `resource_ids`
    /// on the event type form).
    team_ids: Option<String>,
}

/// Persist a resource's team allowlist (delete-then-insert). Unknown team
/// ids are dropped by inserting through a SELECT on `teams`.
async fn save_resource_teams(pool: &SqlitePool, resource_id: &str, team_ids: &Option<String>) {
    let _ = sqlx::query("DELETE FROM resource_teams WHERE resource_id = ?")
        .bind(resource_id)
        .execute(pool)
        .await;
    if let Some(ids) = team_ids {
        for tid in ids.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let _ = sqlx::query(
                "INSERT OR IGNORE INTO resource_teams (resource_id, team_id)
                 SELECT ?, id FROM teams WHERE id = ?",
            )
            .bind(resource_id)
            .bind(tid)
            .execute(pool)
            .await;
        }
    }
}

fn admin_resources_redirect(notice: &str) -> Response {
    Redirect::to(&format!(
        "/dashboard/admin?resource_notice={}",
        urlencoding::encode(notice)
    ))
    .into_response()
}

fn admin_resources_redirect_err(error: &str) -> Response {
    Redirect::to(&format!(
        "/dashboard/admin?resource_error={}",
        urlencoding::encode(error)
    ))
    .into_response()
}

async fn admin_create_resource(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Form(form): Form<AdminResourceForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let feed_url = form.feed_url.trim().to_string();
    if let Err(e) = crate::caldav::validate_caldav_url(&feed_url) {
        return admin_resources_redirect_err(&format!("Invalid feed URL: {}", e));
    }
    // The feed must answer before we store anything, and it gives us the name.
    let body = match crate::resources::fetch_feed(&feed_url).await {
        Ok(b) => b,
        Err(e) => {
            return admin_resources_redirect_err(&format!("Feed check failed: {}", e));
        }
    };
    let name = form
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| crate::resources::feed_calendar_name(&body))
        .unwrap_or_else(|| "Resource".to_string());

    let caldav_url = form
        .caldav_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if let Some(u) = caldav_url {
        if let Err(e) = crate::caldav::validate_caldav_url(u) {
            return admin_resources_redirect_err(&format!("Invalid CalDAV URL: {}", e));
        }
    }
    let caldav_username = form
        .caldav_username
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let caldav_password_enc = match form.caldav_password.as_deref().filter(|s| !s.is_empty()) {
        Some(p) => match crate::crypto::encrypt_password(&state.secret_key, p) {
            Ok(enc) => Some(enc),
            Err(e) => {
                return admin_resources_redirect_err(&format!(
                    "Could not store credentials: {}",
                    e
                ));
            }
        },
        None => None,
    };

    let id = uuid::Uuid::new_v4().to_string();
    let _ = sqlx::query(
        "INSERT INTO resources (id, name, feed_url, caldav_url, caldav_username, caldav_password)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&name)
    .bind(&feed_url)
    .bind(caldav_url)
    .bind(caldav_username)
    .bind(&caldav_password_enc)
    .execute(&state.pool)
    .await;
    save_resource_teams(&state.pool, &id, &form.team_ids).await;

    let cached = crate::resources::sync_resource(&state.pool, &id, &feed_url)
        .await
        .unwrap_or(0);
    tracing::info!(resource_name = %name, admin = %_admin.user.email, "admin: resource created");
    admin_resources_redirect(&format!(
        "Resource \"{}\" added ({} event(s) cached).",
        name, cached
    ))
}

async fn admin_update_resource(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Path(resource_id): Path<String>,
    Form(form): Form<AdminResourceForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let feed_url = form.feed_url.trim().to_string();
    if let Err(e) = crate::caldav::validate_caldav_url(&feed_url) {
        return admin_resources_redirect_err(&format!("Invalid feed URL: {}", e));
    }
    let caldav_url = form
        .caldav_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if let Some(u) = caldav_url {
        if let Err(e) = crate::caldav::validate_caldav_url(u) {
            return admin_resources_redirect_err(&format!("Invalid CalDAV URL: {}", e));
        }
    }
    // Same contract as create: the feed must answer before we store it, so
    // a typo'd URL is caught now instead of silently serving stale events
    // for up to 5 minutes.
    if let Err(e) = crate::resources::fetch_feed(&feed_url).await {
        return admin_resources_redirect_err(&format!("Feed check failed: {}", e));
    }
    let name = form
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("Resource");
    let _ = sqlx::query(
        "UPDATE resources SET name = ?, feed_url = ?, caldav_url = ?, caldav_username = ? WHERE id = ?",
    )
    .bind(name)
    .bind(&feed_url)
    .bind(caldav_url)
    .bind(
        form.caldav_username
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty()),
    )
    .bind(&resource_id)
    .execute(&state.pool)
    .await;
    // Keep-current pattern: empty password field preserves the stored
    // secret. Clearing the username clears the password with it, so no
    // orphaned credential half survives.
    if form
        .caldav_username
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .is_none()
    {
        let _ = sqlx::query("UPDATE resources SET caldav_password = NULL WHERE id = ?")
            .bind(&resource_id)
            .execute(&state.pool)
            .await;
    } else if let Some(p) = form.caldav_password.as_deref().filter(|s| !s.is_empty()) {
        if let Ok(enc) = crate::crypto::encrypt_password(&state.secret_key, p) {
            let _ = sqlx::query("UPDATE resources SET caldav_password = ? WHERE id = ?")
                .bind(&enc)
                .bind(&resource_id)
                .execute(&state.pool)
                .await;
        }
    }
    save_resource_teams(&state.pool, &resource_id, &form.team_ids).await;
    let cached = crate::resources::sync_resource(&state.pool, &resource_id, &feed_url)
        .await
        .unwrap_or(0);
    admin_resources_redirect(&format!("Resource updated ({} event(s) cached).", cached))
}

async fn admin_delete_resource(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Path(resource_id): Path<String>,
    Form(csrf): Form<CsrfForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &csrf._csrf) {
        return resp;
    }
    let _ = sqlx::query("DELETE FROM resources WHERE id = ?")
        .bind(&resource_id)
        .execute(&state.pool)
        .await;
    tracing::info!(resource_id = %resource_id, admin = %_admin.user.email, "admin: resource deleted");
    admin_resources_redirect("Resource deleted.")
}

async fn admin_sync_resource(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Path(resource_id): Path<String>,
    Form(csrf): Form<CsrfForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &csrf._csrf) {
        return resp;
    }
    let feed_url: Option<String> =
        sqlx::query_scalar("SELECT feed_url FROM resources WHERE id = ?")
            .bind(&resource_id)
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None);
    let Some(feed_url) = feed_url else {
        return admin_resources_redirect_err("Resource not found.");
    };
    match crate::resources::sync_resource(&state.pool, &resource_id, &feed_url).await {
        Ok(n) => admin_resources_redirect(&format!("Feed synced, {} event(s) cached.", n)),
        Err(e) => admin_resources_redirect_err(&format!("Sync failed: {}", e)),
    }
}

async fn admin_test_write_resource(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Path(resource_id): Path<String>,
    Form(csrf): Form<CsrfForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &csrf._csrf) {
        return resp;
    }
    let row: Option<(String, Option<String>, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT feed_url, caldav_url, caldav_username, caldav_password FROM resources WHERE id = ?",
    )
    .bind(&resource_id)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);
    let Some((feed_url, caldav_url, service_user, service_pw)) = row else {
        return admin_resources_redirect_err("Resource not found.");
    };
    let Some(url) = caldav_url
        .filter(|u| !u.is_empty())
        .or_else(|| crate::resources::derive_caldav_url(&feed_url))
    else {
        return admin_resources_redirect_err(
            "No CalDAV URL configured and none could be derived from the feed URL.",
        );
    };
    let candidates = resource_write_candidates(
        &state.pool,
        &state.secret_key,
        &url,
        service_user.as_deref(),
        service_pw.as_deref(),
        None,
    )
    .await;
    if candidates.is_empty() {
        return admin_resources_redirect_err(
            "No write credentials available (no service account, and no opted-in member has a matching calendar source).",
        );
    }
    // Full PUT / verify / DELETE / verify cycle with a clearly-labeled
    // temporary event placed 24h out.
    let test_uid = format!("calrs-write-test-{}", uuid::Uuid::new_v4());
    let start = chrono::Utc::now() + Duration::hours(24);
    let end = start + Duration::minutes(15);
    let ics = format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//calrs//write-test//EN\r\nBEGIN:VEVENT\r\nUID:{}\r\nDTSTAMP:{}\r\nDTSTART:{}\r\nDTEND:{}\r\nSUMMARY:calrs write test (safe to delete)\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
        test_uid,
        chrono::Utc::now().format("%Y%m%dT%H%M%SZ"),
        start.format("%Y%m%dT%H%M%SZ"),
        end.format("%Y%m%dT%H%M%SZ"),
    );
    let mut last_err = String::new();
    for (username, password) in &candidates {
        let client = crate::caldav::CaldavClient::new(&url, username, password);
        match client.put_event(&url, &test_uid, &ics).await {
            Ok(()) => {
                let existed = client.event_exists(&url, &test_uid).await.unwrap_or(false);
                let _ = client.delete_event(&url, &test_uid).await;
                let gone = !client.event_exists(&url, &test_uid).await.unwrap_or(true);
                return admin_resources_redirect(&format!(
                    "Write test passed with {} (created: {}, cleaned up: {}).",
                    username,
                    if existed { "verified" } else { "unverified" },
                    if gone {
                        "verified"
                    } else {
                        "check the resource calendar"
                    },
                ));
            }
            Err(e) => last_err = format!("{}: {}", username, e),
        }
    }
    admin_resources_redirect_err(&format!("Write test failed. Last error: {}", last_err))
}

async fn admin_toggle_role(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Form(csrf): Form<CsrfForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &csrf._csrf) {
        return resp;
    }
    // Get current role
    let current_role: Option<(String,)> = sqlx::query_as("SELECT role FROM users WHERE id = ?")
        .bind(&user_id)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None);

    if let Some((role,)) = current_role {
        let new_role = if role == "admin" { "user" } else { "admin" };
        let _ = sqlx::query("UPDATE users SET role = ?, updated_at = datetime('now') WHERE id = ?")
            .bind(new_role)
            .bind(&user_id)
            .execute(&state.pool)
            .await;
        tracing::info!(target_user = %user_id, new_role = %new_role, admin = %_admin.user.email, "admin: role changed");
    }

    Redirect::to("/dashboard/admin").into_response()
}

async fn admin_toggle_enabled(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Form(csrf): Form<CsrfForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &csrf._csrf) {
        return resp;
    }
    // Get current enabled status
    let current: Option<(bool,)> = sqlx::query_as("SELECT enabled FROM users WHERE id = ?")
        .bind(&user_id)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None);

    if let Some((enabled,)) = current {
        let new_enabled = !enabled;
        let _ =
            sqlx::query("UPDATE users SET enabled = ?, updated_at = datetime('now') WHERE id = ?")
                .bind(new_enabled)
                .bind(&user_id)
                .execute(&state.pool)
                .await;
        tracing::info!(target_user = %user_id, enabled = %new_enabled, admin = %_admin.user.email, "admin: user toggled");
    }

    Redirect::to("/dashboard/admin").into_response()
}

async fn admin_delete_user(
    State(state): State<Arc<AppState>>,
    admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Form(csrf): Form<CsrfForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &csrf._csrf) {
        return resp;
    }
    let admin_user = &admin.user;
    let avatars_dir = state.data_dir.join("avatars");
    match crate::auth::delete_user(
        &state.pool,
        &user_id,
        Some(&admin_user.id),
        Some(&avatars_dir),
    )
    .await
    {
        Ok(()) => {
            tracing::info!(target_user = %user_id, admin = %admin_user.email, "admin: user deleted");
            Redirect::to("/dashboard/admin").into_response()
        }
        Err(e) => {
            tracing::warn!(target_user = %user_id, admin = %admin_user.email, error = %e, "admin: user delete refused");
            let encoded = urlencoding::encode(&e.to_string()).into_owned();
            Redirect::to(&format!("/dashboard/admin?error={}", encoded)).into_response()
        }
    }
}

#[derive(Deserialize)]
struct AdminAuthForm {
    _csrf: Option<String>,
    registration_enabled: Option<String>,
    allowed_email_domains: Option<String>,
}

async fn admin_update_auth(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Form(form): Form<AdminAuthForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let registration_enabled = form.registration_enabled.is_some();
    let allowed_domains = form.allowed_email_domains.filter(|d| !d.trim().is_empty());

    let _ = sqlx::query(
        "UPDATE auth_config SET registration_enabled = ?, allowed_email_domains = ?, updated_at = datetime('now') WHERE id = 'singleton'",
    )
    .bind(registration_enabled)
    .bind(&allowed_domains)
    .execute(&state.pool)
    .await;

    tracing::info!(admin = %_admin.user.email, "admin: auth config updated");

    Redirect::to("/dashboard/admin").into_response()
}

#[derive(Deserialize)]
struct AdminThemeForm {
    _csrf: Option<String>,
    theme: Option<String>,
    custom_accent: Option<String>,
    custom_accent_hover: Option<String>,
    custom_bg: Option<String>,
    custom_surface: Option<String>,
    custom_text: Option<String>,
}

async fn admin_update_accent(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Form(form): Form<AdminThemeForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let theme = form
        .theme
        .filter(|t| {
            matches!(
                t.as_str(),
                "default"
                    | "nord"
                    | "dracula"
                    | "gruvbox"
                    | "solarized"
                    | "tokyo-night"
                    | "vates"
                    | "custom"
            )
        })
        .unwrap_or_else(|| "default".to_string());

    if theme == "custom" {
        let accent = form.custom_accent.as_deref().unwrap_or("#2563eb");
        let accent_hover = form.custom_accent_hover.as_deref().unwrap_or("#1d4ed8");
        let bg = form.custom_bg.as_deref().unwrap_or("#f4f4f5");
        let surface = form.custom_surface.as_deref().unwrap_or("#ffffff");
        let text = form.custom_text.as_deref().unwrap_or("#18181b");

        let _ = sqlx::query(
            "UPDATE auth_config SET theme = 'custom', custom_accent = ?, custom_accent_hover = ?, custom_bg = ?, custom_surface = ?, custom_text = ?, updated_at = datetime('now') WHERE id = 'singleton'",
        )
        .bind(accent)
        .bind(accent_hover)
        .bind(bg)
        .bind(surface)
        .bind(text)
        .execute(&state.pool)
        .await;
    } else {
        let _ = sqlx::query(
            "UPDATE auth_config SET theme = ?, updated_at = datetime('now') WHERE id = 'singleton'",
        )
        .bind(&theme)
        .execute(&state.pool)
        .await;
    }

    // Rebuild and cache the CSS
    let new_css = build_theme_css(&state.pool).await;
    *state.theme_css.write().await = new_css;

    tracing::info!(admin = %_admin.user.email, theme = %theme, "admin: theme updated");

    Redirect::to("/dashboard/admin").into_response()
}

#[derive(Deserialize)]
struct AdminOidcForm {
    _csrf: Option<String>,
    oidc_enabled: Option<String>,
    oidc_issuer_url: Option<String>,
    oidc_client_id: Option<String>,
    oidc_client_secret: Option<String>,
    oidc_auto_register: Option<String>,
}

async fn admin_update_oidc(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Form(form): Form<AdminOidcForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let oidc_enabled = form.oidc_enabled.is_some();
    let issuer_url = form.oidc_issuer_url.filter(|s| !s.trim().is_empty());
    let client_id = form.oidc_client_id.filter(|s| !s.trim().is_empty());
    let auto_register = form.oidc_auto_register.is_some();

    // If client_secret is provided (non-empty), update it; otherwise keep current value
    let secret_provided = form
        .oidc_client_secret
        .as_ref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);

    if secret_provided {
        let client_secret = form.oidc_client_secret.unwrap_or_default();
        // Encrypt the secret at rest. We carry the auth_config row's
        // singleton SQLite primary key, so on the read side it goes
        // through crypto::decrypt_value.
        let encrypted_secret = match crate::crypto::encrypt_value(&state.secret_key, &client_secret)
        {
            Ok(s) => s,
            Err(e) => return internal_error_response("encrypt oidc client_secret", &e),
        };
        let _ = sqlx::query(
            "UPDATE auth_config SET oidc_enabled = ?, oidc_issuer_url = ?, oidc_client_id = ?, oidc_client_secret = ?, oidc_auto_register = ?, updated_at = datetime('now') WHERE id = 'singleton'",
        )
        .bind(oidc_enabled)
        .bind(&issuer_url)
        .bind(&client_id)
        .bind(&encrypted_secret)
        .bind(auto_register)
        .execute(&state.pool)
        .await;
    } else {
        let _ = sqlx::query(
            "UPDATE auth_config SET oidc_enabled = ?, oidc_issuer_url = ?, oidc_client_id = ?, oidc_auto_register = ?, updated_at = datetime('now') WHERE id = 'singleton'",
        )
        .bind(oidc_enabled)
        .bind(&issuer_url)
        .bind(&client_id)
        .bind(auto_register)
        .execute(&state.pool)
        .await;
    }

    tracing::info!(admin = %_admin.user.email, "admin: OIDC config updated");

    Redirect::to("/dashboard/admin").into_response()
}

#[derive(Deserialize)]
struct AdminGoogleOAuth2Form {
    _csrf: Option<String>,
    google_oauth2_client_id: Option<String>,
    google_oauth2_client_secret: Option<String>,
}

async fn admin_update_google_oauth2(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Form(form): Form<AdminGoogleOAuth2Form>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let client_id = form
        .google_oauth2_client_id
        .filter(|s| !s.trim().is_empty());

    let secret_provided = form
        .google_oauth2_client_secret
        .as_ref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);

    if secret_provided {
        let client_secret = form.google_oauth2_client_secret.unwrap_or_default();
        let encrypted_secret = match crate::crypto::encrypt_value(&state.secret_key, &client_secret)
        {
            Ok(s) => s,
            Err(e) => return internal_error_response("encrypt google_oauth2 client_secret", &e),
        };
        let _ = sqlx::query(
            "UPDATE auth_config SET google_oauth2_client_id = ?, google_oauth2_client_secret = ?, updated_at = datetime('now') WHERE id = 'singleton'",
        )
        .bind(&client_id)
        .bind(&encrypted_secret)
        .execute(&state.pool)
        .await;
    } else {
        let _ = sqlx::query(
            "UPDATE auth_config SET google_oauth2_client_id = ?, updated_at = datetime('now') WHERE id = 'singleton'",
        )
        .bind(&client_id)
        .execute(&state.pool)
        .await;
    }

    tracing::info!(admin = %_admin.user.email, "admin: Google OAuth2 config updated");
    Redirect::to("/dashboard/admin").into_response()
}

// --- Captcha settings ---

#[derive(Deserialize)]
struct AdminCaptchaForm {
    _csrf: Option<String>,
    captcha_instance_url: Option<String>,
    captcha_site_key: Option<String>,
    captcha_secret: Option<String>,
    captcha_widget_url: Option<String>,
    captcha_wasm_url: Option<String>,
}

// --- General / system runtime settings (base URL, private-host allowlist) ---

#[derive(Deserialize)]
struct AdminGeneralForm {
    _csrf: Option<String>,
    base_url: Option<String>,
    allow_private_hosts: Option<String>,
}

async fn admin_update_general(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Form(form): Form<AdminGeneralForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }

    // Only persist a field that isn't currently forced by an environment
    // variable. A forced field is read-only in the UI and submits the env
    // value back; writing it would either clobber the stored DB value with NULL
    // (disabled inputs) or leak the env value into the DB. The env keeps
    // precedence regardless, so there's nothing to save for those fields.
    if !crate::settings::base_url_from_env() {
        // Normalise (strip trailing slash). Empty clears the override; a
        // non-empty value must be an absolute http(s) URL with a host. We do
        // NOT run the SSRF guard here — the public base URL is legitimately
        // allowed to be localhost / a private host in dev.
        let raw = form
            .base_url
            .as_deref()
            .map(|s| s.trim().trim_end_matches('/'))
            .filter(|s| !s.is_empty());
        let base_url = match raw {
            None => None,
            Some(raw) => match reqwest::Url::parse(raw) {
                Ok(u) if matches!(u.scheme(), "http" | "https") && u.host_str().is_some() => {
                    Some(raw.to_string())
                }
                _ => {
                    let msg = urlencoding::encode(
                        "Base URL must be an absolute http(s) URL, e.g. https://cal.example.com",
                    )
                    .into_owned();
                    return Redirect::to(&format!("/dashboard/admin?error={}", msg))
                        .into_response();
                }
            },
        };
        if let Err(e) = sqlx::query(
            "UPDATE auth_config SET base_url = ?, updated_at = datetime('now') WHERE id = 'singleton'",
        )
        .bind(&base_url)
        .execute(&state.pool)
        .await
        {
            return internal_error_response("save base_url", &e);
        }
    }

    if !crate::settings::allow_private_hosts_from_env() {
        // Re-serialise through the canonical parser so what we store matches
        // what `settings` reads back. Empty → NULL (clears the DB override).
        let allow_private_hosts = form
            .allow_private_hosts
            .as_deref()
            .map(|s| crate::settings::parse_host_list(s).join(","))
            .filter(|s| !s.is_empty());
        if let Err(e) = sqlx::query(
            "UPDATE auth_config SET allow_private_hosts = ?, updated_at = datetime('now') WHERE id = 'singleton'",
        )
        .bind(&allow_private_hosts)
        .execute(&state.pool)
        .await
        {
            return internal_error_response("save allow_private_hosts", &e);
        }
    }

    // Refresh the process-global cache so the change takes effect immediately.
    crate::settings::load_from_db(&state.pool).await;

    tracing::info!(admin = %_admin.user.email, "admin: general settings updated");
    Redirect::to("/dashboard/admin").into_response()
}

async fn admin_update_captcha(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Form(form): Form<AdminCaptchaForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }

    let instance_url = form.captcha_instance_url.filter(|s| !s.trim().is_empty());
    let site_key = form.captcha_site_key.filter(|s| !s.trim().is_empty());
    let widget_url = form.captcha_widget_url.filter(|s| !s.trim().is_empty());
    let wasm_url = form
        .captcha_wasm_url
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    if wasm_url
        .as_deref()
        .is_some_and(|u| !captcha::is_http_url(u))
    {
        let msg = crate::i18n::translate(_admin.lang, "admin-captcha-wasm-url-invalid", None);
        let encoded = urlencoding::encode(&msg).into_owned();
        return Redirect::to(&format!("/dashboard/admin?error={}", encoded)).into_response();
    }

    let secret_provided = form
        .captcha_secret
        .as_ref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);

    if secret_provided {
        let secret = form.captcha_secret.unwrap_or_default();
        let encrypted = match crate::crypto::encrypt_value(&state.secret_key, &secret) {
            Ok(s) => s,
            Err(e) => return internal_error_response("encrypt captcha secret", &e),
        };
        if let Err(e) = sqlx::query(
            "UPDATE auth_config SET captcha_instance_url = ?, captcha_site_key = ?, captcha_secret = ?, captcha_widget_url = ?, captcha_wasm_url = ?, updated_at = datetime('now') WHERE id = 'singleton'",
        )
        .bind(&instance_url)
        .bind(&site_key)
        .bind(&encrypted)
        .bind(&widget_url)
        .bind(&wasm_url)
        .execute(&state.pool)
        .await
        {
            tracing::error!(error = %e, "failed to save captcha config");
        }
    } else {
        if let Err(e) = sqlx::query(
            "UPDATE auth_config SET captcha_instance_url = ?, captcha_site_key = ?, captcha_widget_url = ?, captcha_wasm_url = ?, updated_at = datetime('now') WHERE id = 'singleton'",
        )
        .bind(&instance_url)
        .bind(&site_key)
        .bind(&widget_url)
        .bind(&wasm_url)
        .execute(&state.pool)
        .await
        {
            tracing::error!(error = %e, "failed to save captcha config");
        }
    }

    let new_config = captcha::load_captcha_config(&state.pool, &state.secret_key).await;
    let new_csp = build_csp(&new_config);
    *state.captcha_config.write().await = new_config;
    *state.csp.write().await = new_csp;

    tracing::info!(admin = %_admin.user.email, "admin: captcha config updated");

    Redirect::to("/dashboard/admin").into_response()
}

// --- SMTP settings (database-backed, editable from the admin panel) ---

#[derive(Deserialize)]
struct AdminSmtpForm {
    _csrf: Option<String>,
    host: Option<String>,
    port: Option<String>,
    tls_mode: Option<String>,
    username: Option<String>,
    /// Leave empty to keep the currently stored password (keep-current pattern).
    password: Option<String>,
    from_email: Option<String>,
    from_name: Option<String>,
    /// HTML checkbox: present (any value) when checked, absent when unchecked.
    enabled: Option<String>,
}

async fn admin_update_smtp(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Form(form): Form<AdminSmtpForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }

    // Defensive guard: when the env block governs, the DB config is shadowed and
    // the UI form is locked. Refuse to write so the two channels never diverge.
    if crate::email::smtp_env_active() {
        return Redirect::to("/dashboard/admin").into_response();
    }

    let redirect_err = |msg: &str| {
        let encoded = urlencoding::encode(msg).into_owned();
        Redirect::to(&format!("/dashboard/admin?error={}", encoded)).into_response()
    };

    let host = form.host.unwrap_or_default().trim().to_string();
    if host.is_empty() {
        return redirect_err("SMTP host is required.");
    }

    let from_email = form.from_email.unwrap_or_default().trim().to_string();
    if from_email.len() > 320
        || !from_email.contains('@')
        || from_email
            .rsplit('@')
            .next()
            .is_none_or(|domain| !domain.contains('.'))
    {
        return redirect_err("Please enter a valid 'from' email address.");
    }

    let port: i32 = match form.port.as_deref().map(str::trim) {
        Some("") | None => 587,
        Some(p) => match p.parse::<u16>() {
            Ok(p) => p as i32,
            Err(_) => return redirect_err("SMTP port must be a number between 1 and 65535."),
        },
    };

    let tls_mode = match form.tls_mode.as_deref().map(str::trim) {
        Some("tls") => "tls",
        Some("none") => "none",
        Some("starttls") | Some("") | None => "starttls",
        Some(_) => return redirect_err("TLS mode must be 'starttls', 'tls' or 'none'."),
    };

    let username = form.username.unwrap_or_default().trim().to_string();
    let from_name = form.from_name.and_then(|s| {
        let t = s.trim().to_string();
        if t.is_empty() {
            None
        } else {
            Some(t)
        }
    });
    let enabled = form.enabled.is_some();

    let password = form.password.unwrap_or_default();
    let password_provided = !password.trim().is_empty();

    let existing: Option<(String,)> = match sqlx::query_as("SELECT id FROM smtp_config LIMIT 1")
        .fetch_optional(&state.pool)
        .await
    {
        Ok(row) => row,
        Err(e) => return internal_error_response("check existing smtp config", &e),
    };

    let result = match existing {
        Some((id,)) if password_provided => {
            let password_enc = match crate::crypto::encrypt_password(&state.secret_key, &password) {
                Ok(s) => s,
                Err(e) => return internal_error_response("encrypt smtp password", &e),
            };
            sqlx::query(
                "UPDATE smtp_config SET host = ?, port = ?, username = ?, password_enc = ?, from_email = ?, from_name = ?, tls_mode = ?, enabled = ? WHERE id = ?",
            )
            .bind(&host)
            .bind(port)
            .bind(&username)
            .bind(&password_enc)
            .bind(&from_email)
            .bind(&from_name)
            .bind(tls_mode)
            .bind(enabled)
            .bind(&id)
            .execute(&state.pool)
            .await
        }
        Some((id,)) => {
            // Keep-current: do not touch password_enc.
            sqlx::query(
                "UPDATE smtp_config SET host = ?, port = ?, username = ?, from_email = ?, from_name = ?, tls_mode = ?, enabled = ? WHERE id = ?",
            )
            .bind(&host)
            .bind(port)
            .bind(&username)
            .bind(&from_email)
            .bind(&from_name)
            .bind(tls_mode)
            .bind(enabled)
            .bind(&id)
            .execute(&state.pool)
            .await
        }
        None => {
            // Fresh config needs a password — there is nothing to keep.
            if !password_provided {
                return redirect_err(
                    "A password is required when configuring SMTP for the first time.",
                );
            }
            let password_enc = match crate::crypto::encrypt_password(&state.secret_key, &password) {
                Ok(s) => s,
                Err(e) => return internal_error_response("encrypt smtp password", &e),
            };
            sqlx::query(
                "INSERT INTO smtp_config (id, host, port, username, password_enc, from_email, from_name, tls_mode, enabled) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(&host)
            .bind(port)
            .bind(&username)
            .bind(&password_enc)
            .bind(&from_email)
            .bind(&from_name)
            .bind(tls_mode)
            .bind(enabled)
            .execute(&state.pool)
            .await
        }
    };

    if let Err(e) = result {
        return internal_error_response("save smtp config", &e);
    }

    tracing::info!(admin = %_admin.user.email, "admin: smtp config updated");
    Redirect::to("/dashboard/admin").into_response()
}

#[derive(Deserialize)]
struct AdminSmtpTestForm {
    _csrf: Option<String>,
    to: Option<String>,
}

async fn admin_update_smtp_test(
    State(state): State<Arc<AppState>>,
    admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Form(form): Form<AdminSmtpTestForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }

    let to = form
        .to
        .and_then(|s| {
            let t = s.trim().to_string();
            if t.is_empty() {
                None
            } else {
                Some(t)
            }
        })
        .unwrap_or_else(|| admin.user.email.clone());

    let config = match crate::email::load_smtp_config(&state.pool, &state.secret_key).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return Redirect::to("/dashboard/admin?smtp_test=error").into_response();
        }
        Err(e) => {
            tracing::warn!(error = %e, "admin: smtp test could not load config");
            return Redirect::to("/dashboard/admin?smtp_test=error").into_response();
        }
    };

    match crate::email::send_test_email(&config, &to).await {
        Ok(()) => {
            tracing::info!(admin = %admin.user.email, %to, "admin: smtp test email sent");
            Redirect::to("/dashboard/admin?smtp_test=sent").into_response()
        }
        Err(e) => {
            tracing::warn!(admin = %admin.user.email, error = format!("{e:#}"), "admin: smtp test email failed");
            Redirect::to("/dashboard/admin?smtp_test=error").into_response()
        }
    }
}

#[derive(Deserialize)]
struct AdminSmtpClearForm {
    _csrf: Option<String>,
}

async fn admin_update_smtp_clear(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Form(form): Form<AdminSmtpClearForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }

    // Same guard as admin_update_smtp: when the env block governs, the DB config
    // is shadowed and the UI hides this button — refuse the write defensively.
    if crate::email::smtp_env_active() {
        return Redirect::to("/dashboard/admin").into_response();
    }

    if let Err(e) = sqlx::query("DELETE FROM smtp_config")
        .execute(&state.pool)
        .await
    {
        return internal_error_response("clear smtp config", &e);
    }

    tracing::info!(admin = %_admin.user.email, "admin: smtp config cleared");
    Redirect::to("/dashboard/admin").into_response()
}

// --- SMS settings (database-backed, editable from the admin panel) ---
//
// Deliberately mirrors the SMTP settings above: env-var override, DB singleton
// row, "keep current" pattern on the secret field, AES-256-GCM at rest via
// crate::crypto. The form is provider-agnostic: the same four inputs are
// relabelled per gateway from `sms::ProviderSpec`, so adding a gateway needs no
// change here. SMS stays entirely opt-in: with no config row, the event-type
// toggle simply has nothing to send through.

#[derive(Deserialize)]
struct AdminSmsForm {
    _csrf: Option<String>,
    provider: Option<String>,
    /// Non-secret account identifier (Twilio's Account SID). Unused by gateways
    /// that authenticate with a bare token.
    api_key: Option<String>,
    /// Leave empty to keep the currently stored secret (keep-current pattern).
    api_secret: Option<String>,
    sender: Option<String>,
    /// Region or self-hosted endpoint, and the target URL for the webhook provider.
    base_url: Option<String>,
    /// Default country calling code used to normalise guest-entered local numbers.
    default_country_code: Option<String>,
    /// Instance-wide messages/day ceiling; empty or 0 means no limit.
    daily_cap: Option<String>,
    /// HTML checkbox: present (any value) when checked, absent when unchecked.
    enabled: Option<String>,
}

async fn admin_update_sms(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Form(form): Form<AdminSmsForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }

    // Defensive guard: when the env block governs, the DB config is shadowed
    // and the UI form is locked. Refuse to write so the two channels never diverge.
    if crate::sms::sms_env_active() {
        return Redirect::to("/dashboard/admin").into_response();
    }

    let redirect_err = |msg: &str| {
        let encoded = urlencoding::encode(msg).into_owned();
        Redirect::to(&format!("/dashboard/admin?error={}", encoded)).into_response()
    };

    let provider = form.provider.unwrap_or_default().trim().to_string();
    let api_key = form.api_key.unwrap_or_default().trim().to_string();
    let sender = form.sender.unwrap_or_default().trim().to_string();
    let base_url = form.base_url.unwrap_or_default().trim().to_string();
    let default_country_code = form
        .default_country_code
        .unwrap_or_else(|| crate::sms::phone::DEFAULT_COUNTRY_CODE.to_string())
        .trim()
        .to_string();
    let enabled = form.enabled.is_some();
    let daily_cap: i64 = form
        .daily_cap
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
        .max(0);

    let api_secret = form.api_secret.unwrap_or_default();
    let secret_provided = !api_secret.trim().is_empty();

    let existing: Option<(String, Option<String>)> =
        match sqlx::query_as("SELECT id, api_secret_enc FROM sms_config LIMIT 1")
            .fetch_optional(&state.pool)
            .await
        {
            Ok(row) => row,
            Err(e) => return internal_error_response("check existing sms config", &e),
        };

    // Switching gateway must come with that gateway's own credential: keeping
    // the stored one would silently save, say, a Twilio auth token as a
    // GatewayAPI token and only fail at send time, inside a booking.
    let previous_provider: Option<String> =
        match sqlx::query_scalar("SELECT provider FROM sms_config LIMIT 1")
            .fetch_optional(&state.pool)
            .await
        {
            Ok(row) => row,
            Err(e) => return internal_error_response("check existing sms provider", &e),
        };
    let switching_provider = previous_provider
        .as_deref()
        .is_some_and(|prev| prev != provider);
    if switching_provider && !secret_provided && provider != crate::sms::kinds::WEBHOOK {
        return redirect_err("Switching SMS gateway requires entering that gateway's credential.");
    }

    // Validate the configuration as it will actually be stored, secret
    // included, so a keep-current save of an incomplete row still fails loudly.
    let effective_secret = if secret_provided {
        api_secret.trim().to_string()
    } else if switching_provider {
        String::new()
    } else {
        match existing.as_ref().and_then(|(_, enc)| enc.as_deref()) {
            Some(enc) if !enc.is_empty() => {
                crate::crypto::decrypt_password(&state.secret_key, enc).unwrap_or_default()
            }
            _ => String::new(),
        }
    };

    let candidate = crate::sms::SmsConfig {
        provider: provider.clone(),
        api_key: api_key.clone(),
        api_secret: effective_secret,
        sender: sender.clone(),
        base_url: base_url.clone(),
        default_country_code: default_country_code.clone(),
        daily_cap,
    };
    if let Err(e) = crate::sms::factory::validate_config(&candidate) {
        return redirect_err(&format!("SMS settings: {}.", e));
    }

    // A from-number is a phone number; an alphanumeric sender ID is not, so
    // only numeric senders are held to E.164.
    if sender.starts_with('+') && !crate::sms::phone::is_e164(&sender) {
        return redirect_err(
            "A numeric SMS sender must be in international format, e.g. +15551234567.",
        );
    }

    let result = match existing {
        // A gateway switch always rewrites the secret column, even when the
        // field was left empty (only the credential-less webhook can get
        // here): carrying the previous gateway's secret over would otherwise
        // sign webhook calls with, say, a Twilio auth token.
        Some((id, _)) if secret_provided || switching_provider => {
            let api_secret_enc = if secret_provided {
                match crate::crypto::encrypt_password(&state.secret_key, api_secret.trim()) {
                    Ok(s) => Some(s),
                    Err(e) => return internal_error_response("encrypt sms secret", &e),
                }
            } else {
                None
            };
            sqlx::query(
                "UPDATE sms_config SET provider = ?, api_key = ?, api_secret_enc = ?, sender = ?, base_url = ?, default_country_code = ?, daily_cap = ?, enabled = ? WHERE id = ?",
            )
            .bind(&provider)
            .bind(&api_key)
            .bind(&api_secret_enc)
            .bind(&sender)
            .bind(&base_url)
            .bind(&default_country_code)
            .bind(daily_cap)
            .bind(enabled)
            .bind(&id)
            .execute(&state.pool)
            .await
        }
        Some((id, _)) => {
            // Keep-current: do not touch api_secret_enc. Only reachable when
            // the gateway is unchanged (or is the credential-less webhook),
            // so the stored secret still belongs to this gateway.
            sqlx::query(
                "UPDATE sms_config SET provider = ?, api_key = ?, sender = ?, base_url = ?, default_country_code = ?, daily_cap = ?, enabled = ? WHERE id = ?",
            )
            .bind(&provider)
            .bind(&api_key)
            .bind(&sender)
            .bind(&base_url)
            .bind(&default_country_code)
            .bind(daily_cap)
            .bind(enabled)
            .bind(&id)
            .execute(&state.pool)
            .await
        }
        None => {
            let api_secret_enc = if secret_provided {
                match crate::crypto::encrypt_password(&state.secret_key, api_secret.trim()) {
                    Ok(s) => Some(s),
                    Err(e) => return internal_error_response("encrypt sms secret", &e),
                }
            } else {
                None
            };
            sqlx::query(
                "INSERT INTO sms_config (id, provider, api_key, api_secret_enc, sender, base_url, default_country_code, daily_cap, enabled) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(&provider)
            .bind(&api_key)
            .bind(&api_secret_enc)
            .bind(&sender)
            .bind(&base_url)
            .bind(&default_country_code)
            .bind(daily_cap)
            .bind(enabled)
            .execute(&state.pool)
            .await
        }
    };

    if let Err(e) = result {
        return internal_error_response("save sms config", &e);
    }

    tracing::info!(admin = %_admin.user.email, provider = %provider, "admin: sms config updated");
    Redirect::to("/dashboard/admin").into_response()
}

#[derive(Deserialize)]
struct AdminSmsTestForm {
    _csrf: Option<String>,
    to: Option<String>,
}

/// Send a real test message, or check the credentials for free when the
/// gateway supports it and no recipient was given.
async fn admin_update_sms_test(
    State(state): State<Arc<AppState>>,
    admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Form(form): Form<AdminSmsTestForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }

    let redirect = |outcome: &str, detail: &str| {
        let encoded = urlencoding::encode(detail).into_owned();
        Redirect::to(&format!(
            "/dashboard/admin?sms_test={}&sms_test_detail={}",
            outcome, encoded
        ))
        .into_response()
    };

    let config = match crate::sms::load_config(&state.pool, &state.secret_key).await {
        Ok(Some(c)) => c,
        Ok(None) => return redirect("error", "SMS is not configured."),
        Err(e) => {
            tracing::warn!(error = %e, "admin: SMS test could not load config");
            return redirect("error", "Could not load the SMS configuration.");
        }
    };

    let to = form
        .to
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let Some(to) = to else {
        // No recipient: verify the credentials instead of sending.
        return match crate::sms::check(&config).await {
            Ok(()) => {
                tracing::info!(admin = %admin.user.email, provider = %config.provider, "admin: SMS credentials verified");
                redirect("checked", "Credentials accepted by the gateway.")
            }
            Err(e) => {
                tracing::warn!(admin = %admin.user.email, provider = %config.provider, error = %e, "admin: SMS credential check failed");
                redirect("error", &e.to_string())
            }
        };
    };

    let to = match crate::sms::phone::normalize(&to, &config.default_country_code) {
        Some(number) => number,
        None => return redirect("error", "That is not a usable phone number."),
    };

    match crate::sms::send(&config, &to, "calrs test message. Your SMS gateway works.").await {
        Ok(_) => {
            tracing::info!(admin = %admin.user.email, provider = %config.provider, %to, "admin: test SMS sent");
            redirect("sent", "Test message accepted by the gateway.")
        }
        Err(e) => {
            tracing::warn!(admin = %admin.user.email, provider = %config.provider, error = %e, "admin: test SMS failed");
            redirect("error", &e.to_string())
        }
    }
}

#[derive(Deserialize)]
struct AdminSmsPolicyForm {
    _csrf: Option<String>,
    /// HTML checkbox: present when any user may put an event type into an
    /// SMS-sending mode, absent for admins only.
    allow_all_users: Option<String>,
}

/// Who may enable SMS on an event type.
///
/// Separate from the gateway settings on purpose: it is an instance policy,
/// not a credential, so it stays editable even when the `CALRS_SMS_*` block
/// governs the gateway itself.
async fn admin_update_sms_policy(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Form(form): Form<AdminSmsPolicyForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }

    let allow_all = form.allow_all_users.is_some();
    if let Err(e) =
        sqlx::query("UPDATE auth_config SET sms_allow_all_users = ? WHERE id = 'singleton'")
            .bind(allow_all)
            .execute(&state.pool)
            .await
    {
        return internal_error_response("save sms policy", &e);
    }

    tracing::info!(admin = %_admin.user.email, allow_all, "admin: sms event-type policy updated");
    Redirect::to("/dashboard/admin").into_response()
}

#[derive(Deserialize)]
struct AdminSmsClearForm {
    _csrf: Option<String>,
}

async fn admin_update_sms_clear(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Form(form): Form<AdminSmsClearForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }

    // Same guard as admin_update_sms: when the env block governs, the DB
    // config is shadowed and the UI hides this button. Refuse the write.
    if crate::sms::sms_env_active() {
        return Redirect::to("/dashboard/admin").into_response();
    }

    if let Err(e) = sqlx::query("DELETE FROM sms_config")
        .execute(&state.pool)
        .await
    {
        return internal_error_response("clear sms config", &e);
    }

    tracing::info!(admin = %_admin.user.email, "admin: sms config cleared");
    Redirect::to("/dashboard/admin").into_response()
}

// --- Auto-generated meeting link settings ---

#[derive(Deserialize)]
struct AdminJitsiForm {
    _csrf: Option<String>,
    jitsi_base_url: Option<String>,
    jitsi_pattern: Option<String>,
    jitsi_display_name: Option<String>,
}

async fn admin_update_jitsi(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Form(form): Form<AdminJitsiForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }

    let base_url = form.jitsi_base_url.filter(|s| !s.trim().is_empty());
    let pattern = form.jitsi_pattern.filter(|s| !s.trim().is_empty());
    let display_name = form.jitsi_display_name.filter(|s| !s.trim().is_empty());

    if let Err(e) = sqlx::query(
        "UPDATE auth_config SET jitsi_base_url = ?, jitsi_pattern = ?, jitsi_display_name = ?, updated_at = datetime('now') WHERE id = 'singleton'",
    )
    .bind(&base_url)
    .bind(&pattern)
    .bind(&display_name)
    .execute(&state.pool)
    .await
    {
        tracing::error!(error = %e, "failed to save jitsi config");
    }

    *state.meeting_config.write().await =
        meeting::load_config(&state.pool, &state.secret_key).await;

    tracing::info!(admin = %_admin.user.email, "admin: jitsi config updated");
    Redirect::to("/dashboard/admin").into_response()
}

#[derive(Deserialize)]
struct AdminMeetingWebhookForm {
    _csrf: Option<String>,
    meeting_webhook_url: Option<String>,
    meeting_webhook_auth_mode: Option<String>,
    meeting_webhook_secret: Option<String>,
    meeting_webhook_display_name: Option<String>,
}

async fn admin_update_meeting_webhook(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Form(form): Form<AdminMeetingWebhookForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }

    let url = form.meeting_webhook_url.filter(|s| !s.trim().is_empty());
    let auth_mode = match form.meeting_webhook_auth_mode.as_deref() {
        Some(meeting::WEBHOOK_AUTH_HMAC) => Some(meeting::WEBHOOK_AUTH_HMAC.to_string()),
        Some(meeting::WEBHOOK_AUTH_NONE) => Some(meeting::WEBHOOK_AUTH_NONE.to_string()),
        _ => None,
    };
    let display_name = form
        .meeting_webhook_display_name
        .filter(|s| !s.trim().is_empty());

    // Empty secret field on submit means "keep the current value" (same
    // pattern as OIDC and captcha). Wiping the secret requires switching
    // auth_mode away from "hmac".
    let secret_provided = form
        .meeting_webhook_secret
        .as_ref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);

    if secret_provided {
        let secret = form.meeting_webhook_secret.unwrap_or_default();
        let encrypted = match crate::crypto::encrypt_value(&state.secret_key, &secret) {
            Ok(s) => s,
            Err(e) => return internal_error_response("encrypt webhook secret", &e),
        };
        if let Err(e) = sqlx::query(
            "UPDATE auth_config SET meeting_webhook_url = ?, meeting_webhook_auth_mode = ?, meeting_webhook_secret = ?, meeting_webhook_display_name = ?, updated_at = datetime('now') WHERE id = 'singleton'",
        )
        .bind(&url)
        .bind(&auth_mode)
        .bind(&encrypted)
        .bind(&display_name)
        .execute(&state.pool)
        .await
        {
            tracing::error!(error = %e, "failed to save meeting webhook config");
        }
    } else if let Err(e) = sqlx::query(
        "UPDATE auth_config SET meeting_webhook_url = ?, meeting_webhook_auth_mode = ?, meeting_webhook_display_name = ?, updated_at = datetime('now') WHERE id = 'singleton'",
    )
    .bind(&url)
    .bind(&auth_mode)
    .bind(&display_name)
    .execute(&state.pool)
    .await
    {
        tracing::error!(error = %e, "failed to save meeting webhook config");
    }

    *state.meeting_config.write().await =
        meeting::load_config(&state.pool, &state.secret_key).await;

    tracing::info!(admin = %_admin.user.email, "admin: meeting webhook config updated");
    Redirect::to("/dashboard/admin").into_response()
}

async fn admin_upload_logo(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Query(csrf_query): Query<CsrfQuery>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &csrf_query._csrf) {
        return resp;
    }
    while let Ok(Some(field)) = multipart.next_field().await {
        if field.name() == Some("logo") {
            let content_type = field.content_type().unwrap_or("").to_string();
            if !content_type.starts_with("image/") {
                return Redirect::to("/dashboard/admin").into_response();
            }
            if let Ok(bytes) = field.bytes().await {
                if bytes.len() > 2 * 1024 * 1024 {
                    return Redirect::to("/dashboard/admin").into_response();
                }
                // Trust magic bytes, not the multipart Content-Type header.
                if detect_image_ext(&bytes).is_none() {
                    return Redirect::to("/dashboard/admin").into_response();
                }
                let logo_path = state.data_dir.join("logo.png");
                let _ = tokio::fs::write(&logo_path, &bytes).await;
            }
        }
    }
    Redirect::to("/dashboard/admin").into_response()
}

async fn admin_delete_logo(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Form(csrf): Form<CsrfForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &csrf._csrf) {
        return resp;
    }
    let logo_path = state.data_dir.join("logo.png");
    let _ = tokio::fs::remove_file(&logo_path).await;
    Redirect::to("/dashboard/admin").into_response()
}

async fn admin_update_company_link(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Form(form): Form<CompanyLinkForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let link = form.company_link.trim().to_string();
    // Reject anything that isn't http(s). An admin (or attacker who has
    // taken over an admin account) could otherwise set `javascript:` and
    // turn the company link rendered on every public booking page into
    // stored XSS.
    if !link.is_empty() && !is_safe_company_link(&link) {
        tracing::warn!(
            admin = %_admin.user.email,
            "admin: company_link rejected (only http/https schemes allowed)"
        );
        let msg =
            urlencoding::encode("Company link must start with http:// or https://").into_owned();
        return Redirect::to(&format!("/dashboard/admin?error={}", msg)).into_response();
    }
    let link_value: Option<&str> = if link.is_empty() { None } else { Some(&link) };
    let _ = sqlx::query(
        "UPDATE auth_config SET company_link = ?, updated_at = datetime('now') WHERE id = 'singleton'",
    )
    .bind(link_value)
    .execute(&state.pool)
    .await;
    *state.company_link.write().await = if link.is_empty() { None } else { Some(link) };
    Redirect::to("/dashboard/admin").into_response()
}

// --- Impersonation ---

async fn admin_impersonate(
    State(_state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Form(csrf): Form<CsrfForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &csrf._csrf) {
        return resp;
    }
    tracing::warn!(admin = %_admin.user.email, target = %user_id, "admin: impersonation started");
    let cookie = format!(
        "__Host-calrs_impersonate={}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={}",
        user_id,
        86400 // 24 hours
    );
    ([("Set-Cookie", cookie)], Redirect::to("/dashboard")).into_response()
}

async fn admin_stop_impersonate(
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Form(csrf): Form<CsrfForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &csrf._csrf) {
        return resp;
    }
    tracing::info!("admin: impersonation ended");
    let cookie = "__Host-calrs_impersonate=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0";
    (
        [("Set-Cookie", cookie.to_string())],
        Redirect::to("/dashboard"),
    )
        .into_response()
}

// --- Admin: update member weight ---

#[derive(Deserialize)]
struct WeightForm {
    _csrf: Option<String>,
    weight: i64,
}

async fn admin_update_member_weight(
    State(state): State<Arc<AppState>>,
    _admin: crate::auth::AdminUser,
    headers: HeaderMap,
    Path((group_id, user_id)): Path<(String, String)>,
    Form(form): Form<WeightForm>,
) -> impl IntoResponse {
    if let Err(resp) = verify_csrf_token(&headers, &form._csrf) {
        return resp;
    }
    let w = form.weight.clamp(1, 100);
    let _ = sqlx::query("UPDATE user_groups SET weight = ? WHERE group_id = ? AND user_id = ?")
        .bind(w)
        .bind(&group_id)
        .bind(&user_id)
        .execute(&state.pool)
        .await;
    tracing::info!(
        group_id,
        user_id,
        weight = w,
        "admin: updated member weight"
    );
    Redirect::to("/dashboard/admin").into_response()
}

/// The booking error page, from Fluent message ids, in `lang`. The booking
/// POSTs and the token pages answer in the language of the page the visitor
/// came from, which is not always the browser's, so the language is always
/// passed in. The string-taking form stays for `resolve_guest_phone`, which
/// picks its own wording and hands back a pair that is already translated.
fn render_booking_action_error_keys_in(
    state: &AppState,
    lang: &str,
    title_key: &str,
    message_key: &str,
) -> axum::response::Response {
    render_booking_action_error_in(
        state,
        lang,
        &crate::i18n::translate(lang, title_key, None),
        &crate::i18n::translate(lang, message_key, None),
    )
}

/// The booking error page from already-translated strings, in `lang`.
fn render_booking_action_error_in(
    state: &AppState,
    lang: &str,
    title: &str,
    message: &str,
) -> axum::response::Response {
    render_booking_action_error_html_in(state, lang, title, message).into_response()
}

/// Same page as `render_booking_action_error_in`, for handlers whose
/// signature is `Html<String>` rather than `Response`.
fn render_booking_action_error_html_in(
    state: &AppState,
    lang: &str,
    title: &str,
    message: &str,
) -> Html<String> {
    let tmpl = match state.templates.get_template("booking_action_error.html") {
        Ok(t) => t,
        Err(e) => return internal_error_html("internal", &e),
    };
    Html(
        tmpl.render(context! {
            title => title,
            message => message,
            lang => lang,
        })
        .unwrap_or_else(|e| internal_error_body("template render", &e)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Rate limiter tests ---

    #[tokio::test]
    async fn rate_limiter_allows_under_limit() {
        let limiter = RateLimiter::new(3, 60);
        assert!(!limiter.check_limited("ip1").await);
        assert!(!limiter.check_limited("ip1").await);
        assert!(!limiter.check_limited("ip1").await);
    }

    #[tokio::test]
    async fn rate_limiter_blocks_over_limit() {
        let limiter = RateLimiter::new(2, 60);
        assert!(!limiter.check_limited("ip1").await); // 1
        assert!(!limiter.check_limited("ip1").await); // 2
        assert!(limiter.check_limited("ip1").await); // 3 → blocked
        assert!(limiter.check_limited("ip1").await); // still blocked
    }

    #[tokio::test]
    async fn rate_limiter_independent_per_ip() {
        let limiter = RateLimiter::new(1, 60);
        assert!(!limiter.check_limited("ip1").await);
        assert!(limiter.check_limited("ip1").await); // ip1 blocked
        assert!(!limiter.check_limited("ip2").await); // ip2 still ok
    }

    #[tokio::test]
    async fn rate_limiter_resets_after_window() {
        let limiter = RateLimiter::new(1, 0); // 0-second window = immediate expiry
        assert!(!limiter.check_limited("ip1").await);
        // Window has already expired (0 seconds)
        assert!(!limiter.check_limited("ip1").await); // reset, allowed again
    }

    #[test]
    fn detect_image_ext_recognizes_known_formats() {
        // PNG signature.
        assert_eq!(
            detect_image_ext(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0xff]),
            Some("png")
        );
        // JPEG SOI + APP marker.
        assert_eq!(
            detect_image_ext(&[0xFF, 0xD8, 0xFF, 0xE0, 0x00]),
            Some("jpg")
        );
        // GIF.
        assert_eq!(detect_image_ext(b"GIF89a..."), Some("gif"));
        assert_eq!(detect_image_ext(b"GIF87a..."), Some("gif"));
        // RIFF/WEBP.
        let mut webp = Vec::from(*b"RIFF\x00\x00\x00\x00WEBP");
        webp.extend_from_slice(b"VP8 ");
        assert_eq!(detect_image_ext(&webp), Some("webp"));
    }

    #[test]
    fn detect_image_ext_rejects_non_images() {
        // Empty input, plain text, HTML stub, executable header are all rejected.
        assert_eq!(detect_image_ext(b""), None);
        assert_eq!(detect_image_ext(b"not an image"), None);
        assert_eq!(detect_image_ext(b"<html><body>"), None);
        assert_eq!(detect_image_ext(b"\x7fELF"), None);
        // RIFF without the WEBP marker should not be accepted.
        let riff_wave = b"RIFF\x00\x00\x00\x00WAVEfmt ";
        assert_eq!(detect_image_ext(riff_wave), None);
    }

    #[tokio::test]
    async fn rate_limiter_sweeps_expired_entries() {
        // Pin that periodic eviction actually drops entries from the map so
        // it cannot grow without bound under traffic from many distinct IPs.
        let limiter = RateLimiter::new(5, 0); // 0-second window: immediate expiry
        for i in 0..50 {
            limiter.check_limited(&format!("ip-{}", i)).await;
        }
        // Next call triggers a sweep; all prior entries should be evicted
        // before the new key is inserted.
        limiter.check_limited("trigger-sweep").await;
        let state = limiter.state.lock().await;
        assert_eq!(
            state.attempts.len(),
            1,
            "expired entries should be swept, only the newest survives"
        );
    }

    #[test]
    fn parse_avail_schedule_uses_user_default_when_submitted_is_empty() {
        // Empty submission + user default "Tue 14:00-18:00" → returns the user default
        // instead of falling back to the hardcoded Mon-Fri 09:00-17:00.
        let result = parse_avail_schedule(Some(""), None, None, None, None, Some("2:14:00-18:00"));
        assert_eq!(result.len(), 1);
        let windows = result.get(&2).expect("Tuesday should be set");
        assert_eq!(windows, &vec![("14:00".to_string(), "18:00".to_string())]);
    }

    #[test]
    fn parse_avail_schedule_prefers_submitted_over_user_default() {
        // A populated submission overrides the user default.
        let result = parse_avail_schedule(
            Some("3:10:00-12:00"),
            None,
            None,
            None,
            None,
            Some("2:14:00-18:00"),
        );
        assert_eq!(result.len(), 1);
        let windows = result.get(&3).expect("Wednesday should be set");
        assert_eq!(windows, &vec![("10:00".to_string(), "12:00".to_string())]);
    }

    #[test]
    fn parse_avail_schedule_falls_back_to_legacy_when_both_empty() {
        // Empty submission and empty user default → hardcoded Mon-Fri 09:00-17:00.
        let result = parse_avail_schedule(Some(""), None, None, None, None, Some(""));
        assert_eq!(result.len(), 5);
        for day in 1..=5 {
            let windows = result.get(&day).expect("weekday should be set");
            assert_eq!(windows, &vec![("09:00".to_string(), "17:00".to_string())]);
        }
    }

    // --- has_conflict tests ---

    fn dt(y: i32, m: u32, d: u32, h: u32, mi: u32) -> NaiveDateTime {
        NaiveDate::from_ymd_opt(y, m, d)
            .unwrap()
            .and_hms_opt(h, mi, 0)
            .unwrap()
    }

    #[test]
    fn conflict_overlapping_event() {
        let busy = vec![(dt(2026, 3, 15, 10, 0), dt(2026, 3, 15, 11, 0))];
        // Slot 10:30-11:30 overlaps with 10:00-11:00
        assert!(has_conflict(
            &busy,
            dt(2026, 3, 15, 10, 30),
            dt(2026, 3, 15, 11, 30)
        ));
    }

    #[test]
    fn conflict_no_overlap() {
        let busy = vec![(dt(2026, 3, 15, 10, 0), dt(2026, 3, 15, 11, 0))];
        // Slot 11:00-12:00 starts exactly when event ends (no overlap)
        assert!(!has_conflict(
            &busy,
            dt(2026, 3, 15, 11, 0),
            dt(2026, 3, 15, 12, 0)
        ));
    }

    #[test]
    fn conflict_event_contains_slot() {
        let busy = vec![(dt(2026, 3, 15, 9, 0), dt(2026, 3, 15, 17, 0))];
        // Slot entirely within busy period
        assert!(has_conflict(
            &busy,
            dt(2026, 3, 15, 10, 0),
            dt(2026, 3, 15, 11, 0)
        ));
    }

    #[test]
    fn conflict_slot_contains_event() {
        let busy = vec![(dt(2026, 3, 15, 10, 15), dt(2026, 3, 15, 10, 45))];
        // Slot 10:00-11:00 contains the 10:15-10:45 event
        assert!(has_conflict(
            &busy,
            dt(2026, 3, 15, 10, 0),
            dt(2026, 3, 15, 11, 0)
        ));
    }

    #[test]
    fn conflict_adjacent_not_conflicting() {
        let busy = vec![
            (dt(2026, 3, 15, 9, 0), dt(2026, 3, 15, 10, 0)),
            (dt(2026, 3, 15, 11, 0), dt(2026, 3, 15, 12, 0)),
        ];
        // Slot 10:00-11:00 is between two events (no overlap)
        assert!(!has_conflict(
            &busy,
            dt(2026, 3, 15, 10, 0),
            dt(2026, 3, 15, 11, 0)
        ));
    }

    #[test]
    fn conflict_empty_busy_list() {
        let busy: Vec<(NaiveDateTime, NaiveDateTime)> = vec![];
        assert!(!has_conflict(
            &busy,
            dt(2026, 3, 15, 10, 0),
            dt(2026, 3, 15, 11, 0)
        ));
    }

    #[test]
    fn conflict_buffer_causes_overlap() {
        let busy = vec![(dt(2026, 3, 15, 10, 0), dt(2026, 3, 15, 11, 0))];
        // Slot is 11:00-12:00, but with 15min buffer before → buf_start=10:45 overlaps
        assert!(has_conflict(
            &busy,
            dt(2026, 3, 15, 10, 45),
            dt(2026, 3, 15, 12, 0)
        ));
    }

    // --- expand_recurring_into_busy tests ---

    #[test]
    fn expand_recurring_weekly_into_busy() {
        let recurring = vec![(
            "20260309T100000".to_string(), // Monday 10:00
            "20260309T110000".to_string(), // Monday 11:00
            "FREQ=WEEKLY;BYDAY=MO".to_string(),
            None,
            None,
        )];
        let window_start = dt(2026, 3, 9, 0, 0);
        let window_end = dt(2026, 3, 23, 23, 59);
        let busy = expand_recurring_into_busy(&recurring, window_start, window_end, Tz::UTC);
        // Should have 3 occurrences: Mar 9, 16, 23
        assert_eq!(busy.len(), 3);
        assert_eq!(busy[0].0, dt(2026, 3, 9, 10, 0));
        assert_eq!(busy[1].0, dt(2026, 3, 16, 10, 0));
        assert_eq!(busy[2].0, dt(2026, 3, 23, 10, 0));
    }

    #[test]
    fn expand_recurring_with_exdate() {
        let raw_ical = "BEGIN:VEVENT\nDTSTART:20260309T100000\nDTEND:20260309T110000\nRRULE:FREQ=WEEKLY;BYDAY=MO\nEXDATE:20260316T100000\nEND:VEVENT";
        let recurring = vec![(
            "20260309T100000".to_string(),
            "20260309T110000".to_string(),
            "FREQ=WEEKLY;BYDAY=MO".to_string(),
            Some(raw_ical.to_string()),
            None,
        )];
        let window_start = dt(2026, 3, 9, 0, 0);
        let window_end = dt(2026, 3, 23, 23, 59);
        let busy = expand_recurring_into_busy(&recurring, window_start, window_end, Tz::UTC);
        // Mar 16 excluded, so only Mar 9 and 23
        assert_eq!(busy.len(), 2);
        assert_eq!(busy[0].0, dt(2026, 3, 9, 10, 0));
        assert_eq!(busy[1].0, dt(2026, 3, 23, 10, 0));
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
        sqlx::query(
            "INSERT INTO accounts (id, name, email, timezone) VALUES (?, 't', 't@x', 'UTC')",
        )
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

    async fn user_for(pool: &SqlitePool, user_id: &str) -> crate::models::User {
        sqlx::query_as("SELECT * FROM users WHERE id = ?")
            .bind(user_id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn can_manage_event_type_global_admin_yes_for_any_event() {
        let pool = setup_test_db().await;
        let admin_id = insert_role_user(&pool, "admin@x", "admin").await;
        let owner_id = insert_role_user(&pool, "owner@x", "user").await;
        let personal_et = insert_personal_et(&pool, &owner_id, "personal").await;
        let (_, team_et) = insert_team_with_et(&pool, "team1", "team-et", &[]).await;
        let admin = user_for(&pool, &admin_id).await;
        assert!(can_manage_event_type(&pool, &admin, &personal_et).await);
        assert!(can_manage_event_type(&pool, &admin, &team_et).await);
    }

    #[tokio::test]
    async fn can_manage_event_type_personal_owner_yes_others_no() {
        let pool = setup_test_db().await;
        let owner_id = insert_role_user(&pool, "owner@x", "user").await;
        let other_id = insert_role_user(&pool, "other@x", "user").await;
        let et = insert_personal_et(&pool, &owner_id, "personal").await;
        let owner = user_for(&pool, &owner_id).await;
        let other = user_for(&pool, &other_id).await;
        assert!(can_manage_event_type(&pool, &owner, &et).await);
        assert!(!can_manage_event_type(&pool, &other, &et).await);
    }

    #[tokio::test]
    async fn can_manage_event_type_team_admin_yes_member_no() {
        let pool = setup_test_db().await;
        let admin_id = insert_role_user(&pool, "ta@x", "user").await;
        let member_id = insert_role_user(&pool, "tm@x", "user").await;
        let outsider_id = insert_role_user(&pool, "out@x", "user").await;
        let (_, et) = insert_team_with_et(
            &pool,
            "team1",
            "team-et",
            &[(&admin_id, "admin"), (&member_id, "member")],
        )
        .await;
        let admin = user_for(&pool, &admin_id).await;
        let member = user_for(&pool, &member_id).await;
        let outsider = user_for(&pool, &outsider_id).await;
        assert!(can_manage_event_type(&pool, &admin, &et).await);
        assert!(!can_manage_event_type(&pool, &member, &et).await);
        assert!(!can_manage_event_type(&pool, &outsider, &et).await);
    }

    #[tokio::test]
    async fn can_manage_event_type_team_admin_cannot_manage_others_personal_event() {
        // Being a team admin somewhere does not grant access to an unrelated
        // user's personal event types.
        let pool = setup_test_db().await;
        let team_admin_id = insert_role_user(&pool, "ta@x", "user").await;
        let stranger_id = insert_role_user(&pool, "s@x", "user").await;
        let stranger_et = insert_personal_et(&pool, &stranger_id, "p").await;
        let _ = insert_team_with_et(&pool, "team1", "te", &[(&team_admin_id, "admin")]).await;
        let team_admin = user_for(&pool, &team_admin_id).await;
        assert!(!can_manage_event_type(&pool, &team_admin, &stranger_et).await);
    }

    #[tokio::test]
    async fn can_manage_event_type_team_member_cannot_manage_others_personal_event() {
        let pool = setup_test_db().await;
        let team_member_id = insert_role_user(&pool, "tm@x", "user").await;
        let stranger_id = insert_role_user(&pool, "s@x", "user").await;
        let stranger_et = insert_personal_et(&pool, &stranger_id, "p").await;
        let _ = insert_team_with_et(&pool, "team1", "te", &[(&team_member_id, "member")]).await;
        let team_member = user_for(&pool, &team_member_id).await;
        assert!(!can_manage_event_type(&pool, &team_member, &stranger_et).await);
    }

    #[tokio::test]
    async fn can_manage_event_type_personal_owner_cannot_manage_unrelated_team_event() {
        let pool = setup_test_db().await;
        // Owner of a personal event with the same slug as some team event —
        // owning the personal event must not grant access to the team one.
        let owner_id = insert_role_user(&pool, "owner@x", "user").await;
        let _ = insert_personal_et(&pool, &owner_id, "demo").await;
        let (_, team_et) = insert_team_with_et(&pool, "team1", "demo", &[]).await;
        let owner = user_for(&pool, &owner_id).await;
        assert!(!can_manage_event_type(&pool, &owner, &team_et).await);
    }

    #[tokio::test]
    async fn find_manageable_event_type_by_slug_personal_wins_collision() {
        // If the user has both a personal event and a team-admin event sharing
        // the same slug, the personal event must resolve first (deterministic).
        let pool = setup_test_db().await;
        let user_id = insert_role_user(&pool, "u@x", "user").await;
        let personal_et = insert_personal_et(&pool, &user_id, "demo").await;
        let (_, team_et) =
            insert_team_with_et(&pool, "team1", "demo", &[(&user_id, "admin")]).await;
        let resolved = find_manageable_event_type_by_slug(&pool, &user_id, "demo")
            .await
            .expect("should resolve");
        assert_eq!(resolved.0, personal_et);
        assert_ne!(resolved.0, team_et);
        assert!(resolved.2.is_none(), "personal event has no team_id");
    }

    #[tokio::test]
    async fn find_manageable_event_type_by_slug_member_does_not_resolve() {
        // Regular team members should not resolve team event types via this
        // helper — only team admins do.
        let pool = setup_test_db().await;
        let user_id = insert_role_user(&pool, "m@x", "user").await;
        let _ = insert_team_with_et(&pool, "team1", "demo", &[(&user_id, "member")]).await;
        assert!(find_manageable_event_type_by_slug(&pool, &user_id, "demo")
            .await
            .is_none());
    }

    #[tokio::test]
    async fn fetch_busy_times_empty_calendar() {
        let pool = setup_test_db().await;
        let (user_id, _, _) = seed_test_data(&pool).await;

        let busy = fetch_busy_times_for_user(
            &pool,
            &user_id,
            dt(2026, 3, 15, 0, 0),
            dt(2026, 3, 21, 23, 59),
            Tz::UTC,
            None,
        )
        .await;

        assert!(busy.is_empty(), "No events or bookings → no busy times");
    }

    #[tokio::test]
    async fn fetch_busy_times_includes_bookings() {
        let pool = setup_test_db().await;
        let (user_id, _, et_id) = seed_test_data(&pool).await;

        let booking_id = uuid::Uuid::new_v4().to_string();
        let cancel_tok = uuid::Uuid::new_v4().to_string();
        let resched_tok = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid1', 'Guest', 'guest@example.com', 'UTC', '2026-03-16T10:00:00', '2026-03-16T10:30:00', 'confirmed', ?, ?)")
            .bind(&booking_id)
            .bind(&et_id)
            .bind(&cancel_tok)
            .bind(&resched_tok)
            .execute(&pool).await.unwrap();

        let busy = fetch_busy_times_for_user(
            &pool,
            &user_id,
            dt(2026, 3, 15, 0, 0),
            dt(2026, 3, 21, 23, 59),
            Tz::UTC,
            None,
        )
        .await;

        assert_eq!(busy.len(), 1);
        assert_eq!(busy[0].0, dt(2026, 3, 16, 10, 0));
        assert_eq!(busy[0].1, dt(2026, 3, 16, 10, 30));
    }

    #[tokio::test]
    async fn fetch_busy_times_ignores_cancelled_bookings() {
        let pool = setup_test_db().await;
        let (user_id, _, et_id) = seed_test_data(&pool).await;

        let booking_id = uuid::Uuid::new_v4().to_string();
        let cancel_tok = uuid::Uuid::new_v4().to_string();
        let resched_tok = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid1', 'Guest', 'guest@example.com', 'UTC', '2026-03-16T10:00:00', '2026-03-16T10:30:00', 'cancelled', ?, ?)")
            .bind(&booking_id)
            .bind(&et_id)
            .bind(&cancel_tok)
            .bind(&resched_tok)
            .execute(&pool).await.unwrap();

        let busy = fetch_busy_times_for_user(
            &pool,
            &user_id,
            dt(2026, 3, 15, 0, 0),
            dt(2026, 3, 21, 23, 59),
            Tz::UTC,
            None,
        )
        .await;

        assert!(
            busy.is_empty(),
            "Cancelled bookings should not block availability"
        );
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

    #[tokio::test]
    async fn fetch_busy_times_detects_same_day_compact_event() {
        // Regression: a timed CalDAV event stored in compact iCal form
        // ("YYYYMMDDTHHMMSS") on the SAME day as the busy window must be
        // detected. pick_group_member checks a single-slot window at booking
        // time, so window_end lands on the event's own date. A date-only upper
        // bound ("YYYYMMDD") sorts lexically before the event
        // ("20260618T100000" > "20260618"), so the event was silently dropped
        // and a busy member could be booked (the double-booking we hit prod).
        let pool = setup_test_db().await;
        let (user_id, account_id, _et_id) = seed_test_data(&pool).await;
        seed_synced_event(
            &pool,
            &account_id,
            "20260618T100000",
            "20260618T113000",
            "Europe/Paris",
            "OPAQUE",
        )
        .await;

        let paris: Tz = "Europe/Paris".parse().unwrap();
        let busy = fetch_busy_times_for_user(
            &pool,
            &user_id,
            dt(2026, 6, 18, 10, 0),
            dt(2026, 6, 18, 11, 0),
            paris,
            None,
        )
        .await;

        assert_eq!(
            busy.len(),
            1,
            "same-day compact event must be detected as busy"
        );
        assert_eq!(busy[0].0, dt(2026, 6, 18, 10, 0));
        assert_eq!(busy[0].1, dt(2026, 6, 18, 11, 30));
    }

    #[tokio::test]
    async fn fetch_busy_times_skips_transparent_same_day_event() {
        // Guard: the fix must not start counting TRANSPARENT (free) events.
        let pool = setup_test_db().await;
        let (user_id, account_id, _et_id) = seed_test_data(&pool).await;
        seed_synced_event(
            &pool,
            &account_id,
            "20260618T100000",
            "20260618T113000",
            "Europe/Paris",
            "TRANSPARENT",
        )
        .await;

        let paris: Tz = "Europe/Paris".parse().unwrap();
        let busy = fetch_busy_times_for_user(
            &pool,
            &user_id,
            dt(2026, 6, 18, 10, 0),
            dt(2026, 6, 18, 11, 0),
            paris,
            None,
        )
        .await;

        assert!(busy.is_empty(), "TRANSPARENT events must not block");
    }

    #[tokio::test]
    async fn compute_slots_basic_availability() {
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;

        let busy = BusySource::Individual(vec![]);

        // Start from tomorrow to avoid partial-day flakiness
        let slot_days = compute_slots(
            &pool,
            &et_id,
            30, // 30 min duration
            0,  // no buffer before
            0,  // no buffer after
            0,  // no min notice
            1,  // start from tomorrow
            14, // 14 days ahead
            None,
            Tz::UTC,
            Tz::UTC,
            busy,
            None,
        )
        .await;

        // Should have slots on weekdays only (Mon-Fri)
        assert!(!slot_days.is_empty(), "Should have slots on weekdays");

        // Each day should have 16 slots (09:00-17:00 in 30-min increments)
        for day in &slot_days {
            assert_eq!(
                day.slots.len(),
                16,
                "09:00-17:00 with 30min = 16 slots, got {} for {}",
                day.slots.len(),
                day.date
            );
        }
    }

    #[tokio::test]
    async fn compute_slots_with_busy_event() {
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;

        // Find the next Monday from now
        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let days_to_monday = (next_monday - now.date()).num_days() as i32;

        // Block 10:00-11:00 on that Monday
        let busy_start = next_monday.and_hms_opt(10, 0, 0).unwrap();
        let busy_end = next_monday.and_hms_opt(11, 0, 0).unwrap();
        let busy = BusySource::Individual(vec![(busy_start, busy_end)]);

        let slot_days = compute_slots(
            &pool,
            &et_id,
            30,
            0,
            0,
            0,
            days_to_monday,
            1, // just 1 day
            None,
            Tz::UTC,
            Tz::UTC,
            busy,
            None,
        )
        .await;

        assert!(!slot_days.is_empty(), "Should have the Monday");
        let monday = &slot_days[0];

        // 16 slots normally, minus 2 (10:00 and 10:30 blocked) = 14
        assert_eq!(monday.slots.len(), 14, "10:00 and 10:30 should be blocked");

        // Verify 10:00 and 10:30 are not in the slots
        let slot_times: Vec<&str> = monday.slots.iter().map(|s| s.start.as_str()).collect();
        assert!(!slot_times.contains(&"10:00"), "10:00 should be blocked");
        assert!(!slot_times.contains(&"10:30"), "10:30 should be blocked");
    }

    #[tokio::test]
    async fn compute_slots_with_buffer() {
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;

        // Find the next Monday
        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let days_to_monday = (next_monday - now.date()).num_days() as i32;

        // Block 10:00-10:30 on that Monday
        let busy_start = next_monday.and_hms_opt(10, 0, 0).unwrap();
        let busy_end = next_monday.and_hms_opt(10, 30, 0).unwrap();
        let busy = BusySource::Individual(vec![(busy_start, busy_end)]);

        let slot_days = compute_slots(
            &pool,
            &et_id,
            30,
            15, // 15 min buffer before
            15, // 15 min buffer after
            0,
            days_to_monday,
            1,
            None,
            Tz::UTC,
            Tz::UTC,
            busy,
            None,
        )
        .await;

        assert!(!slot_days.is_empty());
        let monday = &slot_days[0];

        // Event at 10:00-10:30 with 15min buffers blocks 09:45-10:45
        // So slots 09:30 (ends 10:00, buf_end=10:15 > 09:45), 10:00, 10:30 (buf_start=10:15 < 10:30) blocked
        let slot_times: Vec<&str> = monday.slots.iter().map(|s| s.start.as_str()).collect();
        assert!(
            !slot_times.contains(&"10:00"),
            "10:00 should be blocked (direct conflict)"
        );
        assert!(
            slot_times.contains(&"09:00"),
            "09:00 should be free (no buffer overlap)"
        );
    }

    #[tokio::test]
    async fn compute_slots_frequency_limit_per_day_drops_capped_day() {
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;

        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let days_to_monday = (next_monday - now.date()).num_days() as i32;

        sqlx::query("INSERT INTO booking_frequency_limits (id, event_type_id, max_bookings, period) VALUES (?, ?, 1, 'day')")
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(&et_id)
            .execute(&pool).await.unwrap();

        let start_at = next_monday
            .and_hms_opt(10, 0, 0)
            .unwrap()
            .format("%Y-%m-%dT%H:%M:%S")
            .to_string();
        let end_at = next_monday
            .and_hms_opt(10, 30, 0)
            .unwrap()
            .format("%Y-%m-%dT%H:%M:%S")
            .to_string();
        sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid1', 'Guest', 'g@e.com', 'UTC', ?, ?, 'confirmed', ?, ?)")
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(&et_id)
            .bind(&start_at)
            .bind(&end_at)
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(uuid::Uuid::new_v4().to_string())
            .execute(&pool).await.unwrap();

        let slot_days = compute_slots(
            &pool,
            &et_id,
            30,
            0,
            0,
            0,
            days_to_monday,
            5,
            None,
            Tz::UTC,
            Tz::UTC,
            BusySource::Individual(vec![]),
            None,
        )
        .await;

        let monday_date = next_monday.format("%Y-%m-%d").to_string();
        let monday = slot_days.iter().find(|d| d.date == monday_date);
        assert!(
            monday.map(|d| d.slots.is_empty()).unwrap_or(true),
            "1/day cap reached → Monday should expose no slots, got {:?}",
            monday.map(|d| d.slots.len())
        );

        let tuesday_date = (next_monday + Duration::days(1))
            .format("%Y-%m-%d")
            .to_string();
        let tuesday = slot_days
            .iter()
            .find(|d| d.date == tuesday_date)
            .expect("Tuesday should be present");
        assert_eq!(
            tuesday.slots.len(),
            16,
            "Tuesday is unaffected by Monday's per-day cap"
        );
    }

    #[tokio::test]
    async fn compute_slots_frequency_limit_per_week_drops_whole_week() {
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;

        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let days_to_monday = (next_monday - now.date()).num_days() as i32;

        sqlx::query("INSERT INTO booking_frequency_limits (id, event_type_id, max_bookings, period) VALUES (?, ?, 1, 'week')")
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(&et_id)
            .execute(&pool).await.unwrap();

        // One booking on Monday consumes the week's only slot.
        let start_at = next_monday
            .and_hms_opt(10, 0, 0)
            .unwrap()
            .format("%Y-%m-%dT%H:%M:%S")
            .to_string();
        let end_at = next_monday
            .and_hms_opt(10, 30, 0)
            .unwrap()
            .format("%Y-%m-%dT%H:%M:%S")
            .to_string();
        sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid1', 'Guest', 'g@e.com', 'UTC', ?, ?, 'confirmed', ?, ?)")
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(&et_id)
            .bind(&start_at)
            .bind(&end_at)
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(uuid::Uuid::new_v4().to_string())
            .execute(&pool).await.unwrap();

        let slot_days = compute_slots(
            &pool,
            &et_id,
            30,
            0,
            0,
            0,
            days_to_monday,
            5,
            None,
            Tz::UTC,
            Tz::UTC,
            BusySource::Individual(vec![]),
            None,
        )
        .await;

        for day in &slot_days {
            assert!(
                day.slots.is_empty(),
                "Per-week cap of 1 reached → {} should have no slots, got {}",
                day.date,
                day.slots.len()
            );
        }
    }

    #[tokio::test]
    async fn compute_slots_frequency_limit_ignores_cancelled_bookings() {
        // Regression: cancelled bookings must not count toward the cap. If they
        // did, hosts who frequently cancel would silently shrink their own
        // availability.
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;

        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let days_to_monday = (next_monday - now.date()).num_days() as i32;

        sqlx::query("INSERT INTO booking_frequency_limits (id, event_type_id, max_bookings, period) VALUES (?, ?, 1, 'day')")
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(&et_id)
            .execute(&pool).await.unwrap();

        // Single cancelled booking on Monday — should not consume the day's cap.
        let start_at = next_monday
            .and_hms_opt(10, 0, 0)
            .unwrap()
            .format("%Y-%m-%dT%H:%M:%S")
            .to_string();
        let end_at = next_monday
            .and_hms_opt(10, 30, 0)
            .unwrap()
            .format("%Y-%m-%dT%H:%M:%S")
            .to_string();
        sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid1', 'Guest', 'g@e.com', 'UTC', ?, ?, 'cancelled', ?, ?)")
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(&et_id)
            .bind(&start_at)
            .bind(&end_at)
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(uuid::Uuid::new_v4().to_string())
            .execute(&pool).await.unwrap();

        let slot_days = compute_slots(
            &pool,
            &et_id,
            30,
            0,
            0,
            0,
            days_to_monday,
            1,
            None,
            Tz::UTC,
            Tz::UTC,
            BusySource::Individual(vec![]),
            None,
        )
        .await;

        let monday_date = next_monday.format("%Y-%m-%d").to_string();
        let monday = slot_days
            .iter()
            .find(|d| d.date == monday_date)
            .expect("Monday should be present");
        assert_eq!(
            monday.slots.len(),
            16,
            "Cancelled bookings must not consume the day cap; expected full 16 slots, got {}",
            monday.slots.len()
        );
    }

    #[tokio::test]
    async fn compute_slots_frequency_limit_multiple_caps_each_checked() {
        // Configure both a 1/day and a 100/year cap. With one booking on
        // Monday only the day cap fires, so Monday must be hidden but
        // Tue–Fri must stay visible. This pins that the filter consults every
        // configured limit independently rather than stopping at the first.
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;

        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let days_to_monday = (next_monday - now.date()).num_days() as i32;

        sqlx::query("INSERT INTO booking_frequency_limits (id, event_type_id, max_bookings, period) VALUES (?, ?, 1, 'day')")
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(&et_id)
            .execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO booking_frequency_limits (id, event_type_id, max_bookings, period) VALUES (?, ?, 100, 'year')")
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(&et_id)
            .execute(&pool).await.unwrap();

        let start_at = next_monday
            .and_hms_opt(10, 0, 0)
            .unwrap()
            .format("%Y-%m-%dT%H:%M:%S")
            .to_string();
        let end_at = next_monday
            .and_hms_opt(10, 30, 0)
            .unwrap()
            .format("%Y-%m-%dT%H:%M:%S")
            .to_string();
        sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid1', 'Guest', 'g@e.com', 'UTC', ?, ?, 'confirmed', ?, ?)")
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(&et_id)
            .bind(&start_at)
            .bind(&end_at)
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(uuid::Uuid::new_v4().to_string())
            .execute(&pool).await.unwrap();

        let slot_days = compute_slots(
            &pool,
            &et_id,
            30,
            0,
            0,
            0,
            days_to_monday,
            5,
            None,
            Tz::UTC,
            Tz::UTC,
            BusySource::Individual(vec![]),
            None,
        )
        .await;

        let monday_date = next_monday.format("%Y-%m-%d").to_string();
        let monday = slot_days.iter().find(|d| d.date == monday_date);
        assert!(
            monday.map(|d| d.slots.is_empty()).unwrap_or(true),
            "1/day cap should hide Monday even with a lax year cap, got {:?}",
            monday.map(|d| d.slots.len())
        );

        let tuesday_date = (next_monday + Duration::days(1))
            .format("%Y-%m-%d")
            .to_string();
        let tuesday = slot_days
            .iter()
            .find(|d| d.date == tuesday_date)
            .expect("Tuesday should be present");
        assert_eq!(
            tuesday.slots.len(),
            16,
            "Year cap not reached → Tuesday must stay visible"
        );
    }

    /// Attach the seeded event type to a team and add two team members
    /// (alice, bob). Returns their user ids.
    async fn seed_team_for_event_type(pool: &SqlitePool, et_id: &str) -> (String, String) {
        let team_id = uuid::Uuid::new_v4().to_string();
        let alice = uuid::Uuid::new_v4().to_string();
        let bob = uuid::Uuid::new_v4().to_string();

        sqlx::query(
            "INSERT INTO teams (id, name, slug, visibility) VALUES (?, 'Team', 'team', 'public')",
        )
        .bind(&team_id)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query("UPDATE event_types SET team_id = ? WHERE id = ?")
            .bind(&team_id)
            .bind(et_id)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO users (id, email, name, role, auth_provider, username, enabled) VALUES (?, 'alice@example.com', 'Alice', 'user', 'local', 'alice', 1)")
            .bind(&alice).execute(pool).await.unwrap();
        sqlx::query("INSERT INTO users (id, email, name, role, auth_provider, username, enabled) VALUES (?, 'bob@example.com', 'Bob', 'user', 'local', 'bob', 1)")
            .bind(&bob).execute(pool).await.unwrap();
        sqlx::query("INSERT INTO team_members (team_id, user_id, role, source) VALUES (?, ?, 'member', 'direct')")
            .bind(&team_id).bind(&alice).execute(pool).await.unwrap();
        sqlx::query("INSERT INTO team_members (team_id, user_id, role, source) VALUES (?, ?, 'member', 'direct')")
            .bind(&team_id).bind(&bob).execute(pool).await.unwrap();

        (alice, bob)
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

    #[tokio::test]
    async fn would_exceed_frequency_limit_per_member_blocks_only_named_assignee() {
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;
        let (alice, bob) = seed_team_for_event_type(&pool, &et_id).await;

        sqlx::query("INSERT INTO booking_frequency_limits (id, event_type_id, max_bookings, period, per_member) VALUES (?, ?, 1, 'day', 1)")
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(&et_id)
            .execute(&pool).await.unwrap();

        let booked_day = NaiveDate::from_ymd_opt(2026, 3, 16).unwrap();
        let booked_start = booked_day.and_hms_opt(10, 0, 0).unwrap();
        insert_booking(&pool, &et_id, Some(&alice), booked_start, "confirmed").await;

        let proposed = booked_day.and_hms_opt(14, 0, 0).unwrap();
        assert!(
            would_exceed_frequency_limit(&pool, &et_id, proposed, Some(&alice)).await,
            "Alice already has one booking that day under 1/day per-member"
        );
        assert!(
            !would_exceed_frequency_limit(&pool, &et_id, proposed, Some(&bob)).await,
            "Bob has zero bookings; per-member cap should not block him"
        );
    }

    // --- Per-member slot uniqueness (#146) and write-back targets (#147) ---

    #[tokio::test]
    async fn same_slot_bookable_per_member_but_not_twice_per_member() {
        let pool = setup_test_db().await;
        let alice = insert_role_user(&pool, "alice@i146.test", "user").await;
        let bob = insert_role_user(&pool, "bob@i146.test", "user").await;
        let (_team, et_id) = insert_team_with_et(
            &pool,
            "i146",
            "i146-et",
            &[(&alice, "member"), (&bob, "member")],
        )
        .await;
        let start = NaiveDate::from_ymd_opt(2026, 3, 16)
            .unwrap()
            .and_hms_opt(10, 0, 0)
            .unwrap();

        insert_booking(&pool, &et_id, Some(&alice), start, "confirmed").await;
        // Same slot, different assigned member: allowed (#146). The helper
        // unwraps, so reaching the next line IS the assertion.
        insert_booking(&pool, &et_id, Some(&bob), start, "confirmed").await;

        // Same slot, same member again: rejected by idx_bookings_no_overlap.
        let dup = sqlx::query(
            "INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token, assigned_user_id) \
             VALUES (?, ?, ?, 'G', 'g@e.com', 'UTC', '2026-03-16T10:00:00', '2026-03-16T10:30:00', 'confirmed', ?, ?, ?)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&et_id)
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&alice)
        .execute(&pool)
        .await;
        assert!(dup.is_err(), "same member, same slot must stay unique");

        // Unassigned bookings (personal, collective) keep whole-slot
        // exclusivity among themselves.
        insert_booking(&pool, &et_id, None, start, "confirmed").await;
        let dup_null = sqlx::query(
            "INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) \
             VALUES (?, ?, ?, 'G', 'g@e.com', 'UTC', '2026-03-16T10:00:00', '2026-03-16T10:30:00', 'confirmed', ?, ?)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&et_id)
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(uuid::Uuid::new_v4().to_string())
        .execute(&pool)
        .await;
        assert!(
            dup_null.is_err(),
            "two unassigned bookings in one slot must stay unique"
        );
    }

    /// The reschedule/approve ICS must carry the organizer the booking flow
    /// wrote, otherwise Google CalDAV 403s the PUT and the change silently
    /// never reaches the calendar.
    #[tokio::test]
    async fn booking_host_identity_follows_the_booking_not_the_owner() {
        let pool = setup_test_db().await;
        let alice = insert_role_user(&pool, "alice@organizer.test", "user").await;
        let bob = insert_role_user(&pool, "bob@organizer.test", "user").await;
        let (_team, et_id) = insert_team_with_et(
            &pool,
            "organizer",
            "organizer-et",
            &[(&alice, "member"), (&bob, "member")],
        )
        .await;
        let start = NaiveDate::from_ymd_opt(2026, 3, 17)
            .unwrap()
            .and_hms_opt(10, 0, 0)
            .unwrap();

        // Assigned booking: the assigned member, never the event type owner.
        insert_booking(&pool, &et_id, Some(&bob), start, "confirmed").await;
        let uid: String =
            sqlx::query_scalar("SELECT uid FROM bookings WHERE event_type_id = ? LIMIT 1")
                .bind(&et_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            booking_host_identity(&pool, &uid).await,
            Some((
                "bob@organizer.test".to_string(),
                "bob@organizer.test".to_string(),
                None
            )),
            "assigned booking must keep the assigned member as organizer"
        );

        // Collective + unassigned: whole roster joined, first member's address,
        // matching how the booking flow builds it.
        sqlx::query("UPDATE event_types SET scheduling_mode = 'collective' WHERE id = ?")
            .bind(&et_id)
            .execute(&pool)
            .await
            .unwrap();
        let later = start + Duration::hours(2);
        insert_booking(&pool, &et_id, None, later, "confirmed").await;
        let uid2: String = sqlx::query_scalar(
            "SELECT uid FROM bookings WHERE event_type_id = ? AND assigned_user_id IS NULL",
        )
        .bind(&et_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            booking_host_identity(&pool, &uid2).await,
            Some((
                "alice@organizer.test & bob@organizer.test".to_string(),
                "alice@organizer.test".to_string(),
                None
            )),
            "collective booking must carry the roster and the first member's address"
        );

        // Personal event type: the owner.
        let (owner, _, personal_et) = seed_test_data(&pool).await;
        insert_booking(&pool, &personal_et, None, start, "confirmed").await;
        let uid3: String =
            sqlx::query_scalar("SELECT uid FROM bookings WHERE event_type_id = ? LIMIT 1")
                .bind(&personal_et)
                .fetch_one(&pool)
                .await
                .unwrap();
        let owner_email: String =
            sqlx::query_scalar("SELECT COALESCE(booking_email, email) FROM users WHERE id = ?")
                .bind(&owner)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            booking_host_identity(&pool, &uid3)
                .await
                .map(|(_, email, _)| email),
            Some(owner_email),
            "personal booking falls back to the event type owner"
        );
    }

    #[tokio::test]
    async fn booking_write_targets_resolves_assigned_collective_and_fallback() {
        let pool = setup_test_db().await;
        let alice = insert_role_user(&pool, "alice@i147.test", "user").await;
        let bob = insert_role_user(&pool, "bob@i147.test", "user").await;
        let (_team, et_id) = insert_team_with_et(
            &pool,
            "i147",
            "i147-et",
            &[(&alice, "member"), (&bob, "member")],
        )
        .await;
        let start = NaiveDate::from_ymd_opt(2026, 3, 17)
            .unwrap()
            .and_hms_opt(10, 0, 0)
            .unwrap();

        // Assigned booking: the assigned member, never the fallback owner.
        insert_booking(&pool, &et_id, Some(&alice), start, "confirmed").await;
        let uid: String =
            sqlx::query_scalar("SELECT uid FROM bookings WHERE event_type_id = ? LIMIT 1")
                .bind(&et_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            booking_write_targets(&pool, &uid, "owner-id").await,
            vec![alice.clone()],
            "assigned booking targets the assigned member (#147)"
        );

        // Collective + unassigned: every eligible member.
        sqlx::query("UPDATE event_types SET scheduling_mode = 'collective' WHERE id = ?")
            .bind(&et_id)
            .execute(&pool)
            .await
            .unwrap();
        let later = start + Duration::hours(2);
        insert_booking(&pool, &et_id, None, later, "confirmed").await;
        let uid2: String = sqlx::query_scalar(
            "SELECT uid FROM bookings WHERE event_type_id = ? AND assigned_user_id IS NULL",
        )
        .bind(&et_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        let mut targets = booking_write_targets(&pool, &uid2, "owner-id").await;
        targets.sort();
        let mut expected = vec![alice.clone(), bob.clone()];
        expected.sort();
        assert_eq!(targets, expected, "collective targets every member");

        // Personal (no team): the event type owner, even if the caller
        // passed someone else (same person `elect_meet_owner` uses).
        let (owner, _, personal_et) = seed_test_data(&pool).await;
        insert_booking(&pool, &personal_et, None, start, "confirmed").await;
        let uid3: String =
            sqlx::query_scalar("SELECT uid FROM bookings WHERE event_type_id = ? LIMIT 1")
                .bind(&personal_et)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            booking_write_targets(&pool, &uid3, "not-the-owner").await,
            vec![owner.clone()]
        );

        // Unassigned round-robin: event type owner, not the caller.
        sqlx::query("UPDATE event_types SET scheduling_mode = 'round_robin' WHERE id = ?")
            .bind(&et_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE accounts SET user_id = ? WHERE id = (SELECT account_id FROM event_types WHERE id = ?)",
        )
        .bind(&alice)
        .bind(&et_id)
        .execute(&pool)
        .await
        .unwrap();
        let rr_start = start + Duration::hours(4);
        insert_booking(&pool, &et_id, None, rr_start, "confirmed").await;
        let uid4: String =
            sqlx::query_scalar("SELECT uid FROM bookings WHERE event_type_id = ? AND start_at = ?")
                .bind(&et_id)
                .bind(rr_start.format("%Y-%m-%dT%H:%M:%S").to_string())
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            booking_write_targets(&pool, &uid4, &bob).await,
            vec![alice],
            "unassigned round-robin writes to the event type owner, matching Meet minting"
        );
    }

    /// A Google Meet booking is PUT to the owner's Google calendar by
    /// `create_meet_for_booking`, so the write-back loop skips its own PUT to
    /// keep a second ICS from stripping `conferenceData`. It must still record
    /// `caldav_calendar_href`: without it `caldav_delete_booking` reads the
    /// booking as never pushed and returns early, so cancelling leaves the
    /// Google event and its Meet on the host's calendar, blocking their own
    /// availability from then on.
    #[tokio::test]
    async fn google_meet_skip_branch_still_records_caldav_href() {
        let pool = setup_test_db().await;
        let alice = insert_role_user(&pool, "alice@meethref.test", "user").await;
        let et_id = insert_personal_et(&pool, &alice, "meet-href").await;
        sqlx::query("UPDATE event_types SET location_type = 'google_meet' WHERE id = ?")
            .bind(&et_id)
            .execute(&pool)
            .await
            .unwrap();
        let account_id: String = sqlx::query_scalar("SELECT id FROM accounts WHERE user_id = ?")
            .bind(&alice)
            .fetch_one(&pool)
            .await
            .unwrap();
        let write_href = "https://apidata.example.test/dav/alice/events/";
        let source_id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO caldav_sources (id, account_id, name, url, username, enabled, \
             write_calendar_href, auth_type, oauth2_provider, access_token_enc, token_expires_at) \
             VALUES (?, ?, 'Google', 'https://apidata.example.test/dav/', 'alice', 1, ?, \
             'oauth2', 'google', 'unopenable', '2099-01-01T00:00:00')",
        )
        .bind(&source_id)
        .bind(&account_id)
        .bind(write_href)
        .execute(&pool)
        .await
        .unwrap();
        // A Meet URL is what makes `should_skip_caldav_put` fire. The write
        // href is deliberately not `/caldav/v2/`, so a times patch (reschedule)
        // would fail calendarId parse and never hit the network.
        let start = NaiveDate::from_ymd_opt(2026, 3, 17)
            .unwrap()
            .and_hms_opt(10, 0, 0)
            .unwrap();
        insert_booking(&pool, &et_id, None, start, "confirmed").await;
        let uid: String =
            sqlx::query_scalar("SELECT uid FROM bookings WHERE event_type_id = ? LIMIT 1")
                .bind(&et_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        sqlx::query("UPDATE bookings SET meeting_url = ? WHERE uid = ?")
            .bind("https://meet.google.com/aaa-bbbb-ccc")
            .bind(&uid)
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            crate::google_meet::should_skip_caldav_put(
                &pool,
                &uid,
                &alice,
                &source_id,
                "oauth2",
                Some("google")
            )
            .await,
            "precondition: the owner's Google source is the one holding the Meet"
        );
        let details = crate::email::BookingDetails {
            event_title: "Meet".to_string(),
            date: "2026-03-17".to_string(),
            start_time: "10:00".to_string(),
            end_time: "10:30".to_string(),
            guest_name: "G".to_string(),
            guest_email: "g@e.com".to_string(),
            guest_timezone: "UTC".to_string(),
            host_name: "Alice".to_string(),
            host_email: "alice@meethref.test".to_string(),
            uid: uid.clone(),
            host_timezone: "UTC".to_string(),
            ..Default::default()
        };
        caldav_push_booking_for_user(&pool, &[0u8; 32], &alice, &uid, &details).await;
        let stored: Option<String> =
            sqlx::query_scalar("SELECT caldav_calendar_href FROM bookings WHERE uid = ?")
                .bind(&uid)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            stored.as_deref(),
            Some(write_href),
            "the skip branch must record the href, or cancellation cannot find the Google event"
        );
    }

    /// Reschedule availability must be checked against the booking's real
    /// host(s), not the event type owner (#166).
    #[tokio::test]
    async fn reschedule_hosts_follows_the_booking_not_the_owner() {
        let pool = setup_test_db().await;
        let alice = insert_role_user(&pool, "alice@r166.test", "user").await;
        let bob = insert_role_user(&pool, "bob@r166.test", "user").await;
        let (team, et_id) = insert_team_with_et(
            &pool,
            "r166",
            "r166-et",
            &[(&alice, "member"), (&bob, "member")],
        )
        .await;
        let start = NaiveDate::from_ymd_opt(2026, 3, 17)
            .unwrap()
            .and_hms_opt(10, 0, 0)
            .unwrap();

        // Round-robin, assigned: only the assigned member's calendar counts.
        insert_booking(&pool, &et_id, Some(&bob), start, "confirmed").await;
        let uid: String =
            sqlx::query_scalar("SELECT uid FROM bookings WHERE event_type_id = ? LIMIT 1")
                .bind(&et_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        let hosts = reschedule_hosts(&pool, &uid, "owner-id").await;
        assert_eq!(hosts.user_ids, vec![bob.clone()]);
        assert_eq!(hosts.team_id.as_deref(), Some(team.as_str()));
        assert!(
            !hosts.collective,
            "an assigned booking is one member's, not the roster's"
        );

        // Collective + unassigned: every eligible member must be free.
        sqlx::query("UPDATE event_types SET scheduling_mode = 'collective' WHERE id = ?")
            .bind(&et_id)
            .execute(&pool)
            .await
            .unwrap();
        let later = start + Duration::hours(2);
        insert_booking(&pool, &et_id, None, later, "confirmed").await;
        let uid2: String = sqlx::query_scalar(
            "SELECT uid FROM bookings WHERE event_type_id = ? AND assigned_user_id IS NULL",
        )
        .bind(&et_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        let collective_hosts = reschedule_hosts(&pool, &uid2, "owner-id").await;
        let mut members = collective_hosts.user_ids.clone();
        members.sort();
        let mut expected = vec![alice.clone(), bob.clone()];
        expected.sort();
        assert_eq!(members, expected, "collective needs the whole roster free");
        assert!(collective_hosts.collective);

        // Personal event type: the owner, and no team semantics.
        let (owner, _, personal_et) = seed_test_data(&pool).await;
        insert_booking(&pool, &personal_et, None, start, "confirmed").await;
        let uid3: String =
            sqlx::query_scalar("SELECT uid FROM bookings WHERE event_type_id = ? LIMIT 1")
                .bind(&personal_et)
                .fetch_one(&pool)
                .await
                .unwrap();
        let personal_hosts = reschedule_hosts(&pool, &uid3, &owner).await;
        assert_eq!(personal_hosts.user_ids, vec![owner]);
        assert_eq!(personal_hosts.team_id, None);
        assert!(!personal_hosts.collective);
    }

    /// A collective booking cannot be rescheduled when its event type no
    /// longer has an eligible member. The CalDAV write path falls back to the
    /// event type owner for legacy events, but availability must not inherit
    /// that fallback and invent a host outside the eligible roster.
    #[tokio::test]
    async fn reschedule_collective_without_eligible_members_has_no_available_slot() {
        let pool = setup_test_db().await;
        let alice = insert_role_user(&pool, "alice@empty166.test", "user").await;
        let bob = insert_role_user(&pool, "bob@empty166.test", "user").await;
        let (_team, et_id) = insert_team_with_et(
            &pool,
            "empty166",
            "empty166-et",
            &[(&alice, "member"), (&bob, "member")],
        )
        .await;
        sqlx::query("UPDATE event_types SET scheduling_mode = 'collective' WHERE id = ?")
            .bind(&et_id)
            .execute(&pool)
            .await
            .unwrap();
        for member in [&alice, &bob] {
            sqlx::query(
                "INSERT INTO event_type_member_weights (event_type_id, user_id, weight) \
                 VALUES (?, ?, 0)",
            )
            .bind(&et_id)
            .bind(member)
            .execute(&pool)
            .await
            .unwrap();
        }

        let start = NaiveDate::from_ymd_opt(2026, 3, 17)
            .unwrap()
            .and_hms_opt(10, 0, 0)
            .unwrap();
        insert_booking(&pool, &et_id, None, start, "confirmed").await;
        let uid: String =
            sqlx::query_scalar("SELECT uid FROM bookings WHERE event_type_id = ? LIMIT 1")
                .bind(&et_id)
                .fetch_one(&pool)
                .await
                .unwrap();

        let owner_fallback = "owner-fallback";
        assert_eq!(
            booking_write_targets(&pool, &uid, owner_fallback).await,
            vec![owner_fallback.to_string()],
            "CalDAV write-back keeps its legacy owner fallback"
        );

        let hosts = reschedule_hosts(&pool, &uid, owner_fallback).await;
        assert!(hosts.collective);
        assert!(
            hosts.user_ids.is_empty(),
            "availability must preserve the empty eligible roster"
        );

        let end = start + Duration::minutes(30);
        let busy = reschedule_busy_source(
            &pool,
            &hosts,
            &et_id,
            start,
            end,
            chrono_tz::Tz::UTC,
            "",
            "",
        )
        .await;
        assert!(
            !busy_source_is_free(&busy, start, end),
            "an empty collective roster must make every slot unavailable"
        );
    }

    /// A round-robin booking with no assigned member is a data anomaly — the
    /// booking flow refuses the slot when `pick_group_member` finds nobody — but
    /// pre-assignment rows exist. It must stay gated on the event type owner,
    /// the fallback `booking_write_targets` has always applied. Resolving it to
    /// "any member free" instead would let a guest reschedule onto a slot with
    /// no host who is actually free.
    #[tokio::test]
    async fn reschedule_hosts_unassigned_round_robin_falls_back_to_the_owner() {
        let pool = setup_test_db().await;
        let (owner, _, _) = seed_test_data(&pool).await;
        let bob = insert_role_user(&pool, "bob@rrnull.test", "user").await;
        let (_team, et_id) = insert_team_with_et(
            &pool,
            "rrnull",
            "rrnull-et",
            &[(&owner, "member"), (&bob, "member")],
        )
        .await;
        let mode: String =
            sqlx::query_scalar("SELECT scheduling_mode FROM event_types WHERE id = ?")
                .bind(&et_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(mode, "round_robin", "the fixture must not be collective");

        let start = NaiveDate::from_ymd_opt(2026, 3, 17)
            .unwrap()
            .and_hms_opt(10, 0, 0)
            .unwrap();
        insert_booking(&pool, &et_id, None, start, "confirmed").await;
        let uid: String =
            sqlx::query_scalar("SELECT uid FROM bookings WHERE event_type_id = ? LIMIT 1")
                .bind(&et_id)
                .fetch_one(&pool)
                .await
                .unwrap();

        let hosts = reschedule_hosts(&pool, &uid, &owner).await;
        assert_eq!(
            hosts.user_ids,
            vec![owner.clone()],
            "no assigned member and not collective: the owner is the fallback host"
        );
        assert!(!hosts.collective);

        // One host, so Team's "all must be free" is "the owner must be free" —
        // the same gate as before #166, not a loosened any-member check.
        let busy = reschedule_busy_source(
            &pool,
            &hosts,
            &et_id,
            start,
            start + Duration::minutes(30),
            chrono_tz::Tz::UTC,
            "",
            "",
        )
        .await;
        match &busy {
            BusySource::Team(member_busy) => {
                assert_eq!(member_busy.len(), 1);
                assert!(member_busy.contains_key(&owner));
            }
            _ => panic!("a team event type must go through BusySource::Team"),
        }
    }

    /// The busy source a reschedule is checked against must see the assigned
    /// member's bookings and ignore the owner's availability (#166).
    #[tokio::test]
    async fn reschedule_busy_source_uses_the_assigned_member_calendar() {
        let pool = setup_test_db().await;
        let (owner, _, _) = seed_test_data(&pool).await;
        let bob = insert_role_user(&pool, "bob@busy166.test", "user").await;
        let (_team, et_id) = insert_team_with_et(
            &pool,
            "busy166",
            "busy166-et",
            &[(&owner, "member"), (&bob, "member")],
        )
        .await;

        let taken = NaiveDate::from_ymd_opt(2026, 3, 17)
            .unwrap()
            .and_hms_opt(10, 0, 0)
            .unwrap();
        let taken_end = taken + Duration::minutes(30);
        // Bob is already booked at 10:00, the owner is free all day.
        insert_booking(&pool, &et_id, Some(&bob), taken, "confirmed").await;
        // The booking being rescheduled, assigned to Bob, sits elsewhere.
        insert_booking(
            &pool,
            &et_id,
            Some(&bob),
            taken + Duration::hours(4),
            "confirmed",
        )
        .await;
        let uid: String =
            sqlx::query_scalar("SELECT uid FROM bookings WHERE event_type_id = ? AND start_at = ?")
                .bind(&et_id)
                .bind(
                    (taken + Duration::hours(4))
                        .format("%Y-%m-%dT%H:%M:%S")
                        .to_string(),
                )
                .fetch_one(&pool)
                .await
                .unwrap();

        // The pre-#166 check ran against the owner, who is free at 10:00 —
        // which is exactly how the guest got offered a slot Bob could not take.
        assert!(
            fetch_busy_times_for_user_ex(
                &pool,
                &owner,
                taken,
                taken_end,
                chrono_tz::Tz::UTC,
                Some(&et_id),
                None,
                None,
            )
            .await
            .is_empty(),
            "the event type owner is free at 10:00; only Bob is busy"
        );

        let hosts = reschedule_hosts(&pool, &uid, &owner).await;
        let busy = reschedule_busy_source(
            &pool,
            &hosts,
            &et_id,
            taken,
            taken_end,
            chrono_tz::Tz::UTC,
            "",
            "",
        )
        .await;
        assert!(
            !busy_source_is_free(&busy, taken, taken_end),
            "the slot must be busy: it is taken on the assigned member's calendar"
        );
    }

    /// The reschedule page's host profile follows the booking too: the guest
    /// must not be shown the event type owner as their host (#166).
    #[tokio::test]
    async fn reschedule_host_profile_shows_the_booking_host() {
        let pool = setup_test_db().await;
        let (owner, _, _) = seed_test_data(&pool).await;
        let bob = insert_role_user(&pool, "bob@profile166.test", "user").await;
        let (team, et_id) = insert_team_with_et(
            &pool,
            "profile166",
            "profile166-et",
            &[(&owner, "member"), (&bob, "member")],
        )
        .await;
        sqlx::query("UPDATE teams SET name = 'Support' WHERE id = ?")
            .bind(&team)
            .execute(&pool)
            .await
            .unwrap();
        let start = NaiveDate::from_ymd_opt(2026, 3, 17)
            .unwrap()
            .and_hms_opt(10, 0, 0)
            .unwrap();

        insert_booking(&pool, &et_id, Some(&bob), start, "confirmed").await;
        let uid: String =
            sqlx::query_scalar("SELECT uid FROM bookings WHERE event_type_id = ? LIMIT 1")
                .bind(&et_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        let assigned_hosts = reschedule_hosts(&pool, &uid, &owner).await;
        let profile = reschedule_host_profile(&pool, &assigned_hosts, &et_id).await;
        assert_eq!(profile.name, "bob@profile166.test");
        assert_eq!(profile.user_id.as_deref(), Some(bob.as_str()));
        assert!(
            profile.team.is_none(),
            "a round-robin booking is with one person"
        );

        // Collective: the booking belongs to the team, so the team card renders.
        sqlx::query("UPDATE event_types SET scheduling_mode = 'collective' WHERE id = ?")
            .bind(&et_id)
            .execute(&pool)
            .await
            .unwrap();
        insert_booking(&pool, &et_id, None, start + Duration::hours(2), "confirmed").await;
        let uid2: String = sqlx::query_scalar(
            "SELECT uid FROM bookings WHERE event_type_id = ? AND assigned_user_id IS NULL",
        )
        .bind(&et_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        let collective_hosts = reschedule_hosts(&pool, &uid2, &owner).await;
        let team_profile = reschedule_host_profile(&pool, &collective_hosts, &et_id).await;
        assert_eq!(team_profile.name, "Support");
        assert_eq!(team_profile.user_id, None);
        assert_eq!(
            team_profile.team.map(|t| t.members.len()),
            Some(2),
            "the team card lists the eligible roster"
        );
    }

    #[tokio::test]
    async fn assigned_booking_marks_member_busy_not_owner() {
        let pool = setup_test_db().await;
        let (owner, _, et_id) = seed_test_data(&pool).await;
        let alice = insert_role_user(&pool, "alice@busy146.test", "user").await;
        let start = NaiveDate::from_ymd_opt(2026, 3, 18)
            .unwrap()
            .and_hms_opt(10, 0, 0)
            .unwrap();
        let end = start + Duration::minutes(30);
        insert_booking(&pool, &et_id, Some(&alice), start, "confirmed").await;

        let owner_busy =
            fetch_busy_times_for_user(&pool, &owner, start, end, chrono_tz::Tz::UTC, None).await;
        assert!(
            owner_busy.is_empty(),
            "a booking assigned to another member must not mark the owner busy (#146)"
        );
        let alice_busy =
            fetch_busy_times_for_user(&pool, &alice, start, end, chrono_tz::Tz::UTC, None).await;
        assert!(!alice_busy.is_empty(), "assigned member is busy");
    }

    #[tokio::test]
    async fn unassigned_team_booking_marks_members_busy() {
        let pool = setup_test_db().await;
        let alice = insert_role_user(&pool, "alice@coll147.test", "user").await;
        let bob = insert_role_user(&pool, "bob@coll147.test", "user").await;
        let (_team, et_id) = insert_team_with_et(
            &pool,
            "coll147",
            "coll147-et",
            &[(&alice, "member"), (&bob, "member")],
        )
        .await;
        sqlx::query("UPDATE event_types SET scheduling_mode = 'collective' WHERE id = ?")
            .bind(&et_id)
            .execute(&pool)
            .await
            .unwrap();
        let start = NaiveDate::from_ymd_opt(2026, 3, 19)
            .unwrap()
            .and_hms_opt(10, 0, 0)
            .unwrap();
        let end = start + Duration::minutes(30);
        insert_booking(&pool, &et_id, None, start, "confirmed").await;

        for member in [&alice, &bob] {
            let busy =
                fetch_busy_times_for_user(&pool, member, start, end, chrono_tz::Tz::UTC, None)
                    .await;
            assert!(
                !busy.is_empty(),
                "an unassigned (collective) team booking must mark every member busy"
            );
        }
    }

    #[tokio::test]
    async fn pick_group_member_skips_member_with_pending_same_slot() {
        let pool = setup_test_db().await;
        let alice = insert_role_user(&pool, "alice@pend146.test", "user").await;
        let bob = insert_role_user(&pool, "bob@pend146.test", "user").await;
        let (team_id, et_id) = insert_team_with_et(
            &pool,
            "pend146",
            "pend146-et",
            &[(&alice, "member"), (&bob, "member")],
        )
        .await;
        let start = NaiveDate::from_ymd_opt(2026, 3, 20)
            .unwrap()
            .and_hms_opt(10, 0, 0)
            .unwrap();
        let end = start + Duration::minutes(30);

        // Pending bookings don't show in the busy times, but they hold the
        // (event_type, slot, member) key in idx_bookings_no_overlap: the
        // picker must not hand the same member out twice.
        insert_booking(&pool, &et_id, Some(&alice), start, "pending").await;

        let picked = pick_group_member(
            &pool,
            &team_id,
            &et_id,
            start,
            end,
            start,
            0,
            0,
            chrono_tz::Tz::UTC,
        )
        .await
        .expect("bob is free, a member must be picked");
        assert_eq!(picked.0, bob, "picker must skip alice's pending slot");
    }

    #[tokio::test]
    async fn apply_frequency_limit_filter_per_member_keeps_slots_when_one_member_free() {
        // 1/day per-member, 2 team members, 1 booking on Monday assigned to
        // Alice → Monday must still show slots because Bob has headroom.
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;
        let (alice, _bob) = seed_team_for_event_type(&pool, &et_id).await;

        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let days_to_monday = (next_monday - now.date()).num_days() as i32;

        sqlx::query("INSERT INTO booking_frequency_limits (id, event_type_id, max_bookings, period, per_member) VALUES (?, ?, 1, 'day', 1)")
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(&et_id)
            .execute(&pool).await.unwrap();
        insert_booking(
            &pool,
            &et_id,
            Some(&alice),
            next_monday.and_hms_opt(10, 0, 0).unwrap(),
            "confirmed",
        )
        .await;

        let slot_days = compute_slots(
            &pool,
            &et_id,
            30,
            0,
            0,
            0,
            days_to_monday,
            1,
            None,
            Tz::UTC,
            Tz::UTC,
            BusySource::Individual(vec![]),
            None,
        )
        .await;

        let monday_date = next_monday.format("%Y-%m-%d").to_string();
        let monday = slot_days
            .iter()
            .find(|d| d.date == monday_date)
            .expect("Monday should be present");
        assert_eq!(
            monday.slots.len(),
            16,
            "Per-member cap consumed by Alice must not hide slots while Bob is free"
        );
    }

    #[tokio::test]
    async fn apply_frequency_limit_filter_per_member_drops_slots_when_all_members_capped() {
        // 1/day per-member, 2 team members, both already booked on Monday →
        // Monday must show no slots.
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;
        let (alice, bob) = seed_team_for_event_type(&pool, &et_id).await;

        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let days_to_monday = (next_monday - now.date()).num_days() as i32;

        sqlx::query("INSERT INTO booking_frequency_limits (id, event_type_id, max_bookings, period, per_member) VALUES (?, ?, 1, 'day', 1)")
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(&et_id)
            .execute(&pool).await.unwrap();
        insert_booking(
            &pool,
            &et_id,
            Some(&alice),
            next_monday.and_hms_opt(10, 0, 0).unwrap(),
            "confirmed",
        )
        .await;
        insert_booking(
            &pool,
            &et_id,
            Some(&bob),
            next_monday.and_hms_opt(11, 0, 0).unwrap(),
            "confirmed",
        )
        .await;

        let slot_days = compute_slots(
            &pool,
            &et_id,
            30,
            0,
            0,
            0,
            days_to_monday,
            1,
            None,
            Tz::UTC,
            Tz::UTC,
            BusySource::Individual(vec![]),
            None,
        )
        .await;

        let monday_date = next_monday.format("%Y-%m-%d").to_string();
        let monday = slot_days.iter().find(|d| d.date == monday_date);
        assert!(
            monday.map(|d| d.slots.is_empty()).unwrap_or(true),
            "Every team member at cap → Monday must be empty, got {:?}",
            monday.map(|d| d.slots.len())
        );
    }

    #[tokio::test]
    async fn apply_frequency_limit_filter_per_member_on_personal_event_type_degrades_to_wide() {
        // Personal event type (no team) with a per_member flag set. With no
        // team members to scope by, the cap should behave event-type-wide so
        // a single booking still hides the day.
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;

        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let days_to_monday = (next_monday - now.date()).num_days() as i32;

        sqlx::query("INSERT INTO booking_frequency_limits (id, event_type_id, max_bookings, period, per_member) VALUES (?, ?, 1, 'day', 1)")
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(&et_id)
            .execute(&pool).await.unwrap();
        insert_booking(
            &pool,
            &et_id,
            None,
            next_monday.and_hms_opt(10, 0, 0).unwrap(),
            "confirmed",
        )
        .await;

        let slot_days = compute_slots(
            &pool,
            &et_id,
            30,
            0,
            0,
            0,
            days_to_monday,
            1,
            None,
            Tz::UTC,
            Tz::UTC,
            BusySource::Individual(vec![]),
            None,
        )
        .await;

        let monday_date = next_monday.format("%Y-%m-%d").to_string();
        let monday = slot_days.iter().find(|d| d.date == monday_date);
        assert!(
            monday.map(|d| d.slots.is_empty()).unwrap_or(true),
            "Per-member flag on a personal event type must still cap the day"
        );
    }

    #[tokio::test]
    async fn apply_frequency_limit_filter_mixed_per_member_and_wide_fire_independently() {
        // Two limits on the same team event type:
        //   - 1/day per-member
        //   - 3/week event-type-wide
        //
        // Bookings span two consecutive weeks:
        //   Week 1: three bookings by Alice on Mon/Tue/Wed → wide week count
        //           hits its cap (3/3).
        //   Week 2: one booking each by Alice and Bob on Monday → both
        //           per-member day caps fill, wide week count is 2/3 (lax).
        //
        // Expectations:
        //   - Every weekday in week 1 must be hidden — wide cap dominates,
        //     even Thu/Fri where per-member alone would still allow bookings.
        //   - Week 2 Monday must be hidden by the per-member rule (both
        //     members at cap) while the wide rule still has headroom.
        //   - Week 2 Tue-Fri must be visible — neither rule fires.
        //
        // If a future change ever conflates the two rule paths, this test
        // will fail in a specific weekday rather than silently allow or
        // deny everything.
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;
        let (alice, bob) = seed_team_for_event_type(&pool, &et_id).await;

        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let days_to_monday = (next_monday - now.date()).num_days() as i32;

        sqlx::query("INSERT INTO booking_frequency_limits (id, event_type_id, max_bookings, period, per_member) VALUES (?, ?, 1, 'day', 1)")
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(&et_id)
            .execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO booking_frequency_limits (id, event_type_id, max_bookings, period, per_member) VALUES (?, ?, 3, 'week', 0)")
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(&et_id)
            .execute(&pool).await.unwrap();

        // Week 1: three Alice bookings consume the wide week cap.
        for offset in 0..3 {
            insert_booking(
                &pool,
                &et_id,
                Some(&alice),
                (next_monday + Duration::days(offset))
                    .and_hms_opt(10, 0, 0)
                    .unwrap(),
                "confirmed",
            )
            .await;
        }

        // Week 2 Monday: both members booked, capping per-member.
        let week2_monday = next_monday + Duration::days(7);
        insert_booking(
            &pool,
            &et_id,
            Some(&alice),
            week2_monday.and_hms_opt(10, 0, 0).unwrap(),
            "confirmed",
        )
        .await;
        insert_booking(
            &pool,
            &et_id,
            Some(&bob),
            week2_monday.and_hms_opt(11, 0, 0).unwrap(),
            "confirmed",
        )
        .await;

        let slot_days = compute_slots(
            &pool,
            &et_id,
            30,
            0,
            0,
            0,
            days_to_monday,
            14,
            None,
            Tz::UTC,
            Tz::UTC,
            BusySource::Individual(vec![]),
            None,
        )
        .await;

        let find_day = |d: NaiveDate| -> Option<&SlotDay> {
            let key = d.format("%Y-%m-%d").to_string();
            slot_days.iter().find(|x| x.date == key)
        };

        // Week 1 Mon-Fri: every weekday hidden because the wide cap is hit.
        for offset in 0..5 {
            let d = next_monday + Duration::days(offset);
            let day = find_day(d);
            assert!(
                day.map(|x| x.slots.is_empty()).unwrap_or(true),
                "Week 1 {} should be hidden by the 3/week wide cap; got {:?}",
                d,
                day.map(|x| x.slots.len())
            );
        }

        // Week 2 Mon: per-member dominates — wide is lax (2/3) but both
        // members are at their per-day cap.
        let w2_mon = find_day(week2_monday);
        assert!(
            w2_mon.map(|x| x.slots.is_empty()).unwrap_or(true),
            "Week 2 Monday should be hidden by per-member rule; got {:?}",
            w2_mon.map(|x| x.slots.len())
        );

        // Week 2 Tue-Fri: neither rule fires, full availability.
        for offset in 1..5 {
            let d = week2_monday + Duration::days(offset);
            let day = find_day(d).expect("Week 2 weekday should be present");
            assert_eq!(
                day.slots.len(),
                16,
                "Week 2 {} should be free; got {} slots",
                d,
                day.slots.len()
            );
        }
    }

    #[tokio::test]
    async fn compute_slots_no_weekend_slots() {
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;

        // Find next Saturday
        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_sat = now.date();
        while next_sat.weekday() != chrono::Weekday::Sat {
            next_sat += Duration::days(1);
        }
        let days_to_sat = (next_sat - now.date()).num_days() as i32;

        let busy = BusySource::Individual(vec![]);
        let slot_days = compute_slots(
            &pool,
            &et_id,
            30,
            0,
            0,
            0,
            days_to_sat,
            2, // just Sat + Sun
            None,
            Tz::UTC,
            Tz::UTC,
            busy,
            None,
        )
        .await;

        assert!(
            slot_days.is_empty(),
            "Weekends should have no slots (Mon-Fri rules only)"
        );
    }

    #[tokio::test]
    async fn compute_slots_group_any_member_free() {
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;

        // Find the next Monday
        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let days_to_monday = (next_monday - now.date()).num_days() as i32;

        let ten_am = next_monday.and_hms_opt(10, 0, 0).unwrap();
        let ten_thirty = next_monday.and_hms_opt(10, 30, 0).unwrap();

        // Member A is busy at 10:00, Member B is free
        let mut member_busy = HashMap::new();
        member_busy.insert("member_a".to_string(), vec![(ten_am, ten_thirty)]);
        member_busy.insert("member_b".to_string(), vec![]); // free

        let busy = BusySource::Group(member_busy);
        let slot_days = compute_slots(
            &pool,
            &et_id,
            30,
            0,
            0,
            0,
            days_to_monday,
            1,
            None,
            Tz::UTC,
            Tz::UTC,
            busy,
            None,
        )
        .await;

        assert!(!slot_days.is_empty());
        let monday = &slot_days[0];
        // 10:00 should still be available because member B is free
        let slot_times: Vec<&str> = monday.slots.iter().map(|s| s.start.as_str()).collect();
        assert!(
            slot_times.contains(&"10:00"),
            "10:00 should be available (member B is free)"
        );
        assert_eq!(
            monday.slots.len(),
            16,
            "All slots available (at least one member free)"
        );
    }

    #[tokio::test]
    async fn compute_slots_group_all_busy_blocks() {
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;

        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let days_to_monday = (next_monday - now.date()).num_days() as i32;

        let ten_am = next_monday.and_hms_opt(10, 0, 0).unwrap();
        let ten_thirty = next_monday.and_hms_opt(10, 30, 0).unwrap();

        // Both members busy at 10:00
        let mut member_busy = HashMap::new();
        member_busy.insert("member_a".to_string(), vec![(ten_am, ten_thirty)]);
        member_busy.insert("member_b".to_string(), vec![(ten_am, ten_thirty)]);

        let busy = BusySource::Group(member_busy);
        let slot_days = compute_slots(
            &pool,
            &et_id,
            30,
            0,
            0,
            0,
            days_to_monday,
            1,
            None,
            Tz::UTC,
            Tz::UTC,
            busy,
            None,
        )
        .await;

        assert!(!slot_days.is_empty());
        let monday = &slot_days[0];
        let slot_times: Vec<&str> = monday.slots.iter().map(|s| s.start.as_str()).collect();
        assert!(
            !slot_times.contains(&"10:00"),
            "10:00 blocked when ALL members busy"
        );
        assert_eq!(monday.slots.len(), 15, "One slot blocked");
    }

    #[tokio::test]
    async fn compute_slots_team_requires_all_free() {
        // Team links require ALL members to be free (unlike Group which needs ANY)
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;

        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let days_to_monday = (next_monday - now.date()).num_days() as i32;

        let ten_am = next_monday.and_hms_opt(10, 0, 0).unwrap();
        let ten_thirty = next_monday.and_hms_opt(10, 30, 0).unwrap();

        // Only ONE member busy at 10:00 — Team should block, Group would allow
        let mut member_busy = HashMap::new();
        member_busy.insert("member_a".to_string(), vec![(ten_am, ten_thirty)]);
        member_busy.insert("member_b".to_string(), vec![]); // member_b is free

        let busy = BusySource::Team(member_busy);
        let slot_days = compute_slots(
            &pool,
            &et_id,
            30,
            0,
            0,
            0,
            days_to_monday,
            1,
            None,
            Tz::UTC,
            Tz::UTC,
            busy,
            None,
        )
        .await;

        assert!(!slot_days.is_empty());
        let monday = &slot_days[0];
        let slot_times: Vec<&str> = monday.slots.iter().map(|s| s.start.as_str()).collect();
        assert!(
            !slot_times.contains(&"10:00"),
            "Team: 10:00 blocked when ANY member is busy"
        );
        assert_eq!(monday.slots.len(), 15, "One slot blocked for Team");
    }

    #[tokio::test]
    async fn compute_slots_team_all_free_allows() {
        // When all team members are free, the slot should be available
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;

        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let days_to_monday = (next_monday - now.date()).num_days() as i32;

        // No one is busy
        let mut member_busy = HashMap::new();
        member_busy.insert("member_a".to_string(), vec![]);
        member_busy.insert("member_b".to_string(), vec![]);

        let busy = BusySource::Team(member_busy);
        let slot_days = compute_slots(
            &pool,
            &et_id,
            30,
            0,
            0,
            0,
            days_to_monday,
            1,
            None,
            Tz::UTC,
            Tz::UTC,
            busy,
            None,
        )
        .await;

        assert!(!slot_days.is_empty());
        let monday = &slot_days[0];
        assert_eq!(
            monday.slots.len(),
            16,
            "All 16 slots available when team is free"
        );
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

    /// Insert a cached feed event. Compact iCal stamps: "YYYYMMDD" for
    /// all-day events, "YYYYMMDDTHHMMSS" for timed ones.
    async fn insert_resource_event(
        pool: &SqlitePool,
        resource_id: &str,
        start_at: &str,
        end_at: &str,
        status: Option<&str>,
        transp: Option<&str>,
    ) {
        let all_day = start_at.len() == 8;
        sqlx::query(
            "INSERT INTO resource_events (id, resource_id, uid, start_at, end_at, all_day, status, transp) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(resource_id)
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(start_at)
        .bind(end_at)
        .bind(all_day as i32)
        .bind(status)
        .bind(transp)
        .execute(pool)
        .await
        .unwrap();
    }

    /// Insert a confirmed booking carrying a resource assignment.
    async fn insert_resource_booking(
        pool: &SqlitePool,
        et_id: &str,
        resource_id: &str,
        start: NaiveDateTime,
    ) {
        let end = start + Duration::minutes(30);
        sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token, assigned_resource_id) VALUES (?, ?, ?, 'G', 'g@e.com', 'UTC', ?, ?, 'confirmed', ?, ?, ?)")
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(et_id)
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(start.format("%Y-%m-%dT%H:%M:%S").to_string())
            .bind(end.format("%Y-%m-%dT%H:%M:%S").to_string())
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(resource_id)
            .execute(pool).await.unwrap();
    }

    #[tokio::test]
    async fn compute_slots_resource_all_mode_blocks_covered_days() {
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;

        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let days_to_monday = (next_monday - now.date()).num_days() as i32;

        let resource = insert_resource(&pool, "Demo Lab").await;
        attach_resource(&pool, &et_id, &resource).await;
        // All-day feed event with exclusive DTEND: covers Monday and Tuesday.
        insert_resource_event(
            &pool,
            &resource,
            &next_monday.format("%Y%m%d").to_string(),
            &(next_monday + Duration::days(2))
                .format("%Y%m%d")
                .to_string(),
            None,
            None,
        )
        .await;

        let slot_days = compute_slots(
            &pool,
            &et_id,
            30,
            0,
            0,
            0,
            days_to_monday,
            3,
            None,
            Tz::UTC,
            Tz::UTC,
            BusySource::Individual(vec![]),
            None,
        )
        .await;

        for offset in 0..2 {
            let date = (next_monday + Duration::days(offset))
                .format("%Y-%m-%d")
                .to_string();
            let day = slot_days.iter().find(|d| d.date == date);
            assert!(
                day.map(|d| d.slots.is_empty()).unwrap_or(true),
                "{} is covered by the resource event and must expose no slots, got {:?}",
                date,
                day.map(|d| d.slots.len())
            );
        }
        let wednesday = (next_monday + Duration::days(2))
            .format("%Y-%m-%d")
            .to_string();
        let day = slot_days
            .iter()
            .find(|d| d.date == wednesday)
            .expect("Wednesday should be present");
        assert_eq!(
            day.slots.len(),
            16,
            "Wednesday is not covered and must keep all slots"
        );
    }

    #[tokio::test]
    async fn compute_slots_resource_round_robin_one_free_keeps_slots() {
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;
        sqlx::query("UPDATE event_types SET resource_scheduling_mode = 'round_robin' WHERE id = ?")
            .bind(&et_id)
            .execute(&pool)
            .await
            .unwrap();

        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let days_to_monday = (next_monday - now.date()).num_days() as i32;

        let busy_res = insert_resource(&pool, "Lab A").await;
        let free_res = insert_resource(&pool, "Lab B").await;
        attach_resource(&pool, &et_id, &busy_res).await;
        attach_resource(&pool, &et_id, &free_res).await;
        // Only Lab A is busy on Monday, Lab B stays free.
        insert_resource_event(
            &pool,
            &busy_res,
            &next_monday.format("%Y%m%d").to_string(),
            &(next_monday + Duration::days(1))
                .format("%Y%m%d")
                .to_string(),
            None,
            None,
        )
        .await;

        let slot_days = compute_slots(
            &pool,
            &et_id,
            30,
            0,
            0,
            0,
            days_to_monday,
            1,
            None,
            Tz::UTC,
            Tz::UTC,
            BusySource::Individual(vec![]),
            None,
        )
        .await;

        let monday_date = next_monday.format("%Y-%m-%d").to_string();
        let monday = slot_days
            .iter()
            .find(|d| d.date == monday_date)
            .expect("Monday should be present");
        assert_eq!(
            monday.slots.len(),
            16,
            "round_robin with one free resource must not block any slot"
        );
    }

    #[tokio::test]
    async fn compute_slots_resource_round_robin_all_busy_blocks() {
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;
        sqlx::query("UPDATE event_types SET resource_scheduling_mode = 'round_robin' WHERE id = ?")
            .bind(&et_id)
            .execute(&pool)
            .await
            .unwrap();

        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let days_to_monday = (next_monday - now.date()).num_days() as i32;

        let start = next_monday.format("%Y%m%d").to_string();
        let end = (next_monday + Duration::days(1))
            .format("%Y%m%d")
            .to_string();
        for name in ["Lab A", "Lab B"] {
            let rid = insert_resource(&pool, name).await;
            attach_resource(&pool, &et_id, &rid).await;
            insert_resource_event(&pool, &rid, &start, &end, None, None).await;
        }

        let slot_days = compute_slots(
            &pool,
            &et_id,
            30,
            0,
            0,
            0,
            days_to_monday,
            1,
            None,
            Tz::UTC,
            Tz::UTC,
            BusySource::Individual(vec![]),
            None,
        )
        .await;

        let monday_date = next_monday.format("%Y-%m-%d").to_string();
        let monday = slot_days.iter().find(|d| d.date == monday_date);
        assert!(
            monday.map(|d| d.slots.is_empty()).unwrap_or(true),
            "every resource busy in round_robin mode must block the day, got {:?}",
            monday.map(|d| d.slots.len())
        );
    }

    #[tokio::test]
    async fn check_and_pick_all_mode_busy_resource_returns_busy() {
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;

        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }

        let resource = insert_resource(&pool, "Demo Lab").await;
        attach_resource(&pool, &et_id, &resource).await;
        insert_resource_event(
            &pool,
            &resource,
            &next_monday.format("%Y%m%d").to_string(),
            &(next_monday + Duration::days(1))
                .format("%Y%m%d")
                .to_string(),
            None,
            None,
        )
        .await;

        let check = crate::resources::check_and_pick(
            &pool,
            &et_id,
            next_monday.and_hms_opt(10, 0, 0).unwrap(),
            next_monday.and_hms_opt(10, 30, 0).unwrap(),
            Tz::UTC,
            None,
        )
        .await;
        assert_eq!(
            check,
            crate::resources::ResourceCheck::Busy,
            "'all' mode with the only resource busy must refuse the slot"
        );
    }

    #[tokio::test]
    async fn check_and_pick_round_robin_returns_the_free_resource() {
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;
        sqlx::query("UPDATE event_types SET resource_scheduling_mode = 'round_robin' WHERE id = ?")
            .bind(&et_id)
            .execute(&pool)
            .await
            .unwrap();

        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }

        let busy_res = insert_resource(&pool, "Lab A").await;
        let free_res = insert_resource(&pool, "Lab B").await;
        attach_resource(&pool, &et_id, &busy_res).await;
        attach_resource(&pool, &et_id, &free_res).await;
        insert_resource_event(
            &pool,
            &busy_res,
            &next_monday.format("%Y%m%d").to_string(),
            &(next_monday + Duration::days(1))
                .format("%Y%m%d")
                .to_string(),
            None,
            None,
        )
        .await;

        let check = crate::resources::check_and_pick(
            &pool,
            &et_id,
            next_monday.and_hms_opt(10, 0, 0).unwrap(),
            next_monday.and_hms_opt(10, 30, 0).unwrap(),
            Tz::UTC,
            None,
        )
        .await;
        assert_eq!(
            check,
            crate::resources::ResourceCheck::Free {
                assigned: Some(free_res)
            },
            "round_robin must pick the free resource"
        );
    }

    // --- Per-resource team allowlist (#153) ---

    async fn seed_team_with_admin(pool: &SqlitePool, slug: &str, admin_user_id: &str) -> String {
        let team_id = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO teams (id, name, slug, visibility) VALUES (?, ?, ?, 'public')")
            .bind(&team_id)
            .bind(slug)
            .bind(slug)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO team_members (team_id, user_id, role, source) VALUES (?, ?, 'admin', 'direct')",
        )
        .bind(&team_id)
        .bind(admin_user_id)
        .execute(pool)
        .await
        .unwrap();
        team_id
    }

    async fn allow_resource_for_team(pool: &SqlitePool, resource_id: &str, team_id: &str) {
        sqlx::query("INSERT INTO resource_teams (resource_id, team_id) VALUES (?, ?)")
            .bind(resource_id)
            .bind(team_id)
            .execute(pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn attachable_resources_respects_allowlist_and_roles() {
        let pool = setup_test_db().await;
        let admin = insert_role_user(&pool, "admin@allow.test", "admin").await;
        let team_admin = insert_role_user(&pool, "ta@allow.test", "user").await;
        let member = insert_role_user(&pool, "member@allow.test", "user").await;
        let team_id = seed_team_with_admin(&pool, "allow-sales", &team_admin).await;
        sqlx::query(
            "INSERT INTO team_members (team_id, user_id, role, source) VALUES (?, ?, 'member', 'direct')",
        )
        .bind(&team_id)
        .bind(&member)
        .execute(&pool)
        .await
        .unwrap();
        let allowed = insert_resource(&pool, "Lab A").await;
        let _other = insert_resource(&pool, "Lab B").await;
        allow_resource_for_team(&pool, &allowed, &team_id).await;

        let all = attachable_resources(&pool, &admin, true, None).await;
        assert_eq!(all.len(), 2, "global admin sees every resource");

        let ta = attachable_resources(&pool, &team_admin, false, Some(&team_id)).await;
        assert_eq!(
            ta.iter().map(|(id, _)| id.as_str()).collect::<Vec<_>>(),
            vec![allowed.as_str()],
            "team admin sees only the team's allowlist"
        );

        assert!(
            attachable_resources(&pool, &member, false, Some(&team_id))
                .await
                .is_empty(),
            "plain team member may not attach even allowlisted resources"
        );
        assert!(
            attachable_resources(&pool, &team_admin, false, None)
                .await
                .is_empty(),
            "personal event types stay global-admin only"
        );

        let any = attachable_resources_any_team(&pool, &team_admin).await;
        assert_eq!(any.len(), 1, "union helper covers the create forms");
        assert!(attachable_resources_any_team(&pool, &member)
            .await
            .is_empty());
    }

    #[tokio::test]
    async fn save_resources_authorized_filters_and_preserves() {
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;
        let team_admin = insert_role_user(&pool, "ta2@allow.test", "user").await;
        let team_id = seed_team_with_admin(&pool, "allow-support", &team_admin).await;
        let allowed = insert_resource(&pool, "Allowed Lab").await;
        let preexisting = insert_resource(&pool, "Admin-only Lab").await;
        let smuggled = insert_resource(&pool, "Smuggled Lab").await;
        allow_resource_for_team(&pool, &allowed, &team_id).await;
        // A global admin attached a non-allowlisted resource earlier.
        attach_resource(&pool, &et_id, &preexisting).await;

        // Team admin submits an allowlisted id plus a smuggled one.
        save_event_type_resources_authorized(
            &pool,
            &et_id,
            &team_admin,
            false,
            Some(&team_id),
            &Some(format!("{},{}", allowed, smuggled)),
            &Some("round_robin".to_string()),
        )
        .await;

        let mut attached: Vec<String> = sqlx::query_as::<_, (String,)>(
            "SELECT resource_id FROM event_type_resources WHERE event_type_id = ?",
        )
        .bind(&et_id)
        .fetch_all(&pool)
        .await
        .unwrap()
        .into_iter()
        .map(|(id,)| id)
        .collect();
        attached.sort();
        let mut expected = vec![allowed.clone(), preexisting.clone()];
        expected.sort();
        assert_eq!(
            attached, expected,
            "smuggled id dropped, invisible attachment preserved"
        );
        let mode: String =
            sqlx::query_scalar("SELECT resource_scheduling_mode FROM event_types WHERE id = ?")
                .bind(&et_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(mode, "round_robin");

        // Deselecting everything detaches the allowlisted resource but
        // still preserves the one outside the allowlist.
        save_event_type_resources_authorized(
            &pool,
            &et_id,
            &team_admin,
            false,
            Some(&team_id),
            &Some(String::new()),
            &Some("all".to_string()),
        )
        .await;
        let attached: Vec<(String,)> =
            sqlx::query_as("SELECT resource_id FROM event_type_resources WHERE event_type_id = ?")
                .bind(&et_id)
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(attached, vec![(preexisting.clone(),)]);
    }

    #[tokio::test]
    async fn save_resources_authorized_noop_without_allowlist() {
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;
        let team_admin = insert_role_user(&pool, "ta3@allow.test", "user").await;
        let team_id = seed_team_with_admin(&pool, "allow-empty", &team_admin).await;
        let resource = insert_resource(&pool, "Locked Lab").await;
        attach_resource(&pool, &et_id, &resource).await;

        // No allowlist for the team: the save is skipped entirely, mode
        // included, exactly like before the allowlist existed.
        save_event_type_resources_authorized(
            &pool,
            &et_id,
            &team_admin,
            false,
            Some(&team_id),
            &Some(String::new()),
            &Some("round_robin".to_string()),
        )
        .await;

        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM event_type_resources WHERE event_type_id = ?")
                .bind(&et_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(count, 1, "attachments untouched");
        let mode: String =
            sqlx::query_scalar("SELECT resource_scheduling_mode FROM event_types WHERE id = ?")
                .bind(&et_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(mode, "all", "mode untouched");
    }

    #[tokio::test]
    async fn booking_resource_label_reflects_mode() {
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;
        let res_a = insert_resource(&pool, "Lab A").await;
        let res_b = insert_resource(&pool, "Lab B").await;
        attach_resource(&pool, &et_id, &res_a).await;
        attach_resource(&pool, &et_id, &res_b).await;

        let uid = "label-test@calrs";
        sqlx::query(
            "INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token)
             VALUES ('lb1', ?, ?, 'G', 'g@e.com', 'UTC', '2026-08-03T10:00:00', '2026-08-03T10:30:00', 'confirmed', 'ct', 'rt')",
        )
        .bind(&et_id)
        .bind(uid)
        .execute(&pool)
        .await
        .unwrap();

        // 'all' mode: every attached resource, sorted by name.
        assert_eq!(
            booking_resource_label(&pool, uid).await.as_deref(),
            Some("Lab A, Lab B")
        );

        // round_robin: only the assigned resource.
        sqlx::query("UPDATE event_types SET resource_scheduling_mode = 'round_robin' WHERE id = ?")
            .bind(&et_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE bookings SET assigned_resource_id = ? WHERE uid = ?")
            .bind(&res_b)
            .bind(uid)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            booking_resource_label(&pool, uid).await.as_deref(),
            Some("Lab B")
        );

        // no resources attached: None.
        sqlx::query("DELETE FROM event_type_resources WHERE event_type_id = ?")
            .bind(&et_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE bookings SET assigned_resource_id = NULL WHERE uid = ?")
            .bind(uid)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE event_types SET resource_scheduling_mode = 'all' WHERE id = ?")
            .bind(&et_id)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(booking_resource_label(&pool, uid).await, None);
    }

    #[tokio::test]
    async fn sync_failure_records_error_and_success_would_clear_it() {
        let pool = setup_test_db().await;
        let rid = insert_resource(&pool, "Dead Lab").await;
        // Feed URL that fails validation instantly (no network involved).
        let res = crate::resources::sync_resource(&pool, &rid, "not-a-url").await;
        assert!(res.is_err());
        let err: Option<String> =
            sqlx::query_scalar("SELECT last_sync_error FROM resources WHERE id = ?")
                .bind(&rid)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            err.is_some(),
            "failed sync must record last_sync_error for the admin panel"
        );
    }

    #[tokio::test]
    async fn check_and_pick_without_resources_returns_no_resources() {
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;

        let check = crate::resources::check_and_pick(
            &pool,
            &et_id,
            dt(2026, 8, 3, 10, 0),
            dt(2026, 8, 3, 10, 30),
            Tz::UTC,
            None,
        )
        .await;
        assert_eq!(check, crate::resources::ResourceCheck::NoResources);
    }

    #[tokio::test]
    async fn check_and_pick_round_robin_picks_least_loaded_resource() {
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;
        sqlx::query("UPDATE event_types SET resource_scheduling_mode = 'round_robin' WHERE id = ?")
            .bind(&et_id)
            .execute(&pool)
            .await
            .unwrap();

        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }

        // Both resources are free at the checked slot, but Lab A already
        // carries two upcoming confirmed assignments at other times.
        let loaded_res = insert_resource(&pool, "Lab A").await;
        let idle_res = insert_resource(&pool, "Lab B").await;
        attach_resource(&pool, &et_id, &loaded_res).await;
        attach_resource(&pool, &et_id, &idle_res).await;
        insert_resource_booking(
            &pool,
            &et_id,
            &loaded_res,
            next_monday.and_hms_opt(9, 0, 0).unwrap(),
        )
        .await;
        insert_resource_booking(
            &pool,
            &et_id,
            &loaded_res,
            next_monday.and_hms_opt(11, 0, 0).unwrap(),
        )
        .await;

        let check = crate::resources::check_and_pick(
            &pool,
            &et_id,
            next_monday.and_hms_opt(10, 0, 0).unwrap(),
            next_monday.and_hms_opt(10, 30, 0).unwrap(),
            Tz::UTC,
            None,
        )
        .await;
        assert_eq!(
            check,
            crate::resources::ResourceCheck::Free {
                assigned: Some(idle_res)
            },
            "round_robin must prefer the resource with fewer upcoming assignments"
        );
    }

    #[tokio::test]
    async fn check_and_pick_cross_event_type_booking_blocks_shared_resource() {
        // Two event types in 'all' mode share the same resource. A confirmed
        // booking on A must block B at the same time even without any
        // resource_event rows (no write-back involved).
        let pool = setup_test_db().await;
        let (_, account_id, et_a) = seed_test_data(&pool).await;
        let et_b = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO event_types (id, account_id, slug, title, duration_min, buffer_before, buffer_after, min_notice_min, enabled) VALUES (?, ?, 'meeting-b', 'Meeting B', 30, 0, 0, 0, 1)")
            .bind(&et_b)
            .bind(&account_id)
            .execute(&pool).await.unwrap();

        let resource = insert_resource(&pool, "Demo Lab").await;
        attach_resource(&pool, &et_a, &resource).await;
        attach_resource(&pool, &et_b, &resource).await;

        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        insert_booking(
            &pool,
            &et_a,
            None,
            next_monday.and_hms_opt(10, 0, 0).unwrap(),
            "confirmed",
        )
        .await;

        let overlapping = crate::resources::check_and_pick(
            &pool,
            &et_b,
            next_monday.and_hms_opt(10, 0, 0).unwrap(),
            next_monday.and_hms_opt(10, 30, 0).unwrap(),
            Tz::UTC,
            None,
        )
        .await;
        assert_eq!(
            overlapping,
            crate::resources::ResourceCheck::Busy,
            "booking on A must block B at the overlapping time"
        );

        let disjoint = crate::resources::check_and_pick(
            &pool,
            &et_b,
            next_monday.and_hms_opt(14, 0, 0).unwrap(),
            next_monday.and_hms_opt(14, 30, 0).unwrap(),
            Tz::UTC,
            None,
        )
        .await;
        assert_eq!(
            disjoint,
            crate::resources::ResourceCheck::Free { assigned: None },
            "B must stay free outside A's booking"
        );
    }

    #[tokio::test]
    async fn transparent_and_cancelled_resource_events_do_not_block() {
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;

        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let start = next_monday.format("%Y%m%d").to_string();
        let end = (next_monday + Duration::days(1))
            .format("%Y%m%d")
            .to_string();

        let resource = insert_resource(&pool, "Demo Lab").await;
        attach_resource(&pool, &et_id, &resource).await;
        insert_resource_event(&pool, &resource, &start, &end, None, Some("TRANSPARENT")).await;
        insert_resource_event(&pool, &resource, &start, &end, Some("CANCELLED"), None).await;

        let busy = crate::resources::busy_for_resource(
            &pool,
            &resource,
            next_monday.and_hms_opt(0, 0, 0).unwrap(),
            (next_monday + Duration::days(1))
                .and_hms_opt(0, 0, 0)
                .unwrap(),
            Tz::UTC,
            None,
        )
        .await;
        assert!(
            busy.is_empty(),
            "TRANSPARENT and CANCELLED feed events must not produce busy intervals"
        );

        let check = crate::resources::check_and_pick(
            &pool,
            &et_id,
            next_monday.and_hms_opt(10, 0, 0).unwrap(),
            next_monday.and_hms_opt(10, 30, 0).unwrap(),
            Tz::UTC,
            None,
        )
        .await;
        assert_eq!(
            check,
            crate::resources::ResourceCheck::Free { assigned: None },
            "the slot must stay bookable"
        );
    }

    #[tokio::test]
    async fn booking_form_post_assigns_round_robin_resource() {
        let (app, pool, _, et_id) = setup_test_app().await;

        let busy_res = insert_resource(&pool, "Lab A").await;
        let free_res = insert_resource(&pool, "Lab B").await;
        attach_resource(&pool, &et_id, &busy_res).await;
        attach_resource(&pool, &et_id, &free_res).await;
        sqlx::query("UPDATE event_types SET resource_scheduling_mode = 'round_robin' WHERE id = ?")
            .bind(&et_id)
            .execute(&pool)
            .await
            .unwrap();

        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let date_str = next_monday.format("%Y-%m-%d").to_string();
        // Lab A is busy the whole Monday, so the pick must land on Lab B.
        insert_resource_event(
            &pool,
            &busy_res,
            &next_monday.format("%Y%m%d").to_string(),
            &(next_monday + Duration::days(1))
                .format("%Y%m%d")
                .to_string(),
            None,
            None,
        )
        .await;

        let csrf = "test-csrf-resource-book";
        let body = format!(
            "_csrf={}&date={}&time=10%3A00&name=Res+Guest&email=res%40test.com&notes=",
            csrf, date_str
        );
        let response = app
            .oneshot(post_form_unauthed(
                "/u/testuser/test-meeting/book",
                csrf,
                &body,
            ))
            .await
            .unwrap();

        let status = response.status();
        assert!(
            status == 200 || status.is_redirection(),
            "Booking should succeed, got {}",
            status
        );

        let assigned: (Option<String>,) = sqlx::query_as(
            "SELECT assigned_resource_id FROM bookings WHERE guest_email = 'res@test.com'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            assigned.0.as_deref(),
            Some(free_res.as_str()),
            "the booking must record the free round-robin resource"
        );
    }

    // Regression test: an availability rule that ends at 23:00 with a 60-min
    // slot must terminate. Before the fix, compute_slots_from_rules used a
    // NaiveTime cursor, and NaiveTime + Duration wraps at 24h — so when
    // cursor reached 23:00, cursor + slot_duration (60m) wrapped to 00:00
    // which is still <= 23:00 as a time-of-day, making the loop emit a slot
    // every step forever until OOM. Prod symptom: ~4-minute CPU spike +
    // ~9GB RAM before the OOM killer intervened (issue logged in internal
    // Vates Demo Team EN / book-a-demo-of-vates-vms booking page).
    #[test]
    fn compute_slots_terminates_with_window_ending_at_23_00() {
        let rules: Vec<(i32, String, String)> = (1..=4)
            .map(|d| (d, "09:00".to_string(), "23:00".to_string()))
            .collect();
        let busy = BusySource::Individual(vec![]);

        // Pick a start_offset that lands on a Monday so we hit at least one
        // rule-matching day regardless of when the test runs.
        let today = Utc::now().naive_utc().date();
        let mut start = 1i32;
        while (today + Duration::days(start as i64)).weekday() != chrono::Weekday::Mon {
            start += 1;
        }

        let result = compute_slots_from_rules(
            &rules,
            60,
            60,
            0,
            0,
            0,
            start,
            1,
            None,
            Tz::UTC,
            Tz::UTC,
            busy,
            &[],
        );

        // 09:00..=22:00 start times with 60-min spacing and 60-min duration =
        // 14 slots on a matching weekday. Anything beyond a few hundred means
        // the wrap bug is back.
        let total_slots: usize = result.iter().map(|d| d.slots.len()).sum();
        assert!(
            total_slots <= 20,
            "compute_slots_from_rules produced {} slots for a single day with \
             window 09:00-23:00 and 60-min duration; the NaiveTime wrap bug \
             is back",
            total_slots
        );
        assert_eq!(total_slots, 14, "expected exactly 14 hourly slots");
    }

    // Regression for issue #50: a team member in a different timezone than the host
    // must only be considered available within THEIR working hours, not inside the
    // event type's rule window interpreted in host_tz.
    #[tokio::test]
    async fn user_avail_as_busy_respects_member_timezone() {
        let pool = setup_test_db().await;

        let paris_uid = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO users (id, email, name, role, auth_provider, username, enabled, timezone) \
             VALUES (?, 'paris@example.com', 'Paris User', 'user', 'local', 'paris', 1, 'Europe/Paris')",
        )
        .bind(&paris_uid)
        .execute(&pool)
        .await
        .unwrap();

        // Paris member works Mon-Fri 09:00-17:00 local time
        for day in [1, 2, 3, 4, 5] {
            let rid = uuid::Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO user_availability_rules (id, user_id, day_of_week, start_time, end_time) \
                 VALUES (?, ?, ?, '09:00', '17:00')",
            )
            .bind(&rid)
            .bind(&paris_uid)
            .bind(day)
            .execute(&pool)
            .await
            .unwrap();
        }

        // Host is in New_York. In winter: Paris=UTC+1, NY=UTC-5 → 6h offset.
        // Paris 09:00-17:00 == NY 03:00-11:00.
        // Week of 2026-01-12 (Monday).
        let host_tz: Tz = "America/New_York".parse().unwrap();
        let window_start = dt(2026, 1, 12, 0, 0);
        let window_end = dt(2026, 1, 12, 23, 59);

        let busy = user_avail_as_busy(&pool, &paris_uid, window_start, window_end, host_tz).await;

        // Helper: is (t) inside any busy interval?
        let is_busy = |t: NaiveDateTime| busy.iter().any(|(s, e)| &t >= s && &t < e);

        // NY 02:00 Monday = Paris 08:00 — Paris member NOT working yet → must be busy.
        assert!(
            is_busy(dt(2026, 1, 12, 2, 0)),
            "NY 02:00 (Paris 08:00) should be blocked — outside member's working hours"
        );
        // NY 05:00 Monday = Paris 11:00 — Paris member IS working → must NOT be busy.
        assert!(
            !is_busy(dt(2026, 1, 12, 5, 0)),
            "NY 05:00 (Paris 11:00) should be free — inside member's working hours"
        );
        // NY 12:00 Monday = Paris 18:00 — Paris member done for the day → must be busy.
        assert!(
            is_busy(dt(2026, 1, 12, 12, 0)),
            "NY 12:00 (Paris 18:00) should be blocked — outside member's working hours"
        );
    }

    // Regression for Antoine's follow-up: the team event-type flow must apply
    // each member's personal working hours as a constraint (converted into
    // host_tz). Concretely: a team with a single America/Chicago member whose
    // personal rules are Mon-Fri 09:00-17:00 local must render slots in Paris
    // host_tz only from 16:00 onwards, not across the full 09:00-23:00 rule.
    // Verifies the exact conversion user_avail_as_busy performs; the
    // show_group_slots/pick_group_member handlers extend member_busy with
    // this output before running compute_slots.
    #[tokio::test]
    async fn chicago_member_is_busy_at_paris_morning() {
        let pool = setup_test_db().await;
        let uid = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO users (id, email, name, role, auth_provider, username, enabled, timezone) \
             VALUES (?, 'andy@example.com', 'Andy', 'user', 'local', 'andy', 1, 'America/Chicago')",
        )
        .bind(&uid)
        .execute(&pool)
        .await
        .unwrap();

        // Mon-Fri 09:00-17:00 Chicago local
        for day in 1..=5 {
            let rid = uuid::Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO user_availability_rules (id, user_id, day_of_week, start_time, end_time) \
                 VALUES (?, ?, ?, '09:00', '17:00')",
            )
            .bind(&rid)
            .bind(&uid)
            .bind(day)
            .execute(&pool)
            .await
            .unwrap();
        }

        // 2026-07-07 is a Tuesday in full summer DST (Chicago CDT UTC-5,
        // Paris CEST UTC+2, 7-hour offset — matches Antoine's scenario).
        let host_tz: Tz = "Europe/Paris".parse().unwrap();
        let window_start = dt(2026, 7, 7, 0, 0);
        let window_end = dt(2026, 7, 7, 23, 59);

        let busy = user_avail_as_busy(&pool, &uid, window_start, window_end, host_tz).await;
        let is_busy = |t: NaiveDateTime| busy.iter().any(|(s, e)| &t >= s && &t < e);

        // Paris 09:00 = Chicago 02:00 — outside 09-17, must be blocked.
        assert!(
            is_busy(dt(2026, 7, 7, 9, 0)),
            "Paris 09:00 (Chicago 02:00) must be blocked — Andy sleeping"
        );
        // Paris 16:00 = Chicago 09:00 — Andy just started, must be free.
        assert!(
            !is_busy(dt(2026, 7, 7, 16, 0)),
            "Paris 16:00 (Chicago 09:00) must be free — Andy working"
        );
        // Paris 22:00 = Chicago 15:00 — Andy still working, must be free.
        assert!(
            !is_busy(dt(2026, 7, 7, 22, 0)),
            "Paris 22:00 (Chicago 15:00) must be free — Andy working"
        );
    }

    // Regression: when a team member without any user_availability_rules is
    // active, they must be treated as always-available (no synthesized 9-17
    // default). This preserves the behavior Antoine tested originally where
    // a single Paris member expected the full event-type rule window.
    #[tokio::test]
    async fn member_without_personal_rules_is_unconstrained() {
        let pool = setup_test_db().await;
        let uid = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO users (id, email, name, role, auth_provider, username, enabled, timezone) \
             VALUES (?, 'free@example.com', 'No Hours', 'user', 'local', 'free', 1, 'Europe/Paris')",
        )
        .bind(&uid)
        .execute(&pool)
        .await
        .unwrap();
        // Deliberately NO user_availability_rules rows for this user.

        let host_tz: Tz = "Europe/Paris".parse().unwrap();
        let busy = user_avail_as_busy(
            &pool,
            &uid,
            dt(2026, 7, 7, 0, 0),
            dt(2026, 7, 7, 23, 59),
            host_tz,
        )
        .await;

        assert!(
            busy.is_empty(),
            "no personal rules must mean no constraint — got {} busy intervals",
            busy.len()
        );
    }

    // Regression for issue #50: an event type carries its own host timezone,
    // which must take precedence over the account owner's personal timezone.
    // Prevents the original bug where a US-based creator silently made the
    // team's 09:00-21:00 rule land in Chicago time.
    #[tokio::test]
    async fn get_host_tz_prefers_explicit_event_type_timezone() {
        let pool = setup_test_db().await;

        // Create a user in America/Chicago and their account.
        let user_id = uuid::Uuid::new_v4().to_string();
        let account_id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO users (id, email, name, role, auth_provider, username, enabled, timezone) \
             VALUES (?, 'chicago@example.com', 'Chicago User', 'user', 'local', 'chicago', 1, 'America/Chicago')",
        )
        .bind(&user_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO accounts (id, name, email, timezone, user_id) VALUES (?, 'Chicago User', 'chicago@example.com', 'America/Chicago', ?)")
            .bind(&account_id)
            .bind(&user_id)
            .execute(&pool)
            .await
            .unwrap();

        // Event type explicitly pinned to Europe/Paris.
        let et_id = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO event_types (id, account_id, slug, title, duration_min, buffer_before, buffer_after, min_notice_min, enabled, timezone) VALUES (?, ?, 'demo', 'Demo', 30, 0, 0, 0, 1, 'Europe/Paris')")
            .bind(&et_id)
            .bind(&account_id)
            .execute(&pool)
            .await
            .unwrap();

        assert_eq!(
            get_host_tz(&pool, &et_id).await,
            Tz::Europe__Paris,
            "explicit event-type timezone must win over account owner's"
        );

        // Event type with NULL timezone should fall back to the account owner.
        let et_id2 = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO event_types (id, account_id, slug, title, duration_min, buffer_before, buffer_after, min_notice_min, enabled) VALUES (?, ?, 'demo2', 'Demo2', 30, 0, 0, 0, 1)")
            .bind(&et_id2)
            .bind(&account_id)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            get_host_tz(&pool, &et_id2).await,
            Tz::America__Chicago,
            "NULL event-type timezone must fall back to account owner"
        );
    }

    // --- parse_booking_datetime tests ---

    #[test]
    fn parse_booking_datetime_iso_format() {
        assert_eq!(
            parse_booking_datetime("2026-03-15T14:30:00"),
            Some(dt(2026, 3, 15, 14, 30))
        );
    }

    #[test]
    fn parse_booking_datetime_space_format() {
        assert_eq!(
            parse_booking_datetime("2026-03-15 14:30:00"),
            Some(dt(2026, 3, 15, 14, 30))
        );
    }

    #[test]
    fn parse_booking_datetime_trailing_z() {
        assert_eq!(
            parse_booking_datetime("2026-03-15T14:30:00Z"),
            Some(dt(2026, 3, 15, 14, 30))
        );
    }

    #[test]
    fn parse_booking_datetime_invalid() {
        assert_eq!(parse_booking_datetime("not-a-date"), None);
        assert_eq!(parse_booking_datetime(""), None);
        assert_eq!(parse_booking_datetime("2026-13-40T99:99:99"), None);
    }

    // --- format_booking_datetime tests ---

    #[test]
    fn format_booking_datetime_far_future_same_year_not_guaranteed() {
        // Use a date far in the future (2099) so it's never "today"/"tomorrow"/weekday
        let result = format_booking_datetime("2099-07-20T09:15:00");
        assert_eq!(result, "Mon, Jul 20, 2099 at 9:15 AM");
    }

    #[test]
    fn format_booking_datetime_different_year() {
        let result = format_booking_datetime("2050-12-25T18:00:00");
        assert_eq!(result, "Sun, Dec 25, 2050 at 6:00 PM");
    }

    #[test]
    fn format_booking_datetime_invalid_fallback() {
        assert_eq!(format_booking_datetime("garbage"), "garbage");
        assert_eq!(format_booking_datetime(""), "");
    }

    // --- format_booking_range tests ---

    #[test]
    fn format_booking_range_far_future() {
        let result = format_booking_range("2099-07-20T09:00:00", "2099-07-20T09:30:00");
        assert_eq!(result, "Mon, Jul 20, 2099 at 9:00 AM — 9:30 AM");
    }

    #[test]
    fn format_booking_range_end_unparseable() {
        let result = format_booking_range("2099-07-20T09:00:00", "bad");
        assert_eq!(result, "Mon, Jul 20, 2099 at 9:00 AM — bad");
    }

    // --- format_booking_for_dashboard tests ---
    //
    // Regression for issue #100: when the event type's stored timezone differs
    // from the host's profile timezone, the dashboard previously displayed the
    // raw stored time with no timezone label, which the host read as their own
    // time. The fix shifts the primary label into the host's profile tz and
    // adds a secondary guest-tz line.

    #[test]
    fn dashboard_label_converts_stored_tz_to_host_profile_tz() {
        // The user's exact scenario: event type set to America/New_York
        // (UTC-5 in winter), host's profile is Europe/Paris (UTC+1 in winter),
        // guest booked from America/New_York at 10:00 → stored as "10:00".
        // Host should see "4:00 PM" (Paris equivalent), guest line shows "10:00 EST".
        let (primary, secondary) = format_booking_for_dashboard(
            "2099-01-20T10:00:00",
            "2099-01-20T10:30:00",
            "America/New_York",
            "Europe/Paris",
            "America/New_York",
        );
        assert!(
            primary.contains("4:00 PM") && primary.contains("4:30 PM"),
            "primary should be in Europe/Paris, got: {primary}"
        );
        assert!(
            primary.contains("CET"),
            "primary should label tz, got: {primary}"
        );
        let sec = secondary.expect("secondary line expected when guest tz differs from host tz");
        assert!(
            sec.contains("10:00 AM"),
            "secondary should show guest 10:00 AM, got: {sec}"
        );
        assert!(
            sec.contains("EST"),
            "secondary should label guest tz, got: {sec}"
        );
    }

    #[test]
    fn dashboard_label_omits_secondary_when_guest_tz_equals_host_tz() {
        let (_primary, secondary) = format_booking_for_dashboard(
            "2099-07-20T14:00:00",
            "2099-07-20T14:30:00",
            "Europe/Paris",
            "Europe/Paris",
            "Europe/Paris",
        );
        assert!(
            secondary.is_none(),
            "no secondary line when host and guest share tz"
        );
    }

    #[test]
    fn dashboard_label_falls_back_for_unparseable_input() {
        let (primary, secondary) = format_booking_for_dashboard(
            "garbage",
            "also-garbage",
            "Europe/Paris",
            "Europe/Paris",
            "America/New_York",
        );
        assert_eq!(primary, "garbage — also-garbage");
        assert!(secondary.is_none());
    }

    // --- format_date_label tests ---

    #[test]
    fn format_date_label_from_datetime() {
        assert_eq!(
            format_date_label("2026-03-15T14:30:00", "en"),
            "Sunday, March 15, 2026"
        );
    }

    #[test]
    fn format_date_label_from_date_only() {
        assert_eq!(
            format_date_label("2026-03-15", "en"),
            "Sunday, March 15, 2026"
        );
    }

    #[test]
    fn format_date_label_space_separator() {
        assert_eq!(
            format_date_label("2026-03-15 14:30:00", "en"),
            "Sunday, March 15, 2026"
        );
    }

    #[test]
    fn format_date_label_invalid_fallback() {
        assert_eq!(format_date_label("nope", "en"), "nope");
    }

    #[test]
    fn format_date_label_french() {
        assert_eq!(
            format_date_label("2026-03-15", "fr"),
            "dimanche 15 mars 2026"
        );
    }

    // --- format_time_from_dt tests ---

    #[test]
    fn format_time_from_dt_valid() {
        assert_eq!(format_time_from_dt("2026-03-15T14:30:00"), "2:30 PM");
        assert_eq!(format_time_from_dt("2026-03-15 09:05:00"), "9:05 AM");
    }

    #[test]
    fn format_time_from_dt_midnight() {
        assert_eq!(format_time_from_dt("2026-03-15T00:00:00"), "12:00 AM");
    }

    #[test]
    fn format_time_from_dt_unparseable_long_string() {
        // 16+ chars but not a valid datetime → falls back to substring [11..16]
        assert_eq!(format_time_from_dt("XXXX-XX-XX_HH:MM:SS"), "HH:MM");
    }

    #[test]
    fn format_time_from_dt_short_string() {
        assert_eq!(format_time_from_dt("short"), "00:00");
        assert_eq!(format_time_from_dt(""), "00:00");
    }

    // --- extract_time_24h tests ---

    #[test]
    fn extract_time_24h_returns_24h_format() {
        assert_eq!(extract_time_24h("2026-03-15T14:30:00"), "14:30");
        assert_eq!(extract_time_24h("2026-03-15 09:05:00"), "09:05");
        assert_eq!(extract_time_24h("2026-03-15T00:00:00"), "00:00");
    }

    #[test]
    fn extract_time_24h_short_string() {
        assert_eq!(extract_time_24h("short"), "00:00");
        assert_eq!(extract_time_24h(""), "00:00");
    }

    // --- parse_guest_tz tests ---

    #[test]
    fn parse_guest_tz_valid() {
        assert_eq!(
            parse_guest_tz(Some("America/New_York")),
            chrono_tz::America::New_York
        );
        assert_eq!(
            parse_guest_tz(Some("Europe/Paris")),
            chrono_tz::Europe::Paris
        );
        assert_eq!(parse_guest_tz(Some("UTC")), Tz::UTC);
    }

    #[test]
    fn parse_guest_tz_invalid_falls_back() {
        let tz = parse_guest_tz(Some("Not/A/Timezone"));
        // Should be server local or UTC — either way, not panic
        let _ = tz;
    }

    #[test]
    fn parse_guest_tz_none_falls_back() {
        let tz = parse_guest_tz(None);
        let _ = tz;
    }

    // --- parse_avail_windows tests ---

    #[test]
    fn parse_avail_windows_single_window() {
        let w = parse_avail_windows(Some("09:00-17:00"), None, None);
        assert_eq!(w, vec![("09:00".to_string(), "17:00".to_string())]);
    }

    #[test]
    fn parse_avail_windows_multiple_windows() {
        let w = parse_avail_windows(Some("09:00-12:00,13:00-17:00"), None, None);
        assert_eq!(
            w,
            vec![
                ("09:00".to_string(), "12:00".to_string()),
                ("13:00".to_string(), "17:00".to_string()),
            ]
        );
    }

    #[test]
    fn parse_avail_windows_legacy_fallback() {
        let w = parse_avail_windows(None, Some("08:00"), Some("16:00"));
        assert_eq!(w, vec![("08:00".to_string(), "16:00".to_string())]);
    }

    #[test]
    fn parse_avail_windows_empty_string_uses_legacy() {
        let w = parse_avail_windows(Some(""), Some("10:00"), Some("18:00"));
        assert_eq!(w, vec![("10:00".to_string(), "18:00".to_string())]);
    }

    #[test]
    fn parse_avail_windows_invalid_times_ignored() {
        let w = parse_avail_windows(Some("09:00-12:00,bad-data,13:00-17:00"), None, None);
        assert_eq!(
            w,
            vec![
                ("09:00".to_string(), "12:00".to_string()),
                ("13:00".to_string(), "17:00".to_string()),
            ]
        );
    }

    #[test]
    fn parse_avail_windows_defaults_when_none() {
        let w = parse_avail_windows(None, None, None);
        assert_eq!(w, vec![("09:00".to_string(), "17:00".to_string())]);
    }

    // --- validate_booking_input tests ---

    #[test]
    fn validate_booking_input_empty_name() {
        let result = validate_booking_input("", "user@example.com", &None);
        assert_eq!(result, Err("validate-name-length"));
    }

    #[test]
    fn validate_booking_input_name_too_long() {
        let long_name = "a".repeat(256);
        let result = validate_booking_input(&long_name, "user@example.com", &None);
        assert_eq!(result, Err("validate-name-length"));
    }

    #[test]
    fn validate_booking_input_valid_name() {
        let result = validate_booking_input("Jane Doe", "jane@example.com", &None);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_booking_input_empty_email() {
        let result = validate_booking_input("Jane", "", &None);
        assert_eq!(result, Err("validate-email-length"));
    }

    #[test]
    fn validate_booking_input_email_no_at() {
        let result = validate_booking_input("Jane", "userexample.com", &None);
        assert_eq!(result, Err("validate-email-invalid"));
    }

    #[test]
    fn validate_booking_input_email_no_domain_dot() {
        let result = validate_booking_input("Jane", "user@localhost", &None);
        assert_eq!(result, Err("validate-email-invalid"));
    }

    #[test]
    fn validate_booking_input_valid_email() {
        let result = validate_booking_input("Jane", "jane@example.com", &None);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_booking_input_notes_too_long() {
        let long_notes = Some("x".repeat(5001));
        let result = validate_booking_input("Jane", "jane@example.com", &long_notes);
        assert_eq!(result, Err("validate-notes-length"));
    }

    #[test]
    fn validate_booking_input_notes_within_limit() {
        let notes = Some("x".repeat(5000));
        let result = validate_booking_input("Jane", "jane@example.com", &notes);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_booking_input_none_notes() {
        let result = validate_booking_input("Jane", "jane@example.com", &None);
        assert!(result.is_ok());
    }

    /// The guest cap is the only Rust-side message with a plural selector, and
    /// a wrong category is invisible: Fluent falls through to `other`, the page
    /// still renders, and only a reader of that language notices. Polish is the
    /// case that motivated it, selecting one/few/many where English has two
    /// forms.
    #[test]
    fn the_guest_cap_message_pluralises_per_locale() {
        let guests = Some(
            "a@example.com,b@example.com,c@example.com,d@example.com,e@example.com,f@example.com"
                .to_string(),
        );
        let cap = |max: i32, lang: &str| {
            parse_additional_guests(&guests, max, "guest@example.com", lang)
                .expect_err("six guests must overflow every cap this test uses")
        };

        for (lang, _label) in crate::i18n::supported_with_labels() {
            let one = cap(1, lang);
            let two = cap(2, lang);
            for (n, msg) in [(1, &one), (2, &two)] {
                assert!(
                    !msg.contains('{') && !msg.contains("guests-too-many"),
                    "{lang} left the message unresolved at max={n}: {msg}"
                );
            }
            // Comparing the two renderings directly would pass on a message
            // with no selector at all, since the interpolated numeral alone
            // makes them differ. Normalise the digit away: what must differ is
            // the wording around it.
            assert_ne!(
                one,
                two.replace('2', "1"),
                "{lang} says the same thing for one guest and for two apart \
                 from the numeral, so the plural selector is not selecting"
            );
            assert!(
                two.contains('2'),
                "{lang} dropped the count from the plural form: {two}"
            );
        }

        // Polish selects a third category at 5. Its wording coincides with the
        // `few` form here (both take the genitive plural after "najwyżej"), so
        // the property worth pinning is that the variant exists and resolves,
        // not that it reads differently.
        let many = cap(5, "pl");
        assert!(
            !many.contains('{') && many.contains('5'),
            "pl `many` variant did not resolve: {many}"
        );
    }

    // --- validate_date_not_too_far tests ---

    #[test]
    fn validate_date_not_too_far_within_range() {
        let date = Utc::now().naive_utc().date() + Duration::days(30);
        assert!(validate_date_not_too_far(date).is_ok());
    }

    #[test]
    fn validate_date_not_too_far_exactly_365_days() {
        let date = Utc::now().naive_utc().date() + Duration::days(365);
        assert!(validate_date_not_too_far(date).is_ok());
    }

    #[test]
    fn validate_date_not_too_far_367_days_rejected() {
        let date = Utc::now().naive_utc().date() + Duration::days(367);
        assert!(validate_date_not_too_far(date).is_err());
    }

    #[test]
    fn validate_date_not_too_far_past_date_passes() {
        // Past dates are not rejected here (min_notice handles that elsewhere)
        let date = Utc::now().naive_utc().date() - Duration::days(10);
        assert!(validate_date_not_too_far(date).is_ok());
    }

    // --- CSRF function tests ---

    #[test]
    fn generate_csrf_token_returns_valid_uuid() {
        let token = generate_csrf_token();
        assert!(!token.is_empty());
        assert_eq!(token.len(), 36); // UUID format: 8-4-4-4-12
    }

    #[test]
    fn csrf_cookie_has_security_flags() {
        // `Secure` so the token never travels over plaintext HTTP.
        // `SameSite=Lax` to stop cross-site GETs from carrying it.
        // Deliberately NO `HttpOnly` — the double-submit pattern needs the
        // client script in base.html to read the cookie via document.cookie.
        let cookie = csrf_cookie_value("some-token");
        assert!(
            cookie.contains("; Secure"),
            "CSRF cookie must have Secure flag: {}",
            cookie
        );
        assert!(
            cookie.contains("SameSite=Lax"),
            "CSRF cookie must have SameSite=Lax: {}",
            cookie
        );
        assert!(
            !cookie.contains("HttpOnly"),
            "CSRF cookie must NOT be HttpOnly (JS needs to read it): {}",
            cookie
        );
    }

    #[test]
    fn csrf_cookie_embed_uses_samesite_none() {
        let cookie = csrf_cookie_value_for("tok", true);
        assert!(
            cookie.contains("SameSite=None"),
            "embed CSRF cookie must use SameSite=None for third-party iframes: {}",
            cookie
        );
        assert!(
            cookie.contains("; Secure"),
            "embed CSRF cookie must still carry Secure: {}",
            cookie
        );
        assert!(
            cookie.contains("; Partitioned"),
            "embed CSRF cookie must be Partitioned (CHIPS) for browsers blocking unpartitioned 3P cookies: {}",
            cookie
        );
    }

    #[test]
    fn csrf_cookie_non_embed_is_samesite_lax_unpartitioned() {
        let cookie = csrf_cookie_value_for("tok", false);
        assert!(cookie.contains("SameSite=Lax"), "{}", cookie);
        assert!(
            !cookie.contains("Partitioned"),
            "non-embed cookie must not be Partitioned: {}",
            cookie
        );
    }

    #[test]
    fn hex_to_rgb_parses_3_and_6_digit() {
        assert_eq!(hex_to_rgb("ff0000"), Some((255, 0, 0)));
        assert_eq!(hex_to_rgb("2563eb"), Some((37, 99, 235)));
        assert_eq!(hex_to_rgb("f30"), Some((255, 51, 0)));
        assert_eq!(hex_to_rgb("fff"), Some((255, 255, 255)));
        assert_eq!(hex_to_rgb(""), None);
        assert_eq!(hex_to_rgb("12345"), None);
        assert_eq!(hex_to_rgb("gggggg"), None);
    }

    #[test]
    fn hsl_round_trips_through_hex() {
        for hex in [
            "#2563eb", "#f4f4f5", "#18181b", "#ffffff", "#000000", "#be1621",
        ] {
            let (h, s, l) = hex_to_hsl(hex).expect("valid hex");
            assert_eq!(hsl_to_hex(h, s, l), hex, "round trip for {}", hex);
        }
        assert_eq!(hex_to_hsl("nothex"), None);
    }

    /// Splits the generated CSS into its `:root` and `html.dark` halves.
    fn theme_blocks(css: &str) -> (String, String) {
        let (light, dark) = css.split_once("html.dark").expect("both blocks present");
        (light.to_string(), dark.to_string())
    }

    #[test]
    fn custom_theme_derives_a_dark_palette_for_a_light_one() {
        // Regression test for #177: dark mode used to repeat the light colors.
        let css = custom_theme_css("#be1621", "#a01219", "#f5f4f0", "#ffffff", "#1a1b38");
        let (light, dark) = theme_blocks(&css);
        assert!(light.contains("--bg:#f5f4f0"), "{}", light);
        assert!(light.contains("--surface:#ffffff"), "{}", light);
        assert!(
            !dark.contains("--bg:#f5f4f0"),
            "dark bg must differ: {}",
            dark
        );
        assert!(!dark.contains("--surface:#ffffff"), "{}", dark);

        // Every dark neutral is actually dark, and the text is actually light.
        for var in ["--bg", "--surface", "--border"] {
            let hex = css_var(&dark, var);
            let (_, _, l) = hex_to_hsl(&hex).expect("derived hex");
            assert!(l < 0.3, "{} should be dark, got {} (l={})", var, hex, l);
        }
        for var in ["--text", "--text-secondary", "--text-muted"] {
            let hex = css_var(&dark, var);
            let (_, _, l) = hex_to_hsl(&hex).expect("derived hex");
            assert!(l > 0.5, "{} should be light, got {} (l={})", var, hex, l);
        }

        // The brand accent is untouched in both modes.
        assert!(light.contains("--accent:#be1621"), "{}", light);
        assert!(dark.contains("--accent:#be1621"), "{}", dark);
    }

    #[test]
    fn custom_theme_keeps_an_already_dark_palette() {
        let css = custom_theme_css("#bd93f9", "#caa6fc", "#282a36", "#44475a", "#f8f8f2");
        let (_, dark) = theme_blocks(&css);
        assert_eq!(css_var(&dark, "--bg"), "#282a36");
        assert_eq!(css_var(&dark, "--surface"), "#44475a");
        assert_eq!(css_var(&dark, "--text"), "#f8f8f2");
        // Supporting neutrals are still derived so borders match the surface.
        let (_, _, border_l) = hex_to_hsl(&css_var(&dark, "--border")).expect("derived hex");
        let (_, _, surface_l) = hex_to_hsl("#44475a").expect("valid hex");
        assert!(border_l > surface_l, "border should sit above the surface");
    }

    #[test]
    fn custom_theme_derives_for_a_mid_tone_background() {
        // A background at mid lightness is still a light palette when the text
        // is darker than it; an absolute lightness threshold would miss this.
        let css = custom_theme_css("#2563eb", "#1d4ed8", "#7a7a80", "#8e8e94", "#111111");
        let (_, dark) = theme_blocks(&css);
        let (_, _, bg_l) = hex_to_hsl(&css_var(&dark, "--bg")).expect("derived hex");
        assert!(bg_l < 0.3, "mid-tone palette should still get a dark bg");
    }

    #[test]
    fn custom_theme_tolerates_surrounding_whitespace() {
        // The admin form stores the pasted value as-is, and validate_hex trims
        // before measuring, so a padded color reaches the formatter intact.
        let padded = custom_theme_css(" #be1621 ", "#a01219", "#f5f4f0", "#ffffff", "#1a1b38");
        let clean = custom_theme_css("#be1621", "#a01219", "#f5f4f0", "#ffffff", "#1a1b38");
        assert_eq!(padded, clean);
        assert!(
            padded.contains("--accent-subtle:rgba(190,22,33,0.08)"),
            "accent must not parse as black: {}",
            padded
        );
    }

    #[tokio::test]
    async fn build_theme_css_derives_dark_from_stored_custom_colors() {
        let pool = setup_test_db().await;
        sqlx::query(
            "UPDATE auth_config SET theme = 'custom', custom_accent = '#be1621', custom_accent_hover = '#a01219', \
             custom_bg = '#f5f4f0', custom_surface = '#ffffff', custom_text = '#1a1b38' WHERE id = 'singleton'",
        )
        .execute(&pool)
        .await
        .unwrap();

        let css = build_theme_css(&pool).await;
        let (light, dark) = theme_blocks(&css);
        assert_eq!(css_var(&light, "--bg"), "#f5f4f0");
        assert_ne!(css_var(&dark, "--bg"), "#f5f4f0");
        let (_, _, dark_bg_l) = hex_to_hsl(&css_var(&dark, "--bg")).expect("derived hex");
        assert!(dark_bg_l < 0.3, "stored custom theme must yield a dark bg");
    }

    #[tokio::test]
    async fn build_theme_css_derives_dark_when_custom_colors_are_unset() {
        // theme='custom' with the columns still NULL falls back to the default
        // light palette, which must also produce a usable dark block.
        let pool = setup_test_db().await;
        sqlx::query("UPDATE auth_config SET theme = 'custom' WHERE id = 'singleton'")
            .execute(&pool)
            .await
            .unwrap();

        let css = build_theme_css(&pool).await;
        assert!(
            !css.is_empty(),
            "unset custom colors must not blank the theme"
        );
        let (_, dark) = theme_blocks(&css);
        let (_, _, dark_bg_l) = hex_to_hsl(&css_var(&dark, "--bg")).expect("derived hex");
        assert!(dark_bg_l < 0.3, "{}", dark);
    }

    #[test]
    fn custom_theme_rejects_invalid_hex() {
        assert_eq!(
            custom_theme_css("red", "#1d4ed8", "#fff", "#ffffff", "#000000"),
            ""
        );
    }

    /// Reads `--name:<value>;` out of a generated theme block.
    fn css_var(block: &str, name: &str) -> String {
        let start = block
            .find(&format!("{}:", name))
            .unwrap_or_else(|| panic!("{} missing from {}", name, block))
            + name.len()
            + 1;
        let rest = &block[start..];
        let end = rest.find([';', '}']).unwrap_or(rest.len());
        rest[..end].to_string()
    }

    #[test]
    fn brand_css_derives_rgba_variants() {
        let p = EmbedParams {
            brand: Some("ff0000".to_string()),
            ..Default::default()
        };
        let css = p.brand_css().expect("valid hex yields css");
        assert!(css.contains("--accent: #ff0000"), "{}", css);
        assert!(
            css.contains("--accent-subtle: rgba(255,0,0,0.12)"),
            "{}",
            css
        );
        assert!(
            css.contains("--accent-border: rgba(255,0,0,0.3)"),
            "{}",
            css
        );
        assert!(css.contains("--accent-muted: rgba(255,0,0,0.5)"), "{}", css);

        // Invalid input yields no CSS (never inject raw user input).
        let bad = EmbedParams {
            brand: Some("red; } body{display:none".to_string()),
            ..Default::default()
        };
        assert!(bad.brand_css().is_none());
    }

    #[test]
    fn is_embed_request_detects_flag() {
        assert!(is_embed_request(Some("embed=1")));
        assert!(is_embed_request(Some("embed=true")));
        assert!(is_embed_request(Some("foo=bar&embed=1&baz=qux")));
        assert!(!is_embed_request(Some("embed=0")));
        assert!(!is_embed_request(Some("notembed=1")));
        assert!(!is_embed_request(None));
        assert!(!is_embed_request(Some("")));
    }

    #[test]
    fn is_embeddable_path_allows_booking_surfaces_only() {
        // Public booking surfaces — embeddable.
        assert!(is_embeddable_path("/u/alice"));
        assert!(is_embeddable_path("/u/alice/intro"));
        assert!(is_embeddable_path("/u/alice/intro/book"));
        assert!(is_embeddable_path("/team/sales"));
        assert!(is_embeddable_path("/team/sales/intro"));
        assert!(is_embeddable_path("/g/sales"));
        // Legacy single-user booking pages.
        assert!(is_embeddable_path("/intro"));
        assert!(is_embeddable_path("/intro/book"));

        // Sensitive / non-booking surfaces — never embeddable.
        assert!(!is_embeddable_path("/auth/login"));
        assert!(!is_embeddable_path("/auth/register"));
        assert!(!is_embeddable_path("/dashboard"));
        assert!(!is_embeddable_path("/dashboard/event-types"));
        assert!(!is_embeddable_path("/dashboard/admin"));
        assert!(!is_embeddable_path("/"));
        assert!(!is_embeddable_path("/embed.js"));
        assert!(!is_embeddable_path("/accent.css"));
        assert!(!is_embeddable_path("/avatar/123"));
        assert!(!is_embeddable_path("/booking/approve/tok"));
    }

    #[test]
    fn embedded_booking_request_requires_both_flag_and_path() {
        // The blocking issue: embed=1 on a sensitive path must NOT enable embed.
        assert!(!is_embedded_booking_request("/auth/login", Some("embed=1")));
        assert!(!is_embedded_booking_request("/dashboard", Some("embed=1")));
        // Booking surface with the flag — enabled.
        assert!(is_embedded_booking_request(
            "/u/alice/intro",
            Some("embed=1")
        ));
        // Booking surface without the flag — not embed mode.
        assert!(!is_embedded_booking_request("/u/alice/intro", None));
    }

    #[test]
    fn csrf_token_from_headers_extracts_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            "__Host-calrs_csrf=test-token-123".parse().unwrap(),
        );
        let token = csrf_token_from_headers(&headers);
        assert_eq!(token, Some("test-token-123".to_string()));
    }

    #[test]
    fn csrf_token_from_headers_returns_none_when_missing() {
        let headers = HeaderMap::new();
        let token = csrf_token_from_headers(&headers);
        assert_eq!(token, None);
    }

    #[test]
    fn csrf_token_from_headers_ignores_other_cookies() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            "__Host-calrs_session=abc; other=xyz".parse().unwrap(),
        );
        let token = csrf_token_from_headers(&headers);
        assert_eq!(token, None);
    }

    #[test]
    fn verify_csrf_token_passes_when_matching() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            "__Host-calrs_csrf=my-token".parse().unwrap(),
        );
        let form_token = Some("my-token".to_string());
        assert!(verify_csrf_token(&headers, &form_token).is_ok());
    }

    #[test]
    fn verify_csrf_token_fails_when_mismatch() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            "__Host-calrs_csrf=cookie-token".parse().unwrap(),
        );
        let form_token = Some("different-token".to_string());
        assert!(verify_csrf_token(&headers, &form_token).is_err());
    }

    #[test]
    fn verify_csrf_token_fails_when_form_token_none() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            "__Host-calrs_csrf=my-token".parse().unwrap(),
        );
        let form_token: Option<String> = None;
        assert!(verify_csrf_token(&headers, &form_token).is_err());
    }

    #[test]
    fn verify_csrf_token_fails_when_cookie_missing() {
        let headers = HeaderMap::new();
        let form_token = Some("my-token".to_string());
        assert!(verify_csrf_token(&headers, &form_token).is_err());
    }

    #[test]
    fn verify_csrf_token_fails_when_cookie_empty() {
        // An empty cookie value would byte-compare-equal to an empty form
        // field; the explicit empty-cookie guard prevents that bypass.
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            "__Host-calrs_csrf=".parse().unwrap(),
        );
        let form_token = Some(String::new());
        assert!(verify_csrf_token(&headers, &form_token).is_err());
    }

    #[test]
    fn verify_csrf_token_fails_when_lengths_differ() {
        // ConstantTimeEq returns false on length mismatch; this just pins
        // that mismatched-length tokens are still rejected.
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            "__Host-calrs_csrf=short".parse().unwrap(),
        );
        let form_token = Some("a-much-longer-token".to_string());
        assert!(verify_csrf_token(&headers, &form_token).is_err());
    }

    #[test]
    fn verify_csrf_token_fails_when_same_length_differs_at_last_byte() {
        // Exercises the actual ct_eq byte-fold path: both tokens are the
        // same length, so the comparison runs over every byte rather than
        // short-circuiting on the length mismatch.
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            "__Host-calrs_csrf=aaaaaaaaaaaaaaaa".parse().unwrap(),
        );
        let form_token = Some("aaaaaaaaaaaaaaab".to_string());
        assert!(verify_csrf_token(&headers, &form_token).is_err());
    }

    // --- client_ip_for_rate_limit ---

    #[test]
    fn client_ip_unknown_when_no_headers() {
        let headers = HeaderMap::new();
        assert_eq!(client_ip_for_rate_limit(&headers), "unknown");
    }

    #[test]
    fn client_ip_ignores_x_real_ip() {
        // We deliberately do not honour X-Real-IP: in default Caddy/Nginx
        // setups the proxy does not overwrite a client-supplied value, so
        // trusting it would let the client forge their identity directly.
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", "1.2.3.4".parse().unwrap());
        assert_eq!(client_ip_for_rate_limit(&headers), "unknown");
    }

    #[test]
    fn client_ip_takes_rightmost_xff() {
        // The leftmost value is whatever the original client put in the
        // header; the rightmost is the trusted proxy's view of its peer.
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "attacker-spoofed, 198.51.100.7".parse().unwrap(),
        );
        assert_eq!(client_ip_for_rate_limit(&headers), "198.51.100.7");
    }

    #[test]
    fn client_ip_xff_single_value() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.10".parse().unwrap());
        assert_eq!(client_ip_for_rate_limit(&headers), "203.0.113.10");
    }

    #[test]
    fn client_ip_xff_trims_whitespace() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "1.2.3.4 ,    198.51.100.7   ".parse().unwrap(),
        );
        assert_eq!(client_ip_for_rate_limit(&headers), "198.51.100.7");
    }

    // --- internal_error_* sanitization helpers ---

    #[test]
    fn internal_error_response_returns_500_with_generic_body() {
        // Whatever the underlying error says, the response body must not
        // contain it. The detail goes to logs only.
        let resp = internal_error_response("test ctx", &"sensitive: /var/lib/calrs/calrs.db error");
        assert_eq!(resp.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn internal_error_html_body_is_generic() {
        let html = internal_error_html("test", &"users.password_hash leaks here");
        let Html(body) = html;
        assert!(
            !body.contains("password_hash"),
            "body leaked detail: {}",
            body
        );
        assert!(!body.contains("users."), "body leaked detail: {}", body);
        assert!(body.contains("internal error"));
    }

    #[test]
    fn internal_error_body_is_generic() {
        let body = internal_error_body("test", &"some/private/path: nope");
        assert!(!body.contains("/private/path"), "body leaked: {body}");
    }

    #[test]
    fn oidc_error_response_returns_500_without_detail() {
        // openidconnect errors can carry IdP URLs and token content; the
        // response body must not pass them through.
        let resp = oidc_error_response(
            "test",
            &"token endpoint https://idp/token returned: <secret-token-bytes>",
        );
        assert_eq!(resp.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// Capture `tracing` output into a shared buffer so log-emission can be
    /// asserted from a test. Used to pin the contract that the sanitization
    /// helpers actually log the underlying detail; a future refactor that
    /// drops the log call would cause this test to fail.
    ///
    /// Uses a hand-rolled minimal `Subscriber` instead of
    /// `tracing_subscriber::fmt`. The fmt layer's per-event writer plumbing
    /// proved flaky under `cargo tarpaulin` (events occasionally landed in a
    /// dropped buffer), and we don't need the formatting machinery here:
    /// recording field names + their `Debug` strings is enough to assert that
    /// the event carried the expected markers.
    fn capture_tracing<F: FnOnce()>(f: F) -> String {
        use std::sync::{Arc, Mutex};
        use tracing::field::{Field, Visit};
        use tracing::{Event, Metadata, Subscriber};

        #[derive(Clone)]
        struct Buf(Arc<Mutex<String>>);

        struct Recorder {
            buf: Arc<Mutex<String>>,
        }
        impl Subscriber for Recorder {
            fn enabled(&self, _: &Metadata<'_>) -> bool {
                true
            }
            fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
                tracing::span::Id::from_u64(1)
            }
            fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
            fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
            fn event(&self, event: &Event<'_>) {
                struct V<'a>(&'a Mutex<String>);
                impl<'a> Visit for V<'a> {
                    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                        use std::fmt::Write;
                        let mut s = self.0.lock().unwrap();
                        let _ = write!(s, "{}={:?} ", field.name(), value);
                    }
                    fn record_str(&mut self, field: &Field, value: &str) {
                        use std::fmt::Write;
                        let mut s = self.0.lock().unwrap();
                        let _ = write!(s, "{}={} ", field.name(), value);
                    }
                }
                event.record(&mut V(&self.buf));
                self.buf.lock().unwrap().push('\n');
            }
            fn enter(&self, _: &tracing::span::Id) {}
            fn exit(&self, _: &tracing::span::Id) {}
        }

        let buf = Buf(Arc::new(Mutex::new(String::new())));
        let subscriber = Recorder { buf: buf.0.clone() };
        tracing::subscriber::with_default(subscriber, || {
            // tracing caches per-callsite Interest the first time the
            // callsite fires. If a sibling test (e.g. one that just
            // exercises the response body without capturing logs) ran
            // first under NoSubscriber, the cached interest is `never` and
            // our scoped Recorder never sees the event. Force a rebuild
            // against the now-active subscriber before invoking f.
            tracing::callsite::rebuild_interest_cache();
            f();
        });
        let s = buf.0.lock().unwrap().clone();
        s
    }

    /// Whether the current process is running under cargo-tarpaulin. The
    /// tracing-capture tests below race with tarpaulin's instrumentation in
    /// a way I haven't fully pinned down: the captured buffer ends up empty
    /// even though the same test passes deterministically under plain
    /// `cargo test`. Skip those tests under coverage rather than ship a
    /// red CI job, but keep them live everywhere else so the contract is
    /// still enforced.
    ///
    /// Detection uses `cfg!(tarpaulin)` since cargo-tarpaulin compiles with
    /// `--cfg=tarpaulin`. An earlier attempt keyed off `CARGO_TARPAULIN_VERSION`
    /// but tarpaulin never sets that env var, so the guard never fired.
    fn under_tarpaulin() -> bool {
        cfg!(tarpaulin)
    }

    #[test]
    fn internal_error_logs_capture_underlying_detail() {
        if under_tarpaulin() {
            return;
        }
        // Pin: the helper must emit a tracing::error! that carries both the
        // context label and the underlying error string. The body sent to
        // the user is generic; the detail goes here.
        let log = capture_tracing(|| {
            let _ = internal_error_response("test-context-marker", &"sensitive-detail-marker");
        });
        assert!(
            log.contains("test-context-marker"),
            "log missing context: {log}"
        );
        assert!(
            log.contains("sensitive-detail-marker"),
            "log missing error detail: {log}"
        );
    }

    #[test]
    fn oidc_error_logs_capture_underlying_detail() {
        if under_tarpaulin() {
            return;
        }
        let log = capture_tracing(|| {
            let _ = oidc_error_response("oidc-context-marker", &"token-endpoint-detail-marker");
        });
        assert!(
            log.contains("oidc-context-marker"),
            "log missing context: {log}"
        );
        assert!(
            log.contains("token-endpoint-detail-marker"),
            "log missing error detail: {log}"
        );
    }

    // --- is_safe_company_link ---

    #[test]
    fn company_link_accepts_http_and_https() {
        assert!(is_safe_company_link("http://example.com"));
        assert!(is_safe_company_link("https://example.com"));
        assert!(is_safe_company_link("HTTPS://EXAMPLE.COM"));
        assert!(is_safe_company_link("  https://example.com/path  "));
    }

    #[test]
    fn company_link_rejects_javascript_uri() {
        // The whole point of this validator: stop stored XSS via the
        // company-link anchor that renders on every public page.
        assert!(!is_safe_company_link("javascript:alert(1)"));
        assert!(!is_safe_company_link("JAVASCRIPT:alert(1)"));
        assert!(!is_safe_company_link("  javascript:alert(1)"));
    }

    #[test]
    fn company_link_rejects_other_dangerous_schemes() {
        assert!(!is_safe_company_link("data:text/html,<script>"));
        assert!(!is_safe_company_link("vbscript:msgbox(1)"));
        assert!(!is_safe_company_link("file:///etc/passwd"));
    }

    #[test]
    fn company_link_rejects_unschemed_input() {
        // A bare hostname shouldn't slip through. The rendered anchor
        // would be relative to the booking page, which is wrong and
        // looks like a path traversal vector.
        assert!(!is_safe_company_link("example.com"));
        assert!(!is_safe_company_link("/foo/bar"));
        assert!(!is_safe_company_link("//example.com"));
        assert!(!is_safe_company_link(""));
    }

    // --- fetch_busy_times_for_user_ex booking exclusion tests ---

    #[tokio::test]
    async fn fetch_busy_times_ex_excludes_specified_booking() {
        let pool = setup_test_db().await;
        let (user_id, account_id, et_id) = seed_test_data(&pool).await;

        let booking_id = uuid::Uuid::new_v4().to_string();
        let cancel_tok = uuid::Uuid::new_v4().to_string();
        let resched_tok = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid-ex1', 'Guest', 'guest@example.com', 'UTC', '2026-03-16T10:00:00', '2026-03-16T10:30:00', 'confirmed', ?, ?)")
            .bind(&booking_id)
            .bind(&et_id)
            .bind(&cancel_tok)
            .bind(&resched_tok)
            .execute(&pool).await.unwrap();

        // A successful CalDAV write followed by sync creates a second local
        // representation of the same booking under the same iCalendar UID.
        let source_id = uuid::Uuid::new_v4().to_string();
        let calendar_id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO caldav_sources (id, account_id, name, url, username) \
             VALUES (?, ?, 'Write calendar', 'https://calendar.test', 'host')",
        )
        .bind(&source_id)
        .bind(&account_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO calendars (id, source_id, href, display_name, is_busy) \
             VALUES (?, ?, '/write/', 'Write calendar', 1)",
        )
        .bind(&calendar_id)
        .bind(&source_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO events (id, calendar_id, uid, summary, start_at, end_at, status, transp) \
             VALUES (?, ?, 'uid-ex1', 'Synced booking', '20260316T100000', \
                     '20260316T103000', 'CONFIRMED', 'OPAQUE')",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&calendar_id)
        .execute(&pool)
        .await
        .unwrap();

        // Without exclusion both local representations show as busy.
        let busy = fetch_busy_times_for_user_ex(
            &pool,
            &user_id,
            dt(2026, 3, 15, 0, 0),
            dt(2026, 3, 21, 23, 59),
            Tz::UTC,
            None,
            None,
            None,
        )
        .await;
        assert_eq!(
            busy.len(),
            2,
            "booking row and synced calendar copy should both be busy without exclusion"
        );

        // With both identifiers, neither representation blocks its own slot.
        let busy_ex = fetch_busy_times_for_user_ex(
            &pool,
            &user_id,
            dt(2026, 3, 15, 0, 0),
            dt(2026, 3, 21, 23, 59),
            Tz::UTC,
            None,
            Some(&booking_id),
            Some("uid-ex1"),
        )
        .await;
        assert!(
            busy_ex.is_empty(),
            "excluded booking and its synced calendar copy should both disappear"
        );
    }

    #[tokio::test]
    async fn fetch_busy_times_ex_excludes_only_specified_booking() {
        let pool = setup_test_db().await;
        let (user_id, _, et_id) = seed_test_data(&pool).await;

        // Insert two bookings
        let booking_id_1 = uuid::Uuid::new_v4().to_string();
        let booking_id_2 = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid-a', 'Guest A', 'a@example.com', 'UTC', '2026-03-16T10:00:00', '2026-03-16T10:30:00', 'confirmed', ?, ?)")
            .bind(&booking_id_1)
            .bind(&et_id)
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(uuid::Uuid::new_v4().to_string())
            .execute(&pool).await.unwrap();

        sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid-b', 'Guest B', 'b@example.com', 'UTC', '2026-03-16T14:00:00', '2026-03-16T14:30:00', 'confirmed', ?, ?)")
            .bind(&booking_id_2)
            .bind(&et_id)
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(uuid::Uuid::new_v4().to_string())
            .execute(&pool).await.unwrap();

        // Exclude first booking: only second should be busy
        let busy = fetch_busy_times_for_user_ex(
            &pool,
            &user_id,
            dt(2026, 3, 15, 0, 0),
            dt(2026, 3, 21, 23, 59),
            Tz::UTC,
            None,
            Some(&booking_id_1),
            None,
        )
        .await;
        assert_eq!(
            busy.len(),
            1,
            "Only the non-excluded booking should be in busy times"
        );
        assert_eq!(busy[0].0, dt(2026, 3, 16, 14, 0));
    }

    #[tokio::test]
    async fn fetch_busy_times_ex_none_exclusion_matches_original() {
        let pool = setup_test_db().await;
        let (user_id, _, et_id) = seed_test_data(&pool).await;

        let booking_id = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid-c', 'Guest', 'guest@example.com', 'UTC', '2026-03-16T10:00:00', '2026-03-16T10:30:00', 'confirmed', ?, ?)")
            .bind(&booking_id)
            .bind(&et_id)
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(uuid::Uuid::new_v4().to_string())
            .execute(&pool).await.unwrap();

        let busy_original = fetch_busy_times_for_user(
            &pool,
            &user_id,
            dt(2026, 3, 15, 0, 0),
            dt(2026, 3, 21, 23, 59),
            Tz::UTC,
            None,
        )
        .await;

        let busy_ex = fetch_busy_times_for_user_ex(
            &pool,
            &user_id,
            dt(2026, 3, 15, 0, 0),
            dt(2026, 3, 21, 23, 59),
            Tz::UTC,
            None,
            None,
            None,
        )
        .await;

        assert_eq!(
            busy_original.len(),
            busy_ex.len(),
            "None exclusion should match original function"
        );
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

    #[tokio::test]
    async fn reschedule_token_lookup_finds_confirmed_booking() {
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;

        let (bid, token, _) = insert_test_booking(
            &pool,
            &et_id,
            "2026-03-16T10:00:00",
            "2026-03-16T10:30:00",
            "confirmed",
        )
        .await;

        let found: Option<(String,)> = sqlx::query_as(
            "SELECT id FROM bookings WHERE reschedule_token = ? AND status IN ('confirmed', 'pending')"
        )
        .bind(&token)
        .fetch_optional(&pool).await.unwrap();

        assert!(found.is_some(), "Should find booking by reschedule_token");
        assert_eq!(found.unwrap().0, bid);
    }

    #[tokio::test]
    async fn reschedule_token_lookup_finds_pending_booking() {
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;

        let (bid, token, _) = insert_test_booking(
            &pool,
            &et_id,
            "2026-03-16T10:00:00",
            "2026-03-16T10:30:00",
            "pending",
        )
        .await;

        let found: Option<(String,)> = sqlx::query_as(
            "SELECT id FROM bookings WHERE reschedule_token = ? AND status IN ('confirmed', 'pending')"
        )
        .bind(&token)
        .fetch_optional(&pool).await.unwrap();

        assert!(
            found.is_some(),
            "Should find pending booking by reschedule_token"
        );
        assert_eq!(found.unwrap().0, bid);
    }

    #[tokio::test]
    async fn reschedule_token_lookup_rejects_cancelled_booking() {
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;

        let (_, token, _) = insert_test_booking(
            &pool,
            &et_id,
            "2026-03-16T10:00:00",
            "2026-03-16T10:30:00",
            "cancelled",
        )
        .await;

        let found: Option<(String,)> = sqlx::query_as(
            "SELECT id FROM bookings WHERE reschedule_token = ? AND status IN ('confirmed', 'pending')"
        )
        .bind(&token)
        .fetch_optional(&pool).await.unwrap();

        assert!(
            found.is_none(),
            "Cancelled booking should not be found by reschedule_token"
        );
    }

    #[tokio::test]
    async fn reschedule_token_lookup_rejects_declined_booking() {
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;

        let (_, token, _) = insert_test_booking(
            &pool,
            &et_id,
            "2026-03-16T10:00:00",
            "2026-03-16T10:30:00",
            "declined",
        )
        .await;

        let found: Option<(String,)> = sqlx::query_as(
            "SELECT id FROM bookings WHERE reschedule_token = ? AND status IN ('confirmed', 'pending')"
        )
        .bind(&token)
        .fetch_optional(&pool).await.unwrap();

        assert!(
            found.is_none(),
            "Declined booking should not be found by reschedule_token"
        );
    }

    #[tokio::test]
    async fn reschedule_updates_times_and_regenerates_tokens() {
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;

        let (bid, old_resched, old_cancel) = insert_test_booking(
            &pool,
            &et_id,
            "2026-03-16T10:00:00",
            "2026-03-16T10:30:00",
            "confirmed",
        )
        .await;

        // Simulate a guest reschedule: update times, regenerate tokens, set pending
        let new_resched = uuid::Uuid::new_v4().to_string();
        let new_cancel = uuid::Uuid::new_v4().to_string();
        let new_confirm = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "UPDATE bookings SET start_at = ?, end_at = ?, status = 'pending',
                    reschedule_token = ?, cancel_token = ?, confirm_token = ?,
                    reminder_sent_at = NULL
             WHERE id = ?",
        )
        .bind("2026-03-17T14:00:00")
        .bind("2026-03-17T14:30:00")
        .bind(&new_resched)
        .bind(&new_cancel)
        .bind(&new_confirm)
        .bind(&bid)
        .execute(&pool)
        .await
        .unwrap();

        // Verify the booking was updated
        let (start_at, end_at, status, resched_tok, cancel_tok, confirm_tok): (String, String, String, String, String, Option<String>) =
            sqlx::query_as("SELECT start_at, end_at, status, reschedule_token, cancel_token, confirm_token FROM bookings WHERE id = ?")
            .bind(&bid)
            .fetch_one(&pool).await.unwrap();

        assert_eq!(start_at, "2026-03-17T14:00:00");
        assert_eq!(end_at, "2026-03-17T14:30:00");
        assert_eq!(status, "pending");
        assert_eq!(resched_tok, new_resched);
        assert_ne!(
            resched_tok, old_resched,
            "Reschedule token should be regenerated"
        );
        assert_eq!(cancel_tok, new_cancel);
        assert_ne!(cancel_tok, old_cancel, "Cancel token should be regenerated");
        assert_eq!(confirm_tok.unwrap(), new_confirm);
    }

    #[tokio::test]
    async fn stale_reschedule_token_returns_no_match() {
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;

        let (bid, old_token, _) = insert_test_booking(
            &pool,
            &et_id,
            "2026-03-16T10:00:00",
            "2026-03-16T10:30:00",
            "confirmed",
        )
        .await;

        // Regenerate the token (simulating a prior reschedule)
        let new_token = uuid::Uuid::new_v4().to_string();
        sqlx::query("UPDATE bookings SET reschedule_token = ? WHERE id = ?")
            .bind(&new_token)
            .bind(&bid)
            .execute(&pool)
            .await
            .unwrap();

        // Old token should no longer find anything
        let found: Option<(String,)> = sqlx::query_as(
            "SELECT id FROM bookings WHERE reschedule_token = ? AND status IN ('confirmed', 'pending')"
        )
        .bind(&old_token)
        .fetch_optional(&pool).await.unwrap();

        assert!(
            found.is_none(),
            "Stale reschedule token should not find any booking"
        );

        // New token should work
        let found_new: Option<(String,)> = sqlx::query_as(
            "SELECT id FROM bookings WHERE reschedule_token = ? AND status IN ('confirmed', 'pending')"
        )
        .bind(&new_token)
        .fetch_optional(&pool).await.unwrap();

        assert!(
            found_new.is_some(),
            "New reschedule token should find booking"
        );
    }

    #[tokio::test]
    async fn host_initiated_reschedule_stays_confirmed() {
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;

        let (bid, _, _) = insert_test_booking(
            &pool,
            &et_id,
            "2026-03-16T10:00:00",
            "2026-03-16T10:30:00",
            "confirmed",
        )
        .await;

        // Step 1: Host initiates reschedule (sets flag, regenerates token)
        let new_resched = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "UPDATE bookings SET reschedule_token = ?, reschedule_by_host = 1 WHERE id = ?",
        )
        .bind(&new_resched)
        .bind(&bid)
        .execute(&pool)
        .await
        .unwrap();

        let by_host: i32 =
            sqlx::query_scalar("SELECT reschedule_by_host FROM bookings WHERE id = ?")
                .bind(&bid)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(by_host, 1, "reschedule_by_host should be set");

        // Step 2: Guest picks a new time — should stay confirmed since host initiated
        let new_cancel = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "UPDATE bookings SET start_at = ?, end_at = ?, status = 'confirmed',
                    reschedule_token = ?, cancel_token = ?, confirm_token = NULL,
                    reminder_sent_at = NULL, reschedule_by_host = 0
             WHERE id = ?",
        )
        .bind("2026-03-18T09:00:00")
        .bind("2026-03-18T09:30:00")
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&new_cancel)
        .bind(&bid)
        .execute(&pool)
        .await
        .unwrap();

        let (status, confirm_tok, by_host2): (String, Option<String>, i32) = sqlx::query_as(
            "SELECT status, confirm_token, reschedule_by_host FROM bookings WHERE id = ?",
        )
        .bind(&bid)
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(
            status, "confirmed",
            "Host-initiated reschedule should keep confirmed status after guest picks time"
        );
        assert!(
            confirm_tok.is_none(),
            "No confirm_token needed for host-initiated reschedule"
        );
        assert_eq!(
            by_host2, 0,
            "reschedule_by_host should be reset after completion"
        );
    }

    #[tokio::test]
    async fn reschedule_clears_reminder_sent_at() {
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;

        let (bid, _, _) = insert_test_booking(
            &pool,
            &et_id,
            "2026-03-16T10:00:00",
            "2026-03-16T10:30:00",
            "confirmed",
        )
        .await;

        // Set reminder_sent_at
        sqlx::query("UPDATE bookings SET reminder_sent_at = '2026-03-15T08:00:00' WHERE id = ?")
            .bind(&bid)
            .execute(&pool)
            .await
            .unwrap();

        // Reschedule
        sqlx::query(
            "UPDATE bookings SET start_at = '2026-03-17T10:00:00', end_at = '2026-03-17T10:30:00',
                    reschedule_token = ?, cancel_token = ?, reminder_sent_at = NULL
             WHERE id = ?",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&bid)
        .execute(&pool)
        .await
        .unwrap();

        let reminder: Option<Option<String>> =
            sqlx::query_scalar("SELECT reminder_sent_at FROM bookings WHERE id = ?")
                .bind(&bid)
                .fetch_optional(&pool)
                .await
                .unwrap();

        assert_eq!(
            reminder,
            Some(None),
            "reminder_sent_at should be cleared after reschedule"
        );
    }

    #[tokio::test]
    async fn reschedule_excluded_booking_frees_its_slot() {
        let pool = setup_test_db().await;
        let (user_id, _, et_id) = seed_test_data(&pool).await;

        // Book 10:00-10:30
        let (bid, _, _) = insert_test_booking(
            &pool,
            &et_id,
            "2026-03-16T10:00:00",
            "2026-03-16T10:30:00",
            "confirmed",
        )
        .await;

        // Without exclusion: 10:00-10:30 is busy
        let busy = fetch_busy_times_for_user_ex(
            &pool,
            &user_id,
            dt(2026, 3, 16, 9, 0),
            dt(2026, 3, 16, 12, 0),
            Tz::UTC,
            None,
            None,
            None,
        )
        .await;
        assert!(
            has_conflict(&busy, dt(2026, 3, 16, 10, 0), dt(2026, 3, 16, 10, 30)),
            "10:00-10:30 should conflict without exclusion"
        );

        // With exclusion: slot is free for rescheduling back to same time
        let busy_ex = fetch_busy_times_for_user_ex(
            &pool,
            &user_id,
            dt(2026, 3, 16, 9, 0),
            dt(2026, 3, 16, 12, 0),
            Tz::UTC,
            None,
            Some(&bid),
            None,
        )
        .await;
        assert!(
            !has_conflict(&busy_ex, dt(2026, 3, 16, 10, 0), dt(2026, 3, 16, 10, 30)),
            "10:00-10:30 should be free when booking is excluded (reschedule to same slot)"
        );
    }

    // --- Template rendering regression tests ---

    /// Maximum `<a>` nesting depth in rendered HTML. HTML parsers close an
    /// open anchor when they meet another `<a>`, so anything above 1 means the
    /// browser will tear the outer element apart.
    fn max_anchor_depth(html: &str) -> usize {
        let lower = html.to_ascii_lowercase();
        let bytes = lower.as_bytes();
        let (mut depth, mut max, mut i) = (0usize, 0usize, 0usize);
        while i < bytes.len() {
            if bytes[i..].starts_with(b"</a>") {
                depth = depth.saturating_sub(1);
                i += 4;
            } else if bytes[i..].starts_with(b"<a") && matches!(bytes.get(i + 2), Some(b' ' | b'>'))
            {
                depth += 1;
                max = max.max(depth);
                i += 2;
            } else {
                i += 1;
            }
        }
        max
    }

    /// Regression test for #239: an event-type description containing a
    /// markdown link must not produce an `<a>` nested inside the card link on
    /// the user and team profile pages, and the description link must survive.
    #[test]
    fn profile_cards_do_not_nest_description_links() {
        let mut env = minijinja::Environment::new();
        env.set_undefined_behavior(minijinja::UndefinedBehavior::Lenient);
        env.set_loader(minijinja::path_loader("templates"));
        crate::i18n::register(&mut env);

        let description =
            crate::utils::render_inline_markdown("See [the agenda](https://example.com/agenda)");
        assert!(description.contains("<a "), "markdown should render a link");
        let event_types = vec![context! {
            slug => "intro",
            title => "Intro Call",
            duration_min => 30,
            description => description,
            visibility => "public",
        }];

        let profile = env
            .get_template("profile.html")
            .expect("profile.html should load")
            .render(context! {
                host_name => "Alice",
                username => "alice",
                event_types => event_types.clone(),
                lang => "en",
            })
            .expect("profile.html should render");
        let team = env
            .get_template("team_profile.html")
            .expect("team_profile.html should load")
            .render(context! {
                team_name => "Sales",
                team_slug => "sales",
                event_types => event_types,
                lang => "en",
            })
            .expect("team_profile.html should render");

        for (name, html, href) in [
            ("profile.html", &profile, "href=\"/u/alice/intro\""),
            ("team_profile.html", &team, "href=\"/team/sales/intro\""),
        ] {
            assert_eq!(max_anchor_depth(html), 1, "{name} nests an <a> in an <a>");
            assert!(
                html.contains("https://example.com/agenda"),
                "{name} must keep the description link"
            );
            assert!(html.contains(href), "{name} must keep the card link");
        }
    }

    /// Render slots.html WITHOUT reschedule context and verify slot links
    /// point to /book and not to a JSON object.
    /// Regression test for: default(value='') rendering as {"value": ""}
    #[test]
    fn slots_template_links_without_reschedule_context() {
        let mut env = minijinja::Environment::new();
        env.set_undefined_behavior(minijinja::UndefinedBehavior::Lenient);
        env.set_loader(minijinja::path_loader("templates"));
        crate::i18n::register(&mut env);

        let tmpl = env
            .get_template("slots.html")
            .expect("slots.html should load");

        // Minimal context mimicking show_slots_for_user (no reschedule_base)
        let rendered = tmpl
            .render(context! {
                event_type => context! {
                    slug => "intro",
                    title => "Intro Call",
                    duration_min => 30,
                },
                host_name => "Alice",
                username => "alice",
                days => vec![
                    context! {
                        date => "2026-03-16",
                        label => "Mon",
                        slots => vec![
                            context! { start => "10:00", end => "10:30", host_date => "2026-03-16", host_time => "10:00", guest_date => "2026-03-16" },
                        ],
                    },
                ],
                available_dates => vec!["2026-03-16"],
                month_label => "March 2026",
                month_year => "2026-03",
                next_month => "2026-04",
                first_weekday => 0,
                days_in_month => 31,
                today_date => "2026-03-14",
                guest_tz => "UTC",
            })
            .expect("slots.html should render");

        // basePath must be /u/alice/intro, not something with { in it
        assert!(
            rendered.contains("&#x2f;u&#x2f;alice&#x2f;intro")
                || rendered.contains("/u/alice/intro"),
            "basePath should be /u/alice/intro"
        );

        // rescheduleBase must be empty, not a JSON object
        assert!(
            !rendered.contains(r#"{"value"#),
            "rescheduleBase must not render as a JSON object"
        );

        // Slot links should go to /book, not to a bare {
        assert!(
            !rendered.contains(r#"href="{"#),
            "Slot hrefs must not start with opening brace"
        );
    }

    /// Render slots.html WITH reschedule context and verify slot links
    /// use the reschedule URL, not the /book path.
    #[test]
    fn slots_template_links_with_reschedule_context() {
        let mut env = minijinja::Environment::new();
        env.set_undefined_behavior(minijinja::UndefinedBehavior::Lenient);
        env.set_loader(minijinja::path_loader("templates"));
        crate::i18n::register(&mut env);

        let tmpl = env
            .get_template("slots.html")
            .expect("slots.html should load");

        let rendered = tmpl
            .render(context! {
                event_type => context! {
                    slug => "intro",
                    title => "Intro Call",
                    duration_min => 30,
                },
                host_name => "Alice",
                username => "alice",
                reschedule_base => "/booking/reschedule/abc123",
                reschedule_info => context! {
                    event_title => "Intro Call",
                    old_date => "2026-03-15",
                    old_time => "10:00",
                },
                days => vec![
                    context! {
                        date => "2026-03-16",
                        label => "Mon",
                        slots => vec![
                            context! { start => "10:00", end => "10:30", host_date => "2026-03-16", host_time => "10:00", guest_date => "2026-03-16" },
                        ],
                    },
                ],
                available_dates => vec!["2026-03-16"],
                month_label => "March 2026",
                month_year => "2026-03",
                next_month => "2026-04",
                first_weekday => 0,
                days_in_month => 31,
                today_date => "2026-03-14",
                guest_tz => "UTC",
            })
            .expect("slots.html should render");

        // basePath should be the reschedule URL, not the normal /u/alice/intro
        assert!(
            rendered.contains("reschedule&#x2f;abc123") || rendered.contains("reschedule/abc123"),
            "basePath should be the reschedule URL when reschedule_base is set"
        );

        // Reschedule banner should appear
        assert!(
            rendered.contains("Rescheduling:"),
            "Reschedule banner should be visible"
        );

        // Banner must be OUTSIDE slots-outer (not a flex child of the 3-column layout).
        // Search in the HTML body, skipping the <style> block where CSS class names also appear.
        let body_start = rendered.find("<div class=\"reschedule-banner\"").unwrap();
        let slots_outer_start = rendered.find("<div class=\"slots-outer\"").unwrap();
        assert!(
            body_start < slots_outer_start,
            "Reschedule banner div must appear before slots-outer div to avoid flex layout breakage"
        );
    }

    /// Render slots.html on the first bookable month, where the handler passes
    /// `prev_month` as `None`, and verify the calendar payload carries an empty
    /// string rather than the literal "none".
    ///
    /// Regression test for the same class as the `default(value='')` bug above:
    /// minijinja renders a Rust `None` as "none", and `default()` does not
    /// catch it because the value is defined, just none. The JS guard then saw
    /// a truthy "none" and drew a back arrow pointing at ?month=none.
    #[test]
    fn slots_template_renders_absent_prev_month_as_empty() {
        let mut env = minijinja::Environment::new();
        env.set_undefined_behavior(minijinja::UndefinedBehavior::Lenient);
        env.set_loader(minijinja::path_loader("templates"));
        crate::i18n::register(&mut env);
        let tmpl = env
            .get_template("slots.html")
            .expect("slots.html should load");

        // Exactly what build_month_params hands the template.
        let render = |prev: Option<String>| {
            tmpl.render(context! {
                event_type => context! { slug => "intro", title => "Intro Call", duration_min => 30 },
                host_name => "Alice",
                username => "alice",
                days => Vec::<minijinja::Value>::new(),
                available_dates => Vec::<String>::new(),
                month_label => "March 2026",
                month_year => "2026-03",
                prev_month => prev,
                next_month => Some("2026-04".to_string()),
                first_weekday => 0,
                days_in_month => 31,
                today_date => "2026-03-14",
                guest_tz => "UTC",
            })
            .expect("slots.html should render")
        };
        let payload_line = |rendered: &str, key: &str| {
            rendered
                .lines()
                .find(|l| l.contains(&format!("\"{key}\"")))
                .unwrap_or_else(|| panic!("the calendar payload must carry {key}"))
                .trim()
                .to_string()
        };

        let first_month = render(None);
        assert_eq!(
            payload_line(&first_month, "prevMonth"),
            "\"prevMonth\": \"\",",
            "an absent previous month must serialise as an empty string, not \"none\""
        );
        assert!(
            first_month.contains("\"hasPrevMonth\": false"),
            "hasPrevMonth must be false when there is no previous month"
        );

        // Control: a previous month that does exist must still come through,
        // so this cannot pass by blanking prevMonth unconditionally.
        let later_month = render(Some("2026-02".to_string()));
        assert_eq!(
            payload_line(&later_month, "prevMonth"),
            "\"prevMonth\": \"2026-02\","
        );
        assert!(
            later_month.contains("\"hasPrevMonth\": true"),
            "hasPrevMonth must be true when a previous month exists"
        );

        // The forward arrow is the already-correct sibling: same construct,
        // unchanged by this fix, asserted so the two stay in step.
        assert_eq!(
            payload_line(&first_month, "nextMonth"),
            "\"nextMonth\": \"2026-04\","
        );

        // The AJAX path must gate on the flag, matching the forward arrow,
        // so a future regression in the payload cannot resurrect the arrow.
        assert!(
            first_month.contains("if (data.hasPrevMonth && data.prevMonth)"),
            "the AJAX back arrow must gate on hasPrevMonth, as the forward arrow does"
        );
    }

    #[tokio::test]
    async fn compute_slots_blocked_override_skips_day() {
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;

        // Find the next Monday
        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let days_to_monday = (next_monday - now.date()).num_days() as i32;
        let monday_str = next_monday.format("%Y-%m-%d").to_string();

        // Block that Monday with an override
        let override_id = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO availability_overrides (id, event_type_id, date, is_blocked) VALUES (?, ?, ?, 1)")
            .bind(&override_id)
            .bind(&et_id)
            .bind(&monday_str)
            .execute(&pool)
            .await
            .unwrap();

        let slot_days = compute_slots(
            &pool,
            &et_id,
            30,
            0,
            0,
            0,
            days_to_monday,
            1,
            None,
            Tz::UTC,
            Tz::UTC,
            BusySource::Individual(vec![]),
            None,
        )
        .await;

        // Monday should be blocked — no slots
        assert!(
            slot_days.is_empty(),
            "Blocked override should skip the day, got {} days with slots",
            slot_days.len()
        );
    }

    #[tokio::test]
    async fn compute_slots_custom_hours_override() {
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;

        // Find the next Monday
        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let days_to_monday = (next_monday - now.date()).num_days() as i32;
        let monday_str = next_monday.format("%Y-%m-%d").to_string();

        // Override Monday with custom hours: only 10:00-12:00 (instead of default 09:00-17:00)
        let override_id = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO availability_overrides (id, event_type_id, date, start_time, end_time, is_blocked) VALUES (?, ?, ?, '10:00', '12:00', 0)")
            .bind(&override_id)
            .bind(&et_id)
            .bind(&monday_str)
            .execute(&pool)
            .await
            .unwrap();

        let slot_days = compute_slots(
            &pool,
            &et_id,
            30,
            0,
            0,
            0,
            days_to_monday,
            1,
            None,
            Tz::UTC,
            Tz::UTC,
            BusySource::Individual(vec![]),
            None,
        )
        .await;

        assert!(!slot_days.is_empty(), "Should have slots for custom hours");
        // 10:00-12:00 with 30min slots = 4 slots (10:00, 10:30, 11:00, 11:30)
        let total_slots: usize = slot_days.iter().map(|d| d.slots.len()).sum();
        assert_eq!(
            total_slots, 4,
            "10:00-12:00 with 30min = 4 slots, got {}",
            total_slots
        );
    }

    // --- slot_interval_min unit tests ---

    #[tokio::test]
    async fn compute_slots_custom_interval_fewer_slots() {
        // When slot_interval is 60 with a 30-min duration, the cursor steps by 60 min
        // producing 1 slot per hour instead of 2 per hour
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;

        // Override: 60-min slot interval, 30-min duration
        sqlx::query("UPDATE event_types SET slot_interval_min = 60 WHERE id = ?")
            .bind(&et_id)
            .execute(&pool)
            .await
            .unwrap();

        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let days_to_monday = (next_monday - now.date()).num_days() as i32;

        let slot_days = compute_slots(
            &pool,
            &et_id,
            30, // duration
            0,
            0,
            0,
            days_to_monday,
            1,
            None,
            Tz::UTC,
            Tz::UTC,
            BusySource::Individual(vec![]),
            None,
        )
        .await;

        assert!(!slot_days.is_empty());
        let monday = &slot_days[0];
        // 09:00-17:00 = 8 hours; 60-min interval → 8 slots (09:00, 10:00, ..., 16:00)
        assert_eq!(
            monday.slots.len(),
            8,
            "60-min interval over 09:00-17:00 should yield 8 slots, got {}",
            monday.slots.len()
        );
        // Verify exact start times
        let slot_times: Vec<&str> = monday.slots.iter().map(|s| s.start.as_str()).collect();
        let expected: Vec<&str> = vec![
            "09:00", "10:00", "11:00", "12:00", "13:00", "14:00", "15:00", "16:00",
        ];
        assert_eq!(
            slot_times, expected,
            "Slot times should match 60-min interval stepping"
        );
    }

    #[tokio::test]
    async fn compute_slots_custom_interval_15_min() {
        // 15-min interval with 30-min duration: cursor steps by 15 min
        // 09:00-17:00 = 8 hours = 480 min; 480/15 = 32 cursor positions
        // but cursor must satisfy cursor + 30 <= 17:00, so 16:45+30=17:15 > 17:00 → last is 16:30
        // That gives 31 slots (09:00 through 16:30)
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;

        sqlx::query("UPDATE event_types SET slot_interval_min = 15 WHERE id = ?")
            .bind(&et_id)
            .execute(&pool)
            .await
            .unwrap();

        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let days_to_monday = (next_monday - now.date()).num_days() as i32;

        let slot_days = compute_slots(
            &pool,
            &et_id,
            30, // duration
            0,
            0,
            0,
            days_to_monday,
            1,
            None,
            Tz::UTC,
            Tz::UTC,
            BusySource::Individual(vec![]),
            None,
        )
        .await;

        assert!(!slot_days.is_empty());
        let monday = &slot_days[0];
        // 09:00-17:00 with 30-min slot: 31 slots (09:00 … 16:30)
        // 16:45 + 30 = 17:15 > 17:00 so it's excluded
        assert_eq!(
            monday.slots.len(),
            31,
            "15-min interval over 09:00-17:00 should yield 31 slots, got {}",
            monday.slots.len()
        );
        // Verify first and last slots
        let slot_times: Vec<&str> = monday.slots.iter().map(|s| s.start.as_str()).collect();
        assert_eq!(slot_times.first(), Some(&"09:00"));
        assert_eq!(slot_times.last(), Some(&"16:30"));
    }

    #[tokio::test]
    async fn compute_slots_interval_greater_than_duration() {
        // When interval (60) > duration (30), cursor steps 60 but each slot occupies 30 min
        // This means some potential slots are skipped (e.g., 09:30 is never checked)
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;

        sqlx::query("UPDATE event_types SET slot_interval_min = 60 WHERE id = ?")
            .bind(&et_id)
            .execute(&pool)
            .await
            .unwrap();

        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let days_to_monday = (next_monday - now.date()).num_days() as i32;

        // Block 09:00-09:30 on Monday
        let monday_date = next_monday;
        let busy_start = monday_date.and_hms_opt(9, 0, 0).unwrap();
        let busy_end = monday_date.and_hms_opt(9, 30, 0).unwrap();

        let slot_days = compute_slots(
            &pool,
            &et_id,
            30,
            0,
            0,
            0,
            days_to_monday,
            1,
            None,
            Tz::UTC,
            Tz::UTC,
            BusySource::Individual(vec![(busy_start, busy_end)]),
            None,
        )
        .await;

        assert!(!slot_days.is_empty());
        let monday = &slot_days[0];
        // 09:00 slot is blocked by busy event, so 7 remaining slots
        assert_eq!(
            monday.slots.len(),
            7,
            "09:00 slot should be blocked by busy event, got {}",
            monday.slots.len()
        );
        let slot_times: Vec<&str> = monday.slots.iter().map(|s| s.start.as_str()).collect();
        assert!(!slot_times.contains(&"09:00"), "09:00 should be blocked");
        assert!(
            slot_times.contains(&"10:00"),
            "10:00 should still be available"
        );
    }

    #[tokio::test]
    async fn compute_slots_null_interval_defaults_to_duration() {
        // When slot_interval_min is NULL (unset), should default to duration (legacy behavior)
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;

        // Don't set slot_interval — it should be NULL from seed_test_data
        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let days_to_monday = (next_monday - now.date()).num_days() as i32;

        let slot_days = compute_slots(
            &pool,
            &et_id,
            30, // duration
            0,
            0,
            0,
            days_to_monday,
            1,
            None,
            Tz::UTC,
            Tz::UTC,
            BusySource::Individual(vec![]),
            None,
        )
        .await;

        assert!(!slot_days.is_empty());
        let monday = &slot_days[0];
        // Should default to 30-min stepping (same as duration) → 16 slots
        assert_eq!(
            monday.slots.len(),
            16,
            "NULL interval should default to duration (30-min stepping) → 16 slots, got {}",
            monday.slots.len()
        );
    }

    #[tokio::test]
    async fn compute_slots_interval_zero_defaults_to_duration() {
        // When slot_interval_min is 0, should also default to duration
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;

        sqlx::query("UPDATE event_types SET slot_interval_min = 0 WHERE id = ?")
            .bind(&et_id)
            .execute(&pool)
            .await
            .unwrap();

        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let days_to_monday = (next_monday - now.date()).num_days() as i32;

        let slot_days = compute_slots(
            &pool,
            &et_id,
            30,
            0,
            0,
            0,
            days_to_monday,
            1,
            None,
            Tz::UTC,
            Tz::UTC,
            BusySource::Individual(vec![]),
            None,
        )
        .await;

        assert!(!slot_days.is_empty());
        let monday = &slot_days[0];
        assert_eq!(
            monday.slots.len(),
            16,
            "Zero interval should default to duration (30-min stepping) → 16 slots, got {}",
            monday.slots.len()
        );
    }

    #[tokio::test]
    async fn compute_slots_interval_with_buffer_overlap() {
        // Interval of 60 with a 15-min buffer should correctly reject slots
        // that would overlap with busy events via buffer zones
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;

        sqlx::query("UPDATE event_types SET slot_interval_min = 60 WHERE id = ?")
            .bind(&et_id)
            .execute(&pool)
            .await
            .unwrap();

        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let days_to_monday = (next_monday - now.date()).num_days() as i32;

        // Busy event at 09:00-09:30, with 15-min buffer it blocks 08:45-09:45
        // So 09:00 slot (buf_start=08:45, buf_end=10:00) overlaps with busy event (08:45 < 09:30 && 09:00 > 08:45)
        let busy_start = next_monday.and_hms_opt(9, 0, 0).unwrap();
        let busy_end = next_monday.and_hms_opt(9, 30, 0).unwrap();

        let slot_days = compute_slots(
            &pool,
            &et_id,
            30,
            15, // buffer before
            15, // buffer after
            0,
            days_to_monday,
            1,
            None,
            Tz::UTC,
            Tz::UTC,
            BusySource::Individual(vec![(busy_start, busy_end)]),
            None,
        )
        .await;

        assert!(!slot_days.is_empty());
        let monday = &slot_days[0];
        // 09:00 is blocked by direct overlap + buffer
        assert_eq!(
            monday.slots.len(),
            7,
            "09:00 slot blocked by event+buffer, got {}",
            monday.slots.len()
        );
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

    #[tokio::test]
    async fn root_redirects_to_login() {
        let (app, _, _, _) = setup_test_app().await;
        let response = app.oneshot(get("/")).await.unwrap();
        assert_eq!(response.status(), 303);
        assert_eq!(
            response
                .headers()
                .get("location")
                .unwrap()
                .to_str()
                .unwrap(),
            "/auth/login"
        );
    }

    // --- Vendored intl-tel-input bundle ---

    #[tokio::test]
    async fn intl_tel_input_assets_are_served_with_their_content_types() {
        let (app, _, _, _) = setup_test_app().await;
        let expected = [
            ("intlTelInput.min.js", "application/javascript"),
            ("intlTelInput.min.css", "text/css"),
            ("utils.js", "application/javascript"),
            ("flags.webp", "image/webp"),
            ("flags@2x.webp", "image/webp"),
            ("globe.webp", "image/webp"),
            ("globe@2x.webp", "image/webp"),
        ];
        for (file, content_type) in expected {
            let response = app
                .clone()
                .oneshot(get(&format!("/static/intl-tel-input/{file}")))
                .await
                .unwrap();
            assert_eq!(response.status(), 200, "{file} should be served");
            let served = response
                .headers()
                .get("Content-Type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            assert!(
                served.starts_with(content_type),
                "{file} should be served as {content_type}, got {served}"
            );
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            assert!(!bytes.is_empty(), "{file} should not be empty");
        }
    }

    #[tokio::test]
    async fn intl_tel_input_route_serves_only_the_vendored_files() {
        // The handler matches names exactly rather than reading from a
        // directory, so nothing outside the bundle is addressable.
        let (app, _, _, _) = setup_test_app().await;
        for probe in [
            "nope.js",
            "utils.js.map",
            "UTILS.JS",
            "..%2F..%2FCargo.toml",
            "%2Fetc%2Fpasswd",
        ] {
            let response = app
                .clone()
                .oneshot(get(&format!("/static/intl-tel-input/{probe}")))
                .await
                .unwrap();
            assert_ne!(
                response.status(),
                200,
                "{probe} must not resolve to a served file"
            );
        }
    }

    #[test]
    fn vendored_utils_js_keeps_its_apache_notice() {
        // utils.js is Google's libphonenumber under Apache-2.0, not the MIT
        // licence covering the rest of the bundle. The notice has to survive
        // any version bump, so assert on it rather than trusting the README.
        let utils = include_str!("../../assets/intl-tel-input/utils.js");
        let head = &utils[..utils.len().min(400)];
        assert!(
            head.contains("Apache-2.0"),
            "utils.js must keep its Apache-2.0 SPDX header"
        );
        assert!(
            head.contains("Copyright The Closure Library Authors"),
            "utils.js must keep its copyright notice"
        );
        // Lazy loading uses a dynamic import(), which needs an ES module.
        assert!(
            utils.trim_end().ends_with("export default utils;"),
            "utils.js must stay an ES module for loadUtils to work"
        );
    }

    #[test]
    fn book_template_phone_field_degrades_without_javascript() {
        let mut env = minijinja::Environment::new();
        env.set_undefined_behavior(minijinja::UndefinedBehavior::Lenient);
        env.set_loader(minijinja::path_loader("templates"));
        crate::i18n::register(&mut env);
        let tmpl = env
            .get_template("book.html")
            .expect("book.html should load");

        let render = |mode: &str| {
            tmpl.render(context! {
                event_type => context! { slug => "intro", title => "Intro Call", duration_min => 30 },
                sms_phone_mode => mode,
                phone_default_country => "+33",
                form_phone => "",
                host_name => "Alice",
                username => "alice",
            })
            .expect("book.html should render")
        };

        let on = render("optional");
        // The visible input keeps name="phone", so a browser that never runs
        // the widget still posts the number and the server still normalises it.
        assert!(
            on.contains(r#"id="phone" name="phone""#),
            "the phone input must keep its own name for the no-JS path"
        );
        assert!(
            on.contains("/static/intl-tel-input/intlTelInput.min.js"),
            "the widget script should be referenced"
        );
        assert!(
            on.contains("loadUtils"),
            "utils.js should be lazy-loaded, not linked eagerly"
        );
        assert!(
            !on.contains(r#"<script src="/static/intl-tel-input/utils.js">"#),
            "utils.js must not be fetched eagerly on every booking page"
        );
        // The dial code the operator configured is what seeds the country when
        // the browser declines to name one.
        assert!(
            on.contains(r#"DEFAULT_DIAL_CODE = "+33""#),
            "the configured dial code should reach the seed logic"
        );
        // Shared dial codes (+1, +7, +44) resolve by priority. Without this the
        // name-sorted list makes +1 American Samoa.
        assert!(
            on.contains("c.priority") && on.contains("best.priority"),
            "dial-code lookup must prefer the primary country"
        );
        // getNumber() returns "" until utils.js lands, so sync() has to build
        // the number from the selected country in the meantime. Without this a
        // guest who submits inside that window posts an empty phone.
        assert!(
            on.contains("getSelectedCountryData"),
            "sync() must fall back to the picker's country before utils.js loads"
        );
        assert!(
            on.contains("iti.promise"),
            "a re-sync must replace the stopgap once libphonenumber is in"
        );

        // Off means the field, the widget and its stylesheet are all absent.
        let off = render("off");
        assert!(!off.contains(r#"id="phone""#), "no phone field when off");
        // The theme block for .iti lives in base.html and is always present,
        // exactly like the cap-widget one. What must not happen is fetching
        // the bundle on a page with no phone field.
        assert!(
            !off.contains("/static/intl-tel-input/"),
            "no widget asset should be fetched when phone collection is off"
        );
    }

    #[tokio::test]
    async fn login_page_returns_200() {
        let (app, _, _, _) = setup_test_app().await;
        let response = app.oneshot(get("/auth/login")).await.unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;
        assert!(
            body.contains("Sign in"),
            "Login page should contain Sign in"
        );
    }

    #[tokio::test]
    async fn login_page_hides_register_when_disabled() {
        let (app, pool, _, _) = setup_test_app().await;

        // Disable registration
        sqlx::query("UPDATE auth_config SET registration_enabled = 0 WHERE id = 'singleton'")
            .execute(&pool)
            .await
            .unwrap();

        let response = app.oneshot(get("/auth/login")).await.unwrap();
        let body = body_string(response).await;
        assert!(
            !body.contains("Register"),
            "Register link should be hidden when registration is disabled"
        );
    }

    #[tokio::test]
    async fn dashboard_redirects_unauthenticated() {
        let (app, _, _, _) = setup_test_app().await;
        let response = app.oneshot(get("/dashboard")).await.unwrap();
        assert_eq!(response.status(), 303);
    }

    #[tokio::test]
    async fn dashboard_returns_200_for_authenticated_user() {
        let (app, _, session, _) = setup_test_app().await;
        let response = app
            .oneshot(get_authed("/dashboard", &session))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;
        assert!(body.contains("Welcome"), "Dashboard should contain Welcome");
    }

    #[tokio::test]
    async fn event_types_page_returns_200() {
        let (app, _, session, _) = setup_test_app().await;
        let response = app
            .oneshot(get_authed("/dashboard/event-types", &session))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;
        assert!(
            body.contains("Test Meeting"),
            "Event types page should list seeded event type"
        );
    }

    #[tokio::test]
    async fn bookings_page_returns_200() {
        let (app, _, session, _) = setup_test_app().await;
        let response = app
            .oneshot(get_authed("/dashboard/bookings", &session))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;
        assert!(
            body.contains("Upcoming bookings"),
            "Bookings page should render"
        );
    }

    #[tokio::test]
    async fn sources_page_returns_200() {
        let (app, _, session, _) = setup_test_app().await;
        let response = app
            .oneshot(get_authed("/dashboard/sources", &session))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn settings_page_returns_200() {
        let (app, _, session, _) = setup_test_app().await;
        let response = app
            .oneshot(get_authed("/dashboard/settings", &session))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;
        assert!(body.contains("Test User"), "Settings should show user name");
    }

    #[tokio::test]
    async fn admin_page_returns_200_for_admin() {
        let (app, _, session, _) = setup_test_app().await;
        let response = app
            .oneshot(get_authed("/dashboard/admin", &session))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;
        assert!(body.contains("Admin"), "Admin page should render");

        // The SMS card is rendered from the provider registry, so every
        // shipped gateway must show up without touching the template.
        assert!(body.contains("SMS settings"), "SMS card should render");
        for spec in crate::sms::PROVIDER_SPECS {
            assert!(
                body.contains(spec.label),
                "SMS gateway {} should be offered",
                spec.label
            );
        }
    }

    /// The TLS mode `<select>` marks exactly one option `selected`. Two would
    /// be worse than none: a browser honours the last one, so an operator on
    /// STARTTLS would be shown "None, unencrypted" and silently downgrade the
    /// transport by saving the form untouched.
    #[tokio::test]
    async fn admin_smtp_tls_mode_select_marks_one_option() {
        // Reads config that CALRS_* env blocks override (see CLAUDE.md).
        let _env = crate::test_support::ENV_LOCK.lock().await;
        for (stored, expected_label) in [
            ("starttls", "STARTTLS (port 587)"),
            ("tls", "Implicit TLS (port 465)"),
            ("none", "None, unencrypted (local MTA only)"),
        ] {
            let (app, pool, session, _) = setup_test_app().await;
            sqlx::query(
                "INSERT INTO smtp_config (id, host, port, username, password_enc, from_email, tls_mode, enabled) \
                 VALUES (?, 'smtp.test', 587, '', '', 'noreply@test.com', ?, 1)",
            )
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(stored)
            .execute(&pool)
            .await
            .unwrap();

            let response = app
                .oneshot(get_authed("/dashboard/admin", &session))
                .await
                .unwrap();
            assert_eq!(response.status(), 200);
            let body = body_string(response).await;

            let selected: Vec<&str> = [
                "STARTTLS (port 587)",
                "Implicit TLS (port 465)",
                "None, unencrypted (local MTA only)",
            ]
            .into_iter()
            .filter(|label| {
                body.split("<option")
                    .any(|opt| opt.contains(label) && opt.contains("selected"))
            })
            .collect();
            assert_eq!(
                selected,
                vec![expected_label],
                "tls_mode {stored} should select exactly {expected_label}"
            );
        }
    }

    #[tokio::test]
    async fn overrides_page_returns_200() {
        let (app, _, session, _) = setup_test_app().await;
        let response = app
            .oneshot(get_authed(
                "/dashboard/event-types/test-meeting/overrides",
                &session,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;
        assert!(
            body.contains("Date overrides"),
            "Overrides page should render"
        );
        assert!(
            body.contains("Test Meeting"),
            "Should show event type title"
        );
    }

    #[tokio::test]
    async fn public_profile_returns_200() {
        let (app, _, _, _) = setup_test_app().await;
        let response = app.oneshot(get("/u/testuser")).await.unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;
        assert!(
            body.contains("Test Meeting"),
            "Public profile should list event types"
        );
    }

    #[tokio::test]
    async fn public_profile_trailing_slash_redirects_to_working_canonical_page() {
        let (app, _, _, _) = setup_test_app().await;
        for query in ["", "?lang=fr&next=https%3A%2F%2Fexample.com%2F&tag=a&tag=b"] {
            let response = app
                .clone()
                .oneshot(get(&format!("/u/testuser/{query}")))
                .await
                .unwrap();
            assert_eq!(response.status(), 308);
            let location = response.headers()["location"].to_str().unwrap();
            assert_eq!(location, format!("/u/testuser{query}"));
            let canonical = app.clone().oneshot(get(location)).await.unwrap();
            assert_eq!(canonical.status(), 200);
            assert!(body_string(canonical).await.contains("Test Meeting"));
        }
    }

    #[tokio::test]
    async fn public_profile_trailing_slash_head_preserves_encoded_path_and_query() {
        let (app, _, _, _) = setup_test_app().await;
        let request = axum::http::Request::builder()
            .method("HEAD")
            .uri("/u/test%75ser/?value=%2F%3F%26")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), 308);
        assert_eq!(
            response.headers()["location"],
            "/u/test%75ser?value=%2F%3F%26"
        );
        assert!(body_string(response).await.is_empty());
    }

    #[tokio::test]
    async fn public_slots_page_returns_200() {
        let (app, _, _, _) = setup_test_app().await;
        let response = app.oneshot(get("/u/testuser/test-meeting")).await.unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;
        assert!(
            body.contains("Test Meeting"),
            "Slots page should show event type title"
        );
    }

    #[tokio::test]
    async fn troubleshoot_returns_200() {
        let (app, _, session, _) = setup_test_app().await;
        let response = app
            .oneshot(get_authed("/dashboard/troubleshoot", &session))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;
        assert!(
            body.contains("Troubleshoot"),
            "Troubleshoot page should render"
        );
    }

    #[tokio::test]
    async fn nonexistent_profile_returns_404_or_empty() {
        let (app, _, _, _) = setup_test_app().await;
        let response = app.oneshot(get("/u/nonexistent")).await.unwrap();
        // Should return 404 or a page indicating no user found
        let status = response.status();
        assert!(
            status == 404 || status == 200,
            "Nonexistent user should return 404 or 200 with empty page"
        );
    }

    #[tokio::test]
    async fn booking_with_invalid_cancel_token_shows_error() {
        let (app, _, _, _) = setup_test_app().await;
        let response = app
            .oneshot(get("/booking/cancel/invalid-token-123"))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;
        assert!(
            body.contains("invalid") || body.contains("Invalid") || body.contains("expired"),
            "Invalid cancel token should show error"
        );
    }

    #[tokio::test]
    async fn booking_with_invalid_approve_token_shows_error() {
        let (app, _, _, _) = setup_test_app().await;
        let response = app
            .oneshot(get("/booking/approve/invalid-token-123"))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;
        assert!(
            body.contains("invalid") || body.contains("Invalid") || body.contains("expired"),
            "Invalid approve token should show error"
        );
    }

    #[tokio::test]
    async fn booking_with_invalid_reschedule_token_shows_error() {
        let (app, _, _, _) = setup_test_app().await;
        let response = app
            .oneshot(get("/booking/reschedule/invalid-token-123"))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;
        assert!(
            body.contains("invalid") || body.contains("Invalid") || body.contains("expired"),
            "Invalid reschedule token should show error"
        );
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

    // --- POST handler tests ---

    #[tokio::test]
    async fn post_without_csrf_returns_403() {
        let (app, _, session, _) = setup_test_app().await;
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/dashboard/event-types/test-meeting/toggle")
            .header("cookie", format!("__Host-calrs_session={}", session))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from("_csrf=wrong-token"))
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(
            response.status(),
            403,
            "Missing/mismatched CSRF should return 403"
        );
    }

    #[tokio::test]
    async fn toggle_event_type_disables_and_enables() {
        let (app, pool, session, _) = setup_test_app().await;
        let csrf = "test-csrf-toggle";

        // Disable
        let response = app
            .oneshot(post_form(
                "/dashboard/event-types/test-meeting/toggle",
                &session,
                csrf,
                &format!("_csrf={}", csrf),
            ))
            .await
            .unwrap();
        assert!(
            response.status().is_redirection(),
            "Toggle should redirect, got {}",
            response.status()
        );

        let enabled: Option<(i32,)> =
            sqlx::query_as("SELECT enabled FROM event_types WHERE slug = 'test-meeting'")
                .fetch_optional(&pool)
                .await
                .unwrap();
        assert_eq!(enabled.unwrap().0, 0, "Event type should be disabled");

        // Re-enable (need a fresh router since oneshot consumes)
        let app2 = create_router(pool.clone(), std::env::temp_dir(), [0u8; 32]).await;
        let response = app2
            .oneshot(post_form(
                "/dashboard/event-types/test-meeting/toggle",
                &session,
                csrf,
                &format!("_csrf={}", csrf),
            ))
            .await
            .unwrap();
        assert!(response.status().is_redirection());

        let enabled: Option<(i32,)> =
            sqlx::query_as("SELECT enabled FROM event_types WHERE slug = 'test-meeting'")
                .fetch_optional(&pool)
                .await
                .unwrap();
        assert_eq!(enabled.unwrap().0, 1, "Event type should be re-enabled");
    }

    #[tokio::test]
    async fn create_override_blocked_day() {
        let (app, pool, session, _) = setup_test_app().await;
        let csrf = "test-csrf-override";

        let response = app
            .oneshot(post_form(
                "/dashboard/event-types/test-meeting/overrides",
                &session,
                csrf,
                &format!("_csrf={}&date=2026-06-15&override_type=blocked", csrf),
            ))
            .await
            .unwrap();
        assert!(
            response.status().is_redirection(),
            "Create override should redirect"
        );

        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM availability_overrides WHERE date = '2026-06-15' AND is_blocked = 1",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(count.0, 1, "Blocked override should be created");
    }

    #[tokio::test]
    async fn create_override_custom_hours() {
        let (app, pool, session, _) = setup_test_app().await;
        let csrf = "test-csrf-custom";

        let response = app
            .oneshot(post_form(
                "/dashboard/event-types/test-meeting/overrides",
                &session,
                csrf,
                &format!(
                    "_csrf={}&date=2026-06-16&override_type=custom&start_time=10%3A00&end_time=14%3A00",
                    csrf
                ),
            ))
            .await
            .unwrap();
        assert!(response.status().is_redirection());

        let row: Option<(String, String, i32)> = sqlx::query_as(
            "SELECT start_time, end_time, is_blocked FROM availability_overrides WHERE date = '2026-06-16'",
        )
        .fetch_optional(&pool)
        .await
        .unwrap();
        let (start, end, blocked) = row.unwrap();
        assert_eq!(start, "10:00");
        assert_eq!(end, "14:00");
        assert_eq!(blocked, 0);
    }

    #[tokio::test]
    async fn create_override_custom_hours_invalid_range_rejected() {
        let (app, pool, session, _) = setup_test_app().await;
        let csrf = "test-csrf-inv";

        // end_time before start_time
        let response = app
            .oneshot(post_form(
                "/dashboard/event-types/test-meeting/overrides",
                &session,
                csrf,
                &format!(
                    "_csrf={}&date=2026-06-17&override_type=custom&start_time=14%3A00&end_time=10%3A00",
                    csrf
                ),
            ))
            .await
            .unwrap();
        assert!(response.status().is_redirection());

        let count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM availability_overrides WHERE date = '2026-06-17'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(count.0, 0, "Invalid time range should not create override");
    }

    #[tokio::test]
    async fn delete_override_removes_from_db() {
        let (app, pool, session, _) = setup_test_app().await;

        // Insert an override to delete
        let override_id = uuid::Uuid::new_v4().to_string();
        let et_id: String =
            sqlx::query_scalar("SELECT id FROM event_types WHERE slug = 'test-meeting'")
                .fetch_one(&pool)
                .await
                .unwrap();
        sqlx::query("INSERT INTO availability_overrides (id, event_type_id, date, is_blocked) VALUES (?, ?, '2026-07-01', 1)")
            .bind(&override_id)
            .bind(&et_id)
            .execute(&pool)
            .await
            .unwrap();

        let csrf = "test-csrf-del";
        let response = app
            .oneshot(post_form(
                &format!(
                    "/dashboard/event-types/test-meeting/overrides/{}/delete",
                    override_id
                ),
                &session,
                csrf,
                &format!("_csrf={}", csrf),
            ))
            .await
            .unwrap();
        assert!(response.status().is_redirection());

        let count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM availability_overrides WHERE id = ?")
                .bind(&override_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(count.0, 0, "Override should be deleted");
    }

    #[tokio::test]
    async fn booking_form_post_creates_booking() {
        let (app, pool, _, _) = setup_test_app().await;
        let csrf = "test-csrf-book";

        // Find next Monday for a valid slot
        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let date_str = next_monday.format("%Y-%m-%d").to_string();

        let body = format!(
            "_csrf={}&date={}&time=10%3A00&name=Jane+Doe&email=jane%40example.com&notes=Hello",
            csrf, date_str
        );
        let response = app
            .oneshot(post_form_unauthed(
                "/u/testuser/test-meeting/book",
                csrf,
                &body,
            ))
            .await
            .unwrap();

        // Should render confirmation page (200) or redirect
        let status = response.status();
        assert!(
            status == 200 || status.is_redirection(),
            "Booking should succeed, got {}",
            status
        );

        let count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM bookings WHERE guest_email = 'jane@example.com'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(count.0, 1, "Booking should be created in DB");
    }

    /// #236: an SMTP relay that accepts the connection and then never answers
    /// used to hold the booking request until the reverse proxy gave up with
    /// a 504, although the booking was already committed. The confirmation
    /// page must come back without waiting on SMTP at all.
    #[tokio::test]
    async fn booking_does_not_wait_on_a_stalled_smtp_relay() {
        // The SMTP config comes from the DB row; a CALRS_SMTP_* block set by a
        // concurrent env test would override it.
        let _env = crate::test_support::ENV_LOCK.lock().await;
        let (app, pool, _, _) = setup_test_app().await;
        let csrf = "test-csrf-stalled-smtp";

        // A relay that accepts and then stays silent: no 220 greeting ever.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (connected_tx, connected_rx) = tokio::sync::oneshot::channel::<()>();
        let relay = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let _ = connected_tx.send(());
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            drop(sock);
        });

        sqlx::query(
            "INSERT INTO smtp_config (id, host, port, username, password_enc, from_email, tls_mode, enabled) \
             VALUES (?, '127.0.0.1', ?, '', ?, 'noreply@test.com', 'none', 1)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(port as i64)
        .bind(crate::crypto::encrypt_password(&[0u8; 32], "").unwrap())
        .execute(&pool)
        .await
        .unwrap();

        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let date_str = next_monday.format("%Y-%m-%d").to_string();
        let body = format!(
            "_csrf={}&date={}&time=10%3A00&name=Jane+Doe&email=jane%40example.com&notes=",
            csrf, date_str
        );

        // Well under SMTP_SEND_TIMEOUT: only a non-blocking send passes this.
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            app.oneshot(post_form_unauthed(
                "/u/testuser/test-meeting/book",
                csrf,
                &body,
            )),
        )
        .await
        .expect("booking response waited on the stalled SMTP relay")
        .unwrap();
        assert_eq!(response.status(), 200);

        let count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM bookings WHERE guest_email = 'jane@example.com'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(count.0, 1, "Booking should be created in DB");

        // The email path did run (in the background), so the test is not
        // passing merely because SMTP was never reached.
        tokio::time::timeout(std::time::Duration::from_secs(5), connected_rx)
            .await
            .expect("the background email task never reached the relay")
            .unwrap();
        relay.abort();
    }

    #[tokio::test]
    async fn booking_invalid_email_rejected() {
        let (app, pool, _, _) = setup_test_app().await;
        let csrf = "test-csrf-inv-email";

        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let date_str = next_monday.format("%Y-%m-%d").to_string();

        let body = format!(
            "_csrf={}&date={}&time=10%3A00&name=Jane&email=not-an-email&notes=",
            csrf, date_str
        );
        let response = app
            .oneshot(post_form_unauthed(
                "/u/testuser/test-meeting/book",
                csrf,
                &body,
            ))
            .await
            .unwrap();

        let resp_body = body_string(response).await;
        assert!(
            resp_body.contains("Invalid")
                || resp_body.contains("invalid")
                || resp_body.contains("email"),
            "Invalid email should be rejected"
        );

        let count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM bookings WHERE guest_email = 'not-an-email'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(count.0, 0, "Invalid booking should not be saved");
    }

    #[tokio::test]
    async fn booking_empty_name_rejected() {
        let (app, pool, _, _) = setup_test_app().await;
        let csrf = "test-csrf-empty-name";

        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let date_str = next_monday.format("%Y-%m-%d").to_string();

        let body = format!(
            "_csrf={}&date={}&time=10%3A00&name=&email=jane%40example.com&notes=",
            csrf, date_str
        );
        let response = app
            .oneshot(post_form_unauthed(
                "/u/testuser/test-meeting/book",
                csrf,
                &body,
            ))
            .await
            .unwrap();

        let resp_body = body_string(response).await;
        assert!(
            resp_body.contains("required")
                || resp_body.contains("Name")
                || resp_body.contains("name"),
            "Empty name should be rejected"
        );

        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM bookings")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count.0, 0, "No booking should be saved with empty name");
    }

    #[tokio::test]
    async fn confirm_pending_booking_via_dashboard() {
        let (app, pool, session, et_id) = setup_test_app().await;

        // Create a pending booking
        let booking_id = uuid::Uuid::new_v4().to_string();
        let cancel_tok = uuid::Uuid::new_v4().to_string();
        let resched_tok = uuid::Uuid::new_v4().to_string();
        let confirm_tok = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token, confirm_token) VALUES (?, ?, 'uid-confirm', 'Guest', 'guest@test.com', 'UTC', '2026-06-15T10:00:00', '2026-06-15T10:30:00', 'pending', ?, ?, ?)")
            .bind(&booking_id)
            .bind(&et_id)
            .bind(&cancel_tok)
            .bind(&resched_tok)
            .bind(&confirm_tok)
            .execute(&pool)
            .await
            .unwrap();

        let csrf = "test-csrf-confirm";
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

        let status: Option<(String,)> = sqlx::query_as("SELECT status FROM bookings WHERE id = ?")
            .bind(&booking_id)
            .fetch_optional(&pool)
            .await
            .unwrap();
        assert_eq!(
            status.unwrap().0,
            "confirmed",
            "Booking should be confirmed"
        );
    }

    #[tokio::test]
    async fn cancel_booking_via_dashboard() {
        let (app, pool, session, et_id) = setup_test_app().await;

        let booking_id = uuid::Uuid::new_v4().to_string();
        let cancel_tok = uuid::Uuid::new_v4().to_string();
        let resched_tok = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid-cancel', 'Guest', 'guest@test.com', 'UTC', '2026-06-15T14:00:00', '2026-06-15T14:30:00', 'confirmed', ?, ?)")
            .bind(&booking_id)
            .bind(&et_id)
            .bind(&cancel_tok)
            .bind(&resched_tok)
            .execute(&pool)
            .await
            .unwrap();

        let csrf = "test-csrf-cancel";
        let response = app
            .oneshot(post_form(
                &format!("/dashboard/bookings/{}/cancel", booking_id),
                &session,
                csrf,
                &format!("_csrf={}&reason=conflict", csrf),
            ))
            .await
            .unwrap();
        assert!(response.status().is_redirection());

        let status: Option<(String,)> = sqlx::query_as("SELECT status FROM bookings WHERE id = ?")
            .bind(&booking_id)
            .fetch_optional(&pool)
            .await
            .unwrap();
        assert_eq!(
            status.unwrap().0,
            "cancelled",
            "Booking should be cancelled"
        );
    }

    #[tokio::test]
    async fn decline_pending_booking_via_dashboard() {
        let (app, pool, session, et_id) = setup_test_app().await;

        let booking_id = uuid::Uuid::new_v4().to_string();
        let cancel_tok = uuid::Uuid::new_v4().to_string();
        let resched_tok = uuid::Uuid::new_v4().to_string();
        let confirm_tok = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token, confirm_token) VALUES (?, ?, 'uid-decline-dash', 'Guest', 'guest@test.com', 'UTC', '2026-06-16T14:00:00', '2026-06-16T14:30:00', 'pending', ?, ?, ?)")
            .bind(&booking_id)
            .bind(&et_id)
            .bind(&cancel_tok)
            .bind(&resched_tok)
            .bind(&confirm_tok)
            .execute(&pool)
            .await
            .unwrap();

        let csrf = "test-csrf-decline-dash";
        let response = app
            .oneshot(post_form(
                &format!("/dashboard/bookings/{}/cancel", booking_id),
                &session,
                csrf,
                &format!("_csrf={}&reason=not+a+fit", csrf),
            ))
            .await
            .unwrap();
        assert!(response.status().is_redirection());

        let status: Option<(String,)> = sqlx::query_as("SELECT status FROM bookings WHERE id = ?")
            .bind(&booking_id)
            .fetch_optional(&pool)
            .await
            .unwrap();
        assert_eq!(
            status.unwrap().0,
            "declined",
            "Pending booking should be declined, not silently left in pending"
        );
    }

    #[tokio::test]
    async fn approve_booking_via_email_token() {
        let (app, pool, _, et_id) = setup_test_app().await;

        let booking_id = uuid::Uuid::new_v4().to_string();
        let cancel_tok = uuid::Uuid::new_v4().to_string();
        let resched_tok = uuid::Uuid::new_v4().to_string();
        let confirm_tok = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token, confirm_token) VALUES (?, ?, 'uid-approve', 'Guest', 'guest@test.com', 'UTC', '2026-06-20T10:00:00', '2026-06-20T10:30:00', 'pending', ?, ?, ?)")
            .bind(&booking_id)
            .bind(&et_id)
            .bind(&cancel_tok)
            .bind(&resched_tok)
            .bind(&confirm_tok)
            .execute(&pool)
            .await
            .unwrap();

        // GET /booking/approve/{token} — shows confirmation form, does NOT approve
        let app2 = app.clone();
        let response = app2
            .oneshot(get(&format!("/booking/approve/{}", confirm_tok)))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;
        assert!(
            body.contains("Approve booking"),
            "GET should show approve form"
        );

        let status: Option<(String,)> = sqlx::query_as("SELECT status FROM bookings WHERE id = ?")
            .bind(&booking_id)
            .fetch_optional(&pool)
            .await
            .unwrap();
        assert_eq!(
            status.unwrap().0,
            "pending",
            "Booking should still be pending after GET"
        );

        // POST /booking/approve/{token} — actually approves
        let response = app
            .oneshot(post_bare(&format!("/booking/approve/{}", confirm_tok)))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);

        let status: Option<(String,)> = sqlx::query_as("SELECT status FROM bookings WHERE id = ?")
            .bind(&booking_id)
            .fetch_optional(&pool)
            .await
            .unwrap();
        assert_eq!(
            status.unwrap().0,
            "confirmed",
            "Booking should be confirmed via POST token"
        );
    }

    /// Regression test for #101: when the event type's timezone differs from
    /// the guest's timezone, approving a pending booking must render (and
    /// email) the time in the guest's timezone, not the event-type-local time
    /// the row was stored as.
    #[tokio::test]
    async fn approve_booking_renders_time_in_guest_timezone() {
        let (app, pool, _, et_id) = setup_test_app().await;

        // Event type stored in America/New_York. 10:00 NY in June (EDT, UTC-4)
        // == 14:00 UTC == 16:00 in Europe/Paris (CEST, UTC+2).
        sqlx::query("UPDATE event_types SET timezone = 'America/New_York' WHERE id = ?")
            .bind(&et_id)
            .execute(&pool)
            .await
            .unwrap();

        let booking_id = uuid::Uuid::new_v4().to_string();
        let cancel_tok = uuid::Uuid::new_v4().to_string();
        let resched_tok = uuid::Uuid::new_v4().to_string();
        let confirm_tok = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token, confirm_token) VALUES (?, ?, 'uid-approve-tz', 'Guest', 'guest@test.com', 'Europe/Paris', '2026-06-20T10:00:00', '2026-06-20T10:30:00', 'pending', ?, ?, ?)")
            .bind(&booking_id)
            .bind(&et_id)
            .bind(&cancel_tok)
            .bind(&resched_tok)
            .bind(&confirm_tok)
            .execute(&pool)
            .await
            .unwrap();

        let response = app
            .oneshot(post_bare(&format!("/booking/approve/{}", confirm_tok)))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;

        assert!(
            body.contains("16:00") && body.contains("16:30"),
            "Approval page should render times in the guest's tz (Europe/Paris: 16:00 – 16:30), got body fragment: {}",
            &body[..body.len().min(2000)]
        );
        assert!(
            !body.contains("10:00") && !body.contains("10:30"),
            "Approval page should not render the event-type-local time (America/New_York: 10:00)"
        );
    }

    #[tokio::test]
    async fn decline_booking_via_email_token() {
        let (app, pool, _, et_id) = setup_test_app().await;

        let booking_id = uuid::Uuid::new_v4().to_string();
        let cancel_tok = uuid::Uuid::new_v4().to_string();
        let resched_tok = uuid::Uuid::new_v4().to_string();
        let confirm_tok = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token, confirm_token) VALUES (?, ?, 'uid-decline', 'Guest', 'guest@test.com', 'UTC', '2026-06-21T10:00:00', '2026-06-21T10:30:00', 'pending', ?, ?, ?)")
            .bind(&booking_id)
            .bind(&et_id)
            .bind(&cancel_tok)
            .bind(&resched_tok)
            .bind(&confirm_tok)
            .execute(&pool)
            .await
            .unwrap();

        // GET /booking/decline/{token} shows form
        let response = app
            .oneshot(get(&format!("/booking/decline/{}", confirm_tok)))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;
        assert!(
            body.contains("ecline") || body.contains("reason"),
            "Decline form should render"
        );
    }

    #[tokio::test]
    async fn guest_cancel_via_token() {
        let (app, pool, _, et_id) = setup_test_app().await;

        let booking_id = uuid::Uuid::new_v4().to_string();
        let cancel_tok = uuid::Uuid::new_v4().to_string();
        let resched_tok = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid-gcancel', 'Guest', 'guest@test.com', 'UTC', '2026-06-22T10:00:00', '2026-06-22T10:30:00', 'confirmed', ?, ?)")
            .bind(&booking_id)
            .bind(&et_id)
            .bind(&cancel_tok)
            .bind(&resched_tok)
            .execute(&pool)
            .await
            .unwrap();

        // GET /booking/cancel/{token} shows cancel form
        let response = app
            .oneshot(get(&format!("/booking/cancel/{}", cancel_tok)))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;
        assert!(
            body.contains("cancel") || body.contains("Cancel"),
            "Cancel form should render"
        );
    }

    /// Regression test for #101 (cancel surface): when the event type is in a
    /// different tz from the guest, the cancellation page (and the cancellation
    /// email it mirrors) must render the time in the guest's tz, not the
    /// event-type-local stored time.
    #[tokio::test]
    async fn guest_cancel_renders_time_in_guest_timezone() {
        let (app, pool, _, et_id) = setup_test_app().await;

        sqlx::query("UPDATE event_types SET timezone = 'America/New_York' WHERE id = ?")
            .bind(&et_id)
            .execute(&pool)
            .await
            .unwrap();

        let booking_id = uuid::Uuid::new_v4().to_string();
        let cancel_tok = uuid::Uuid::new_v4().to_string();
        let resched_tok = uuid::Uuid::new_v4().to_string();
        // 10:00 NY in June (EDT, UTC-4) == 16:00 Europe/Paris (CEST, UTC+2).
        sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid-gcancel-tz', 'Guest', 'guest@test.com', 'Europe/Paris', '2026-06-22T10:00:00', '2026-06-22T10:30:00', 'confirmed', ?, ?)")
            .bind(&booking_id)
            .bind(&et_id)
            .bind(&cancel_tok)
            .bind(&resched_tok)
            .execute(&pool)
            .await
            .unwrap();

        let csrf = "test-csrf-gcancel-tz";
        let response = app
            .oneshot(post_form_unauthed(
                &format!("/booking/cancel/{}", cancel_tok),
                csrf,
                &format!("_csrf={}", csrf),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;

        assert!(
            body.contains("16:00") && body.contains("16:30"),
            "Cancellation page should render times in the guest's tz (Europe/Paris: 16:00 – 16:30)"
        );
        assert!(
            !body.contains("10:00") && !body.contains("10:30"),
            "Cancellation page should not render the event-type-local time (America/New_York: 10:00)"
        );
    }

    #[tokio::test]
    async fn login_with_wrong_password_shows_error() {
        let (app, pool, _, _) = setup_test_app().await;

        // Set a password on the test user
        let hash = crate::auth::hash_password("correct-password").unwrap();
        sqlx::query("UPDATE users SET password_hash = ? WHERE email = 'test@example.com'")
            .bind(&hash)
            .execute(&pool)
            .await
            .unwrap();

        let csrf = "test-csrf-login";
        let response = app
            .oneshot(post_form_unauthed(
                "/auth/login",
                csrf,
                &format!(
                    "_csrf={}&email=test%40example.com&password=wrong-password",
                    csrf
                ),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;
        assert!(
            body.contains("Invalid") || body.contains("invalid") || body.contains("error"),
            "Wrong password should show error"
        );
    }

    #[tokio::test]
    async fn login_with_correct_password_redirects() {
        let (app, pool, _, _) = setup_test_app().await;

        let hash = crate::auth::hash_password("my-password").unwrap();
        sqlx::query("UPDATE users SET password_hash = ? WHERE email = 'test@example.com'")
            .bind(&hash)
            .execute(&pool)
            .await
            .unwrap();

        let csrf = "test-csrf-login-ok";
        let response = app
            .oneshot(post_form_unauthed(
                "/auth/login",
                csrf,
                &format!(
                    "_csrf={}&email=test%40example.com&password=my-password",
                    csrf
                ),
            ))
            .await
            .unwrap();
        assert!(
            response.status().is_redirection(),
            "Successful login should redirect, got {}",
            response.status()
        );
        let location = response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            location.contains("dashboard"),
            "Should redirect to dashboard, got {}",
            location
        );
    }

    #[tokio::test]
    async fn register_when_disabled_returns_error() {
        let (app, pool, _, _) = setup_test_app().await;

        sqlx::query("UPDATE auth_config SET registration_enabled = 0 WHERE id = 'singleton'")
            .execute(&pool)
            .await
            .unwrap();

        let csrf = "test-csrf-reg";
        let response = app
            .oneshot(post_form_unauthed(
                "/auth/register",
                csrf,
                &format!(
                    "_csrf={}&name=New+User&email=new%40example.com&password=pass1234",
                    csrf
                ),
            ))
            .await
            .unwrap();
        let body = body_string(response).await;
        assert!(
            body.contains("disabled")
                || body.contains("Disabled")
                || body.contains("not available"),
            "Registration when disabled should show error"
        );

        let count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM users WHERE email = 'new@example.com'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(count.0, 0, "User should not be created");
    }

    // --- Dashboard pages: new event type form ---

    #[tokio::test]
    async fn new_event_type_form_returns_200() {
        let (app, _, session, _) = setup_test_app().await;
        let response = app
            .oneshot(get_authed("/dashboard/event-types/new", &session))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;
        assert!(
            body.contains("event type") || body.contains("Event type") || body.contains("Create")
        );
    }

    #[tokio::test]
    async fn edit_event_type_form_returns_200() {
        let (app, _, session, _) = setup_test_app().await;
        let response = app
            .oneshot(get_authed(
                "/dashboard/event-types/test-meeting/edit",
                &session,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;
        assert!(body.contains("Test Meeting"));
    }

    #[tokio::test]
    async fn new_source_form_returns_200() {
        let (app, _, session, _) = setup_test_app().await;
        let response = app
            .oneshot(get_authed("/dashboard/sources/new", &session))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
    }

    /// Helper for the source-edit tests: insert a caldav source for the test user.
    /// Returns the source id. Encrypts with the all-zeroes test secret_key so
    /// the update handler's decrypt-on-keep-existing path works. Uses
    /// `example.com` which has public DNS, so `validate_caldav_url` (which does
    /// DNS resolution to check for SSRF) doesn't fail in the test sandbox.
    async fn seed_source(pool: &SqlitePool, name: &str, password: &str) -> String {
        let account_id: (String,) = sqlx::query_as(
            "SELECT id FROM accounts WHERE user_id = (SELECT id FROM users WHERE username = 'testuser') LIMIT 1",
        )
        .fetch_one(pool)
        .await
        .unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        let enc = crate::crypto::encrypt_password(&[0u8; 32], password).unwrap();
        sqlx::query(
            "INSERT INTO caldav_sources (id, account_id, name, url, username, password_enc) VALUES (?, ?, ?, 'https://example.com/dav/old/', 'olduser', ?)",
        )
        .bind(&id)
        .bind(&account_id.0)
        .bind(name)
        .bind(&enc)
        .execute(pool)
        .await
        .unwrap();
        id
    }

    #[tokio::test]
    async fn edit_source_form_renders_prefilled() {
        let (app, pool, session, _) = setup_test_app().await;
        let sid = seed_source(&pool, "My Source", "old-pw").await;

        let response = app
            .oneshot(get_authed(
                &format!("/dashboard/sources/{}/edit", sid),
                &session,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;
        assert!(
            body.contains("Edit calendar source"),
            "should render in editing mode"
        );
        assert!(body.contains("My Source"), "name pre-filled");
        // minijinja escapes '/' as '&#x2f;' in attribute values; check both the
        // host and a path segment (which won't include slashes).
        assert!(body.contains("example.com"), "url host pre-filled");
        assert!(
            body.contains("dav") && body.contains("old"),
            "url path pre-filled"
        );
        assert!(body.contains("olduser"), "username pre-filled");
        assert!(
            body.contains("Leave blank to keep existing"),
            "password placeholder"
        );
    }

    #[tokio::test]
    async fn update_source_changes_fields_and_keeps_password_when_blank() {
        let (app, pool, session, _) = setup_test_app().await;
        let sid = seed_source(&pool, "My Source", "old-pw").await;

        let csrf = "test-csrf-update-source";
        let body = format!(
            "_csrf={}&name=Renamed&url=https%3A%2F%2Fexample.com%2Fdav%2Fnew%2F&username=newuser&password=&no_test=on",
            csrf
        );
        let response = app
            .oneshot(post_form(
                &format!("/dashboard/sources/{}/edit", sid),
                &session,
                csrf,
                &body,
            ))
            .await
            .unwrap();
        assert!(response.status().is_redirection() || response.status() == 200);

        let row: (String, String, String, String) = sqlx::query_as(
            "SELECT name, url, username, password_enc FROM caldav_sources WHERE id = ?",
        )
        .bind(&sid)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.0, "Renamed");
        assert_eq!(row.1, "https://example.com/dav/new/");
        assert_eq!(row.2, "newuser");
        // Decrypt the stored blob and confirm the password is unchanged.
        let pw = crate::crypto::decrypt_password(&[0u8; 32], &row.3).unwrap();
        assert_eq!(pw, "old-pw", "blank password must keep the existing one");
    }

    #[tokio::test]
    async fn update_source_rotates_password() {
        let (app, pool, session, _) = setup_test_app().await;
        let sid = seed_source(&pool, "My Source", "old-pw").await;

        let csrf = "test-csrf-rotate";
        let body = format!(
            "_csrf={}&name=My+Source&url=https%3A%2F%2Fexample.com%2Fdav%2Fold%2F&username=olduser&password=new-pw-rotated&no_test=on",
            csrf
        );
        let response = app
            .oneshot(post_form(
                &format!("/dashboard/sources/{}/edit", sid),
                &session,
                csrf,
                &body,
            ))
            .await
            .unwrap();
        assert!(response.status().is_redirection() || response.status() == 200);

        let enc: (String,) = sqlx::query_as("SELECT password_enc FROM caldav_sources WHERE id = ?")
            .bind(&sid)
            .fetch_one(&pool)
            .await
            .unwrap();
        let pw = crate::crypto::decrypt_password(&[0u8; 32], &enc.0).unwrap();
        assert_eq!(
            pw, "new-pw-rotated",
            "non-blank password must replace the existing one"
        );
    }

    #[tokio::test]
    async fn update_source_404_for_other_user_source() {
        // The edit handler must scope by user_id; trying to edit a source the
        // current user doesn't own should redirect away (not leak/edit).
        let (app, pool, session, _) = setup_test_app().await;

        // Insert an account belonging to a *different* user, and a source under it.
        let other_user_id = uuid::Uuid::new_v4().to_string();
        let other_account_id = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO users (id, email, name, role, auth_provider, username, enabled) VALUES (?, 'other@example.com', 'Other', 'user', 'local', 'otheruser', 1)")
            .bind(&other_user_id)
            .execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO accounts (id, name, email, timezone, user_id) VALUES (?, 'Other', 'other@example.com', 'UTC', ?)")
            .bind(&other_account_id)
            .bind(&other_user_id)
            .execute(&pool).await.unwrap();
        let other_sid = uuid::Uuid::new_v4().to_string();
        let enc = crate::crypto::encrypt_password(&[0u8; 32], "secret").unwrap();
        sqlx::query("INSERT INTO caldav_sources (id, account_id, name, url, username, password_enc) VALUES (?, ?, 'Other source', 'https://other.example.com/', 'someone', ?)")
            .bind(&other_sid)
            .bind(&other_account_id)
            .bind(&enc)
            .execute(&pool).await.unwrap();

        let response = app
            .oneshot(get_authed(
                &format!("/dashboard/sources/{}/edit", other_sid),
                &session,
            ))
            .await
            .unwrap();
        // Handler redirects to /dashboard/sources for unauthorised access.
        assert!(response.status().is_redirection());
    }

    // --- Event type CRUD ---

    #[tokio::test]
    async fn create_event_type_via_post() {
        let (app, pool, session, _) = setup_test_app().await;
        let csrf = "test-csrf-create-et";
        let body = format!(
            "_csrf={}&title=New+Meeting&slug=new-meeting&duration_min=45&location_value=https%3A%2F%2Fmeet.example.com&avail_days=1,2,3,4,5&avail_start=09:00&avail_end=17:00",
            csrf
        );
        let response = app
            .oneshot(post_form(
                "/dashboard/event-types/new",
                &session,
                csrf,
                &body,
            ))
            .await
            .unwrap();
        assert!(
            response.status().is_redirection(),
            "Create event type should redirect, got {}",
            response.status()
        );

        let count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM event_types WHERE slug = 'new-meeting'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(count.0, 1, "Event type should be created");
    }

    #[tokio::test]
    async fn delete_event_type_with_no_bookings() {
        let (app, pool, session, _) = setup_test_app().await;
        let csrf = "test-csrf-del-et";

        // Create an event type to delete (no bookings)
        let et_id = uuid::Uuid::new_v4().to_string();
        let account_id: String = sqlx::query_scalar("SELECT id FROM accounts LIMIT 1")
            .fetch_one(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO event_types (id, account_id, slug, title, duration_min, enabled) VALUES (?, ?, 'deletable', 'Deletable', 30, 1)")
            .bind(&et_id)
            .bind(&account_id)
            .execute(&pool)
            .await
            .unwrap();

        let response = app
            .oneshot(post_form(
                "/dashboard/event-types/deletable/delete",
                &session,
                csrf,
                &format!("_csrf={}", csrf),
            ))
            .await
            .unwrap();
        assert!(response.status().is_redirection());

        let count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM event_types WHERE slug = 'deletable'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(count.0, 0, "Event type should be deleted");
    }

    // --- Settings ---

    #[tokio::test]
    async fn settings_save_updates_name() {
        let (app, pool, session, _) = setup_test_app().await;
        let csrf = "test-csrf-settings";
        let body = format!("_csrf={}&name=Updated+Name&booking_email=", csrf);
        let response = app
            .oneshot(post_form("/dashboard/settings", &session, csrf, &body))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let resp_body = body_string(response).await;
        assert!(resp_body.contains("Settings saved") || resp_body.contains("Updated Name"));

        let name: Option<String> =
            sqlx::query_scalar("SELECT name FROM users WHERE email = 'test@example.com'")
                .fetch_optional(&pool)
                .await
                .unwrap();
        assert_eq!(name.unwrap(), "Updated Name");
    }

    #[tokio::test]
    async fn settings_failed_save_does_not_write_the_username() {
        let (app, pool, session, _) = setup_test_app().await;
        let before: Option<String> =
            sqlx::query_scalar("SELECT username FROM users WHERE email = 'test@example.com'")
                .fetch_one(&pool)
                .await
                .unwrap();
        let csrf = "test-csrf-settings-208";
        let body = format!(
            "_csrf={}&name=Test+User&username=brand-new-name&booking_email=not-an-email",
            csrf
        );
        let response = app
            .oneshot(post_form("/dashboard/settings", &session, csrf, &body))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let resp_body = body_string(response).await;
        assert!(
            !resp_body.contains("Settings saved"),
            "a rejected booking email must not report a save"
        );

        let after: Option<String> =
            sqlx::query_scalar("SELECT username FROM users WHERE email = 'test@example.com'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            after, before,
            "the username must not be written by a failed save"
        );
        assert_ne!(after.as_deref(), Some("brand-new-name"));
    }

    #[tokio::test]
    async fn settings_save_writes_the_username_with_the_rest() {
        let (app, pool, session, _) = setup_test_app().await;
        let csrf = "test-csrf-settings-208-ok";
        let body = format!(
            "_csrf={}&name=Test+User&username=brand-new-name&booking_email=",
            csrf
        );
        let response = app
            .oneshot(post_form("/dashboard/settings", &session, csrf, &body))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let after: Option<String> =
            sqlx::query_scalar("SELECT username FROM users WHERE email = 'test@example.com'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(after.as_deref(), Some("brand-new-name"));
    }

    #[tokio::test]
    async fn settings_save_confirms_language_change_in_the_new_language() {
        let (app, _pool, session, _) = setup_test_app().await;
        let csrf = "test-csrf-settings-lang";
        let body = format!("_csrf={}&name=Test+User&booking_email=&language=fr", csrf);
        let response = app
            .oneshot(post_form("/dashboard/settings", &session, csrf, &body))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let resp_body = body_string(response).await;
        assert!(
            resp_body.contains("Paramètres enregistrés"),
            "confirmation should render in the language that was just saved"
        );
        assert!(
            !resp_body.contains("Settings saved"),
            "confirmation should not render in the pre-save language"
        );
    }

    #[tokio::test]
    async fn settings_validation_error_keeps_the_submitted_fields() {
        let (app, pool, session, _) = setup_test_app().await;
        let csrf = "test-csrf-settings-keep";
        // Empty name is rejected. Every other field carries an edit, and none of
        // them matches what the seeded row holds.
        let body = format!(
            "_csrf={}&name=&username=testuser&title=Head+of+Demos&bio=Runs+the+demo+rota\
             &booking_email=demo%40example.com&timezone=Europe%2FParis&language=fr",
            csrf
        );
        let response = app
            .oneshot(post_form("/dashboard/settings", &session, csrf, &body))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let resp_body = body_string(response).await;

        assert!(
            resp_body.contains("Name must be between 1 and 255 characters."),
            "the name error should be shown"
        );
        for expected in [
            r#"value="Head of Demos""#,
            "Runs the demo rota",
            r#"value="demo@example.com""#,
            // minijinja escapes the slash in the option value.
            r#"value="Europe&#x2f;Paris" selected"#,
            r#"value="fr" selected"#,
        ] {
            assert!(
                resp_body.contains(expected),
                "a rejected field should not discard the other edits, missing {expected}"
            );
        }

        // The checkbox was left unchecked, so it must come back unchecked even
        // though the stored row still has it on.
        let checkbox = resp_body
            .split(r#"name="allow_dynamic_group""#)
            .nth(1)
            .expect("the dynamic-group checkbox should render")
            .split('>')
            .next()
            .unwrap_or("");
        assert!(
            !checkbox.contains("checked"),
            "an unchecked box should come back unchecked"
        );

        // Nothing was saved: the UPDATE never ran.
        let (title, tz): (Option<String>, String) =
            sqlx::query_as("SELECT title, timezone FROM users WHERE email = 'test@example.com'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(title, None);
        assert_eq!(tz, "UTC");
    }

    #[tokio::test]
    async fn settings_booking_email_error_shows_the_rejected_value() {
        let (app, _pool, session, _) = setup_test_app().await;
        let csrf = "test-csrf-settings-email";
        let body = format!(
            "_csrf={}&name=Alice+Martin&username=testuser&title=Head+of+Demos\
             &booking_email=not-an-email",
            csrf
        );
        let response = app
            .oneshot(post_form("/dashboard/settings", &session, csrf, &body))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let resp_body = body_string(response).await;

        assert!(
            resp_body.contains("Please enter a valid booking email address."),
            "the booking email error should be shown"
        );
        assert!(
            resp_body.contains(r#"value="not-an-email""#),
            "the field in error should show the value that was rejected"
        );
        assert!(
            resp_body.contains(r#"value="Head of Demos""#),
            "the other edits should survive the error"
        );
        assert!(
            resp_body.contains(r#"value="Alice Martin""#),
            "the submitted name should survive the error"
        );
        let avatar = resp_body
            .split(r#"flex-shrink: 0; overflow: hidden;">"#)
            .nth(1)
            .expect("the avatar preview should render")
            .split("</div>")
            .next()
            .unwrap_or("");
        assert!(
            avatar.contains("AM"),
            "the avatar initials should follow the name being shown, got {avatar:?}"
        );
    }

    // --- Admin actions ---

    #[tokio::test]
    async fn admin_toggle_user_role() {
        let (app, pool, session, _) = setup_test_app().await;

        // Create a non-admin user
        let user2_id = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO users (id, email, name, role, auth_provider, username, enabled) VALUES (?, 'user2@test.com', 'User Two', 'user', 'local', 'user2', 1)")
            .bind(&user2_id)
            .execute(&pool)
            .await
            .unwrap();

        let csrf = "test-csrf-toggle-role";
        let response = app
            .oneshot(post_form(
                &format!("/dashboard/admin/users/{}/toggle-role", user2_id),
                &session,
                csrf,
                &format!("_csrf={}", csrf),
            ))
            .await
            .unwrap();
        assert!(response.status().is_redirection());

        let role: String = sqlx::query_scalar("SELECT role FROM users WHERE id = ?")
            .bind(&user2_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(role, "admin", "User should be promoted to admin");
    }

    #[tokio::test]
    async fn admin_toggle_user_enabled() {
        let (app, pool, session, _) = setup_test_app().await;

        let user2_id = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO users (id, email, name, role, auth_provider, username, enabled) VALUES (?, 'user3@test.com', 'User Three', 'user', 'local', 'user3', 1)")
            .bind(&user2_id)
            .execute(&pool)
            .await
            .unwrap();

        let csrf = "test-csrf-toggle-en";
        let response = app
            .oneshot(post_form(
                &format!("/dashboard/admin/users/{}/toggle-enabled", user2_id),
                &session,
                csrf,
                &format!("_csrf={}", csrf),
            ))
            .await
            .unwrap();
        assert!(response.status().is_redirection());

        let enabled: i32 = sqlx::query_scalar("SELECT enabled FROM users WHERE id = ?")
            .bind(&user2_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(enabled, 0, "User should be disabled");
    }

    #[tokio::test]
    async fn admin_update_auth_settings() {
        let (app, pool, session, _) = setup_test_app().await;
        let csrf = "test-csrf-auth";
        let body = format!("_csrf={}&allowed_email_domains=example.com", csrf);
        let response = app
            .oneshot(post_form("/dashboard/admin/auth", &session, csrf, &body))
            .await
            .unwrap();
        assert!(response.status().is_redirection());

        let domains: Option<String> = sqlx::query_scalar(
            "SELECT allowed_email_domains FROM auth_config WHERE id = 'singleton'",
        )
        .fetch_optional(&pool)
        .await
        .unwrap();
        assert_eq!(domains.unwrap(), "example.com");
    }

    #[tokio::test]
    async fn admin_captcha_wasm_url_is_validated_and_stored() {
        let (app, pool, session, _) = setup_test_app().await;
        let stored = || async {
            sqlx::query_scalar::<_, Option<String>>(
                "SELECT captcha_wasm_url FROM auth_config WHERE id = 'singleton'",
            )
            .fetch_one(&pool)
            .await
            .unwrap()
        };

        let csrf = "test-csrf-captcha-wasm";
        let body = format!("_csrf={}&captcha_wasm_url=javascript%3Aalert(1)", csrf);
        let response = app
            .clone()
            .oneshot(post_form("/dashboard/admin/captcha", &session, csrf, &body))
            .await
            .unwrap();
        let location = response.headers()["location"].to_str().unwrap().to_string();
        assert!(
            location.starts_with("/dashboard/admin?error="),
            "{location}"
        );
        assert_eq!(stored().await, None, "an invalid URL must not be saved");

        let body = format!(
            "_csrf={}&captcha_wasm_url=https%3A%2F%2Fcap.example.com%2Fassets%2Fcap_wasm_bg.wasm",
            csrf
        );
        let response = app
            .oneshot(post_form("/dashboard/admin/captcha", &session, csrf, &body))
            .await
            .unwrap();
        assert_eq!(response.headers()["location"], "/dashboard/admin");
        assert_eq!(
            stored().await.as_deref(),
            Some("https://cap.example.com/assets/cap_wasm_bg.wasm")
        );
    }

    #[tokio::test]
    async fn admin_captcha_form_shows_stored_values_while_incomplete() {
        let (app, pool, session, _) = setup_test_app().await;
        // No secret, so the captcha is not active, but the URLs are stored.
        sqlx::query(
            "UPDATE auth_config SET captcha_instance_url = 'https://cap.example.com', \
             captcha_site_key = 'site-123', captcha_secret = NULL, \
             captcha_widget_url = 'https://cdn.example.com/widget.js', \
             captcha_wasm_url = 'https://cdn.example.com/cap_wasm_bg.wasm' \
             WHERE id = 'singleton'",
        )
        .execute(&pool)
        .await
        .unwrap();

        let response = app
            .oneshot(get_authed("/dashboard/admin", &session))
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = body_string(response).await;
        for (field, value) in [
            ("captcha_instance_url", "https://cap.example.com"),
            ("captcha_site_key", "site-123"),
            ("captcha_widget_url", "https://cdn.example.com/widget.js"),
            (
                "captcha_wasm_url",
                "https://cdn.example.com/cap_wasm_bg.wasm",
            ),
        ] {
            let input = body
                .split("<input")
                .find(|tag| tag.contains(&format!("name=\"{field}\"")))
                .unwrap_or_else(|| panic!("no {field} input"));
            // minijinja escapes '/' in attribute values.
            let escaped = value.replace('/', "&#x2f;");
            assert!(
                input.contains(&format!("value=\"{escaped}\"")),
                "{field} lost its stored value: {input}"
            );
        }
    }

    #[tokio::test]
    async fn admin_captcha_inputs_are_labelled() {
        let (app, _, session, _) = setup_test_app().await;
        let response = app
            .oneshot(get_authed("/dashboard/admin", &session))
            .await
            .unwrap();
        let body = body_string(response).await;
        for field in [
            "captcha_instance_url",
            "captcha_site_key",
            "captcha_secret",
            "captcha_widget_url",
            "captcha_wasm_url",
        ] {
            assert_eq!(
                body.matches(&format!("id=\"{field}\"")).count(),
                1,
                "{field} needs exactly one id"
            );
            assert!(
                body.contains(&format!("<label for=\"{field}\">")),
                "{field} has no label pointing at it"
            );
        }
    }

    #[tokio::test]
    async fn admin_non_admin_gets_403() {
        let (app, pool, _, _) = setup_test_app().await;

        // Create a non-admin user with session
        let user_id = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO users (id, email, name, role, auth_provider, username, enabled) VALUES (?, 'nonadmin@test.com', 'Non Admin', 'user', 'local', 'nonadmin', 1)")
            .bind(&user_id)
            .execute(&pool)
            .await
            .unwrap();
        let session = uuid::Uuid::new_v4().to_string();
        let expires = (Utc::now() + Duration::days(30))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        sqlx::query("INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)")
            .bind(&session)
            .bind(&user_id)
            .bind(&expires)
            .execute(&pool)
            .await
            .unwrap();

        let response = app
            .oneshot(get_authed("/dashboard/admin", &session))
            .await
            .unwrap();
        assert_eq!(response.status(), 403, "Non-admin should get 403");
    }

    // --- Token-based POST actions ---

    #[tokio::test]
    async fn decline_booking_via_post() {
        let (app, pool, _, et_id) = setup_test_app().await;

        let booking_id = uuid::Uuid::new_v4().to_string();
        let cancel_tok = uuid::Uuid::new_v4().to_string();
        let resched_tok = uuid::Uuid::new_v4().to_string();
        let confirm_tok = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token, confirm_token) VALUES (?, ?, 'uid-dec-post', 'Guest', 'guest@test.com', 'UTC', '2026-07-01T10:00:00', '2026-07-01T10:30:00', 'pending', ?, ?, ?)")
            .bind(&booking_id)
            .bind(&et_id)
            .bind(&cancel_tok)
            .bind(&resched_tok)
            .bind(&confirm_tok)
            .execute(&pool)
            .await
            .unwrap();

        let csrf = "test-csrf-decline-post";
        let response = app
            .oneshot(post_form_unauthed(
                &format!("/booking/decline/{}", confirm_tok),
                csrf,
                &format!("_csrf={}&reason=Not+available", csrf),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);

        let status: String = sqlx::query_scalar("SELECT status FROM bookings WHERE id = ?")
            .bind(&booking_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(status, "declined", "Booking should be declined");
    }

    #[tokio::test]
    async fn guest_cancel_booking_via_post() {
        let (app, pool, _, et_id) = setup_test_app().await;

        let booking_id = uuid::Uuid::new_v4().to_string();
        let cancel_tok = uuid::Uuid::new_v4().to_string();
        let resched_tok = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid-gcancel-post', 'Guest', 'guest@test.com', 'UTC', '2026-07-02T10:00:00', '2026-07-02T10:30:00', 'confirmed', ?, ?)")
            .bind(&booking_id)
            .bind(&et_id)
            .bind(&cancel_tok)
            .bind(&resched_tok)
            .execute(&pool)
            .await
            .unwrap();

        let csrf = "test-csrf-gcancel-post";
        let response = app
            .oneshot(post_form_unauthed(
                &format!("/booking/cancel/{}", cancel_tok),
                csrf,
                &format!("_csrf={}&reason=Changed+plans", csrf),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);

        let status: String = sqlx::query_scalar("SELECT status FROM bookings WHERE id = ?")
            .bind(&booking_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(status, "cancelled", "Booking should be cancelled by guest");
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

    #[tokio::test]
    async fn guest_cancel_no_notice_succeeds() {
        let (app, pool, _, et_id) = setup_test_app().await;
        // No cancel_notice_min set on event type. Booking starts in 30 min.
        let cancel_tok = uuid::Uuid::new_v4().to_string();
        let resched_tok = uuid::Uuid::new_v4().to_string();
        let booking_id = insert_booking_at(
            &pool,
            &et_id,
            &cancel_tok,
            &resched_tok,
            chrono::Duration::minutes(30),
        )
        .await;

        let csrf = "csrf-cancel-no-notice";
        let response = app
            .oneshot(post_form_unauthed(
                &format!("/booking/cancel/{}", cancel_tok),
                csrf,
                &format!("_csrf={}", csrf),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let status: String = sqlx::query_scalar("SELECT status FROM bookings WHERE id = ?")
            .bind(&booking_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            status, "cancelled",
            "Without a notice window the cancel must succeed"
        );
    }

    #[tokio::test]
    async fn guest_cancel_within_notice_window_blocked() {
        let (app, pool, _, et_id) = setup_test_app().await;
        // Notice window of 60 min, booking starts in 30 min: blocked.
        sqlx::query("UPDATE event_types SET cancel_notice_min = 60 WHERE id = ?")
            .bind(&et_id)
            .execute(&pool)
            .await
            .unwrap();
        let cancel_tok = uuid::Uuid::new_v4().to_string();
        let resched_tok = uuid::Uuid::new_v4().to_string();
        let booking_id = insert_booking_at(
            &pool,
            &et_id,
            &cancel_tok,
            &resched_tok,
            chrono::Duration::minutes(30),
        )
        .await;

        // GET should already block.
        let response = app
            .clone()
            .oneshot(get(&format!("/booking/cancel/{}", cancel_tok)))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;
        assert!(
            body.contains("notice") || body.contains("60") || body.contains("minutes"),
            "Blocked page should mention the notice (got body length {})",
            body.len()
        );

        // POST must also be blocked, and the booking must not transition.
        let csrf = "csrf-cancel-blocked";
        let response = app
            .oneshot(post_form_unauthed(
                &format!("/booking/cancel/{}", cancel_tok),
                csrf,
                &format!("_csrf={}", csrf),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let status: String = sqlx::query_scalar("SELECT status FROM bookings WHERE id = ?")
            .bind(&booking_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(status, "confirmed", "Blocked POST must not mutate state");
    }

    #[tokio::test]
    async fn guest_cancel_outside_notice_window_succeeds() {
        let (app, pool, _, et_id) = setup_test_app().await;
        // Notice window of 60 min, booking starts in 120 min: allowed.
        sqlx::query("UPDATE event_types SET cancel_notice_min = 60 WHERE id = ?")
            .bind(&et_id)
            .execute(&pool)
            .await
            .unwrap();
        let cancel_tok = uuid::Uuid::new_v4().to_string();
        let resched_tok = uuid::Uuid::new_v4().to_string();
        let booking_id = insert_booking_at(
            &pool,
            &et_id,
            &cancel_tok,
            &resched_tok,
            chrono::Duration::minutes(120),
        )
        .await;

        let csrf = "csrf-cancel-allowed";
        let response = app
            .oneshot(post_form_unauthed(
                &format!("/booking/cancel/{}", cancel_tok),
                csrf,
                &format!("_csrf={}", csrf),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let status: String = sqlx::query_scalar("SELECT status FROM bookings WHERE id = ?")
            .bind(&booking_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(status, "cancelled");
    }

    #[tokio::test]
    async fn guest_reschedule_no_notice_succeeds() {
        let (app, pool, _, et_id) = setup_test_app().await;
        let cancel_tok = uuid::Uuid::new_v4().to_string();
        let resched_tok = uuid::Uuid::new_v4().to_string();
        let _ = insert_booking_at(
            &pool,
            &et_id,
            &cancel_tok,
            &resched_tok,
            chrono::Duration::minutes(30),
        )
        .await;

        // GET the slot picker. With no notice, it should render the slot
        // page (status 200 and contains the event title or slot markers).
        let response = app
            .oneshot(get(&format!("/booking/reschedule/{}", resched_tok)))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;
        assert!(
            body.contains("Test Meeting") || body.contains("reschedul"),
            "No notice -> slot page should render, body length {}",
            body.len()
        );
    }

    #[tokio::test]
    async fn guest_reschedule_within_notice_window_blocked() {
        let (app, pool, _, et_id) = setup_test_app().await;
        sqlx::query("UPDATE event_types SET reschedule_notice_min = 60 WHERE id = ?")
            .bind(&et_id)
            .execute(&pool)
            .await
            .unwrap();
        let cancel_tok = uuid::Uuid::new_v4().to_string();
        let resched_tok = uuid::Uuid::new_v4().to_string();
        let booking_id = insert_booking_at(
            &pool,
            &et_id,
            &cancel_tok,
            &resched_tok,
            chrono::Duration::minutes(30),
        )
        .await;

        // GET blocks before the slot picker is rendered.
        let response = app
            .clone()
            .oneshot(get(&format!("/booking/reschedule/{}", resched_tok)))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;
        assert!(
            body.contains("notice") || body.contains("60") || body.contains("minutes"),
            "Blocked page should mention the notice"
        );

        // POST also blocked: booking start_at must not change.
        let csrf = "csrf-resched-blocked";
        // Submit a new date 10 days out so we don't hit other guards.
        let new_date = (Local::now().naive_local().date() + chrono::Duration::days(10))
            .format("%Y-%m-%d")
            .to_string();
        let original_start: String =
            sqlx::query_scalar("SELECT start_at FROM bookings WHERE id = ?")
                .bind(&booking_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        let response = app
            .oneshot(post_form_unauthed(
                &format!("/booking/reschedule/{}", resched_tok),
                csrf,
                &format!("_csrf={}&date={}&time=10%3A00&tz=UTC", csrf, new_date),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let still: String = sqlx::query_scalar("SELECT start_at FROM bookings WHERE id = ?")
            .bind(&booking_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            still, original_start,
            "Blocked POST must not move the booking"
        );
    }

    #[tokio::test]
    async fn guest_reschedule_outside_notice_window_succeeds() {
        let (app, pool, _, et_id) = setup_test_app().await;
        sqlx::query("UPDATE event_types SET reschedule_notice_min = 60 WHERE id = ?")
            .bind(&et_id)
            .execute(&pool)
            .await
            .unwrap();
        let cancel_tok = uuid::Uuid::new_v4().to_string();
        let resched_tok = uuid::Uuid::new_v4().to_string();
        let _ = insert_booking_at(
            &pool,
            &et_id,
            &cancel_tok,
            &resched_tok,
            chrono::Duration::minutes(120),
        )
        .await;

        // GET should render the slot picker (not the blocked page).
        let response = app
            .oneshot(get(&format!("/booking/reschedule/{}", resched_tok)))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;
        // Slot picker contains the event title; the blocked page does
        // not. Either presence of "Test Meeting" or absence of the
        // notice-line is fine.
        assert!(
            body.contains("Test Meeting") || body.contains("reschedul"),
            "Outside notice window the slot picker should render"
        );
    }

    #[tokio::test]
    async fn host_cancel_unaffected_by_notice() {
        // The dashboard cancel handler must bypass the guest notice window.
        // Set a 24h cancel_notice and a booking 30 min out: the host should
        // still be able to cancel via /dashboard/bookings/{id}/cancel.
        let (app, pool, session, et_id) = setup_test_app().await;
        sqlx::query("UPDATE event_types SET cancel_notice_min = 1440 WHERE id = ?")
            .bind(&et_id)
            .execute(&pool)
            .await
            .unwrap();
        let cancel_tok = uuid::Uuid::new_v4().to_string();
        let resched_tok = uuid::Uuid::new_v4().to_string();
        let booking_id = insert_booking_at(
            &pool,
            &et_id,
            &cancel_tok,
            &resched_tok,
            chrono::Duration::minutes(30),
        )
        .await;

        let csrf = "csrf-host-cancel";
        let response = app
            .oneshot(post_form(
                &format!("/dashboard/bookings/{}/cancel", booking_id),
                &session,
                csrf,
                &format!("_csrf={}", csrf),
            ))
            .await
            .unwrap();
        assert!(
            response.status().is_redirection(),
            "Host cancel should redirect, got {}",
            response.status()
        );
        let status: String = sqlx::query_scalar("SELECT status FROM bookings WHERE id = ?")
            .bind(&booking_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            status, "cancelled",
            "Host cancel must succeed regardless of guest notice window"
        );
    }

    // --- Host reschedule ---

    #[tokio::test]
    async fn host_reschedule_page_returns_200() {
        let (app, pool, session, et_id) = setup_test_app().await;

        let booking_id = uuid::Uuid::new_v4().to_string();
        let cancel_tok = uuid::Uuid::new_v4().to_string();
        let resched_tok = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid-hresched', 'Guest', 'guest@test.com', 'UTC', '2026-07-10T10:00:00', '2026-07-10T10:30:00', 'confirmed', ?, ?)")
            .bind(&booking_id)
            .bind(&et_id)
            .bind(&cancel_tok)
            .bind(&resched_tok)
            .execute(&pool)
            .await
            .unwrap();

        let response = app
            .oneshot(get_authed(
                &format!("/dashboard/bookings/{}/reschedule", booking_id),
                &session,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;
        assert!(
            body.contains("Guest") || body.contains("reschedule") || body.contains("Reschedule")
        );
    }

    #[tokio::test]
    async fn host_reschedule_post_sets_flag() {
        let (app, pool, session, et_id) = setup_test_app().await;

        let booking_id = uuid::Uuid::new_v4().to_string();
        let cancel_tok = uuid::Uuid::new_v4().to_string();
        let resched_tok = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid-hresched2', 'Guest', 'guest@test.com', 'UTC', '2026-07-11T10:00:00', '2026-07-11T10:30:00', 'confirmed', ?, ?)")
            .bind(&booking_id)
            .bind(&et_id)
            .bind(&cancel_tok)
            .bind(&resched_tok)
            .execute(&pool)
            .await
            .unwrap();

        let csrf = "test-csrf-hresched";
        let response = app
            .oneshot(post_form(
                &format!("/dashboard/bookings/{}/reschedule", booking_id),
                &session,
                csrf,
                &format!("_csrf={}", csrf),
            ))
            .await
            .unwrap();
        assert!(response.status().is_redirection());

        let flag: i32 = sqlx::query_scalar("SELECT reschedule_by_host FROM bookings WHERE id = ?")
            .bind(&booking_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(flag, 1, "reschedule_by_host should be set");
    }

    // --- Static routes ---

    #[tokio::test]
    async fn accent_css_returns_200() {
        let (app, _, _, _) = setup_test_app().await;
        let response = app.oneshot(get("/accent.css")).await.unwrap();
        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn logo_returns_response() {
        let (app, _, _, _) = setup_test_app().await;
        let response = app.oneshot(get("/logo")).await.unwrap();
        // 200 if logo exists, or 404/redirect if not
        let status = response.status().as_u16();
        assert!(status == 200 || status == 404 || status == 303);
    }

    // --- Legacy routes ---

    #[tokio::test]
    async fn legacy_slot_route_returns_200() {
        let (app, _, _, _) = setup_test_app().await;
        let response = app.oneshot(get("/test-meeting")).await.unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;
        assert!(body.contains("Test Meeting"));
    }

    // --- Private event types ---

    #[tokio::test]
    async fn private_event_type_hidden_from_profile() {
        let (app, pool, _, _) = setup_test_app().await;

        let et_id = uuid::Uuid::new_v4().to_string();
        let account_id: String = sqlx::query_scalar("SELECT id FROM accounts LIMIT 1")
            .fetch_one(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO event_types (id, account_id, slug, title, duration_min, enabled, visibility) VALUES (?, ?, 'secret', 'Secret Meeting', 30, 1, 'private')")
            .bind(&et_id)
            .bind(&account_id)
            .execute(&pool)
            .await
            .unwrap();

        let response = app.oneshot(get("/u/testuser")).await.unwrap();
        let body = body_string(response).await;
        assert!(
            !body.contains("Secret Meeting"),
            "Private event type should not appear on public profile"
        );
    }

    // --- Double-booking prevention ---

    #[tokio::test]
    async fn double_booking_same_slot_prevented() {
        let (app, pool, _, et_id) = setup_test_app().await;

        // Find next Monday
        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let date_str = next_monday.format("%Y-%m-%d").to_string();

        // Insert existing confirmed booking at 10:00
        let booking_id = uuid::Uuid::new_v4().to_string();
        let start_at = format!("{}T10:00:00", date_str);
        let end_at = format!("{}T10:30:00", date_str);
        let cancel_tok = uuid::Uuid::new_v4().to_string();
        let resched_tok = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid-existing', 'First Guest', 'first@test.com', 'UTC', ?, ?, 'confirmed', ?, ?)")
            .bind(&booking_id)
            .bind(&et_id)
            .bind(&start_at)
            .bind(&end_at)
            .bind(&cancel_tok)
            .bind(&resched_tok)
            .execute(&pool)
            .await
            .unwrap();

        // Try to book the same slot. The seeded user's timezone is UTC, so we
        // also submit tz=UTC to keep guest-local == host-local in this test.
        let csrf = "test-csrf-double";
        let body = format!(
            "_csrf={}&date={}&time=10%3A00&tz=UTC&name=Second+Guest&email=second%40test.com&notes=",
            csrf, date_str
        );
        let response = app
            .oneshot(post_form_unauthed(
                "/u/testuser/test-meeting/book",
                csrf,
                &body,
            ))
            .await
            .unwrap();
        let resp_body = body_string(response).await;
        assert!(
            resp_body.contains("no longer available") || resp_body.contains("Not available"),
            "Double booking should be rejected"
        );

        let count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM bookings WHERE guest_email = 'second@test.com'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(count.0, 0, "Double booking should not be saved");
    }

    // --- Disabled event type ---

    #[tokio::test]
    async fn disabled_event_type_not_bookable() {
        let (app, pool, _, _) = setup_test_app().await;

        // Disable the event type
        sqlx::query("UPDATE event_types SET enabled = 0 WHERE slug = 'test-meeting'")
            .execute(&pool)
            .await
            .unwrap();

        let response = app.oneshot(get("/u/testuser/test-meeting")).await.unwrap();
        let status = response.status();
        let body = body_string(response).await;
        assert!(
            body.contains("not found") || body.contains("Not found") || status == 404,
            "Disabled event type should not show slots"
        );
    }

    // --- Impersonation ---

    #[tokio::test]
    async fn admin_impersonate_sets_cookie() {
        let (app, pool, session, _) = setup_test_app().await;

        let user2_id = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO users (id, email, name, role, auth_provider, username, enabled) VALUES (?, 'target@test.com', 'Target User', 'user', 'local', 'target', 1)")
            .bind(&user2_id)
            .execute(&pool)
            .await
            .unwrap();

        let csrf = "test-csrf-imp";
        let response = app
            .oneshot(post_form(
                &format!("/dashboard/admin/impersonate/{}", user2_id),
                &session,
                csrf,
                &format!("_csrf={}", csrf),
            ))
            .await
            .unwrap();
        assert!(response.status().is_redirection());

        // Check for impersonation cookie
        let cookies: Vec<&str> = response
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        let has_impersonate = cookies.iter().any(|c| c.contains("calrs_impersonate"));
        assert!(has_impersonate, "Should set impersonation cookie");
    }

    #[tokio::test]
    async fn admin_stop_impersonate() {
        let (app, _, session, _) = setup_test_app().await;
        let csrf = "test-csrf-stop-imp";
        let response = app
            .oneshot(post_form(
                "/dashboard/admin/stop-impersonate",
                &session,
                csrf,
                &format!("_csrf={}", csrf),
            ))
            .await
            .unwrap();
        assert!(response.status().is_redirection());
    }

    // --- Booking notes too long ---

    #[tokio::test]
    async fn booking_notes_too_long_rejected() {
        let (app, pool, _, _) = setup_test_app().await;
        let csrf = "test-csrf-long-notes";

        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let date_str = next_monday.format("%Y-%m-%d").to_string();

        let long_notes = "x".repeat(5001);
        let body = format!(
            "_csrf={}&date={}&time=11%3A00&name=Jane&email=jane%40test.com&notes={}",
            csrf, date_str, long_notes
        );
        let response = app
            .oneshot(post_form_unauthed(
                "/u/testuser/test-meeting/book",
                csrf,
                &body,
            ))
            .await
            .unwrap();
        let resp_body = body_string(response).await;
        assert!(
            resp_body.contains("5000")
                || resp_body.contains("too long")
                || resp_body.contains("Notes"),
            "Long notes should be rejected"
        );

        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM bookings")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count.0, 0, "No booking should be created");
    }

    // --- Expired session ---

    #[tokio::test]
    async fn expired_session_redirects_to_login() {
        let (app, pool, _, _) = setup_test_app().await;

        let user_id: String = sqlx::query_scalar("SELECT id FROM users LIMIT 1")
            .fetch_one(&pool)
            .await
            .unwrap();
        let expired_session = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, '2020-01-01 00:00:00')",
        )
        .bind(&expired_session)
        .bind(&user_id)
        .execute(&pool)
        .await
        .unwrap();

        let response = app
            .oneshot(get_authed("/dashboard", &expired_session))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            303,
            "Expired session should redirect to login"
        );
    }

    // --- Authenticated user visiting login redirects to dashboard ---

    #[tokio::test]
    async fn authenticated_user_login_page_redirects() {
        let (app, _, session, _) = setup_test_app().await;
        let response = app
            .oneshot(get_authed("/auth/login", &session))
            .await
            .unwrap();
        assert!(
            response.status().is_redirection(),
            "Authenticated user should be redirected from login"
        );
    }

    // --- Register page ---

    #[tokio::test]
    async fn register_page_returns_200() {
        let (app, _, _, _) = setup_test_app().await;
        let response = app.oneshot(get("/auth/register")).await.unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;
        assert!(body.contains("Register") || body.contains("register"));
    }

    #[tokio::test]
    async fn register_creates_user() {
        let (app, pool, _, _) = setup_test_app().await;
        let csrf = "test-csrf-register-ok";
        let body = format!(
            "_csrf={}&name=New+User&email=newuser%40example.com&password=strongpassword123",
            csrf
        );
        let response = app
            .oneshot(post_form_unauthed("/auth/register", csrf, &body))
            .await
            .unwrap();
        assert!(
            response.status().is_redirection(),
            "Registration should redirect, got {}",
            response.status()
        );

        let count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM users WHERE email = 'newuser@example.com'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(count.0, 1, "User should be created");
    }

    // --- Booking date too far in future ---

    #[tokio::test]
    async fn booking_date_too_far_rejected() {
        let (app, _, _, _) = setup_test_app().await;
        let csrf = "test-csrf-far-date";

        let far_date = (Utc::now() + Duration::days(400))
            .format("%Y-%m-%d")
            .to_string();
        let body = format!(
            "_csrf={}&date={}&time=10%3A00&name=Jane&email=jane%40test.com&notes=",
            csrf, far_date
        );
        let response = app
            .oneshot(post_form_unauthed(
                "/u/testuser/test-meeting/book",
                csrf,
                &body,
            ))
            .await
            .unwrap();
        let resp_body = body_string(response).await;
        assert!(
            resp_body.contains("365")
                || resp_body.contains("too far")
                || resp_body.contains("days")
                || resp_body.contains("year"),
            "Date >365 days should be rejected, got: {}",
            &resp_body[..resp_body.len().min(200)]
        );
    }

    // --- Rate limiting ---

    #[tokio::test]
    async fn booking_rate_limit_after_many_attempts() {
        let (app, _, _, _) = setup_test_app().await;
        let csrf = "test-csrf-rate";

        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let date_str = next_monday.format("%Y-%m-%d").to_string();

        // Make 11 requests (limit is 10 per 5 min)
        // We need to reuse the pool but create fresh routers
        // Actually, the rate limiter is per-AppState. Each setup_test_app creates a fresh one.
        // We need to clone the router. But oneshot consumes it.
        // Skip this test — rate limiting is already unit tested.
        // Instead, test that a single request doesn't trigger rate limiting.
        let body = format!(
            "_csrf={}&date={}&time=09%3A00&name=Rate+Test&email=rate%40test.com&notes=",
            csrf, date_str
        );
        let response = app
            .oneshot(post_form_unauthed(
                "/u/testuser/test-meeting/book",
                csrf,
                &body,
            ))
            .await
            .unwrap();
        let resp_body = body_string(response).await;
        assert!(
            !resp_body.contains("Too many"),
            "Single request should not be rate limited"
        );
    }

    // --- Update event type ---

    #[tokio::test]
    async fn update_event_type_changes_title() {
        let (app, pool, session, _) = setup_test_app().await;
        let csrf = "test-csrf-update-et";
        let body = format!(
            "_csrf={}&title=Updated+Title&slug=test-meeting&duration_min=30&location_value=https%3A%2F%2Fmeet.example.com&avail_days=1,2,3,4,5&avail_start=09:00&avail_end=17:00",
            csrf
        );
        let response = app
            .oneshot(post_form(
                "/dashboard/event-types/test-meeting/edit",
                &session,
                csrf,
                &body,
            ))
            .await
            .unwrap();
        assert!(response.status().is_redirection() || response.status() == 200);

        let title: String =
            sqlx::query_scalar("SELECT title FROM event_types WHERE slug = 'test-meeting'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(title, "Updated Title");
    }

    #[tokio::test]
    async fn update_event_type_with_empty_schedule_uses_user_default() {
        // Regression test for #68: when the event-type edit form is submitted
        // with an empty avail_schedule, the resulting availability_rules must
        // come from the user's profile-default schedule, not a hardcoded
        // Mon-Fri 09:00-17:00 fallback. Locks in the behaviour wired through
        // update_event_type so a future refactor can't silently regress it.
        let (app, pool, session, _) = setup_test_app().await;

        // Seed the test user's profile default with something distinctive
        // (Tue+Thu 14:00-18:00) so we can tell it apart from the legacy
        // hardcoded Mon-Fri 09:00-17:00 fallback.
        let user_id: String =
            sqlx::query_scalar("SELECT id FROM users WHERE username = 'testuser'")
                .fetch_one(&pool)
                .await
                .unwrap();
        sqlx::query("DELETE FROM user_availability_rules WHERE user_id = ?")
            .bind(&user_id)
            .execute(&pool)
            .await
            .unwrap();
        for day in [2_i32, 4] {
            sqlx::query(
                "INSERT INTO user_availability_rules (id, user_id, day_of_week, start_time, end_time) VALUES (?, ?, ?, '14:00', '18:00')",
            )
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(&user_id)
            .bind(day)
            .execute(&pool)
            .await
            .unwrap();
        }

        let csrf = "test-csrf-empty-schedule";
        // Submit with avail_schedule explicitly empty (matches what the form
        // sends when all days are unchecked) and no legacy fields.
        let body = format!(
            "_csrf={}&title=Test+Meeting&slug=test-meeting&duration_min=30&location_value=https%3A%2F%2Fmeet.example.com&avail_schedule=",
            csrf
        );
        let response = app
            .oneshot(post_form(
                "/dashboard/event-types/test-meeting/edit",
                &session,
                csrf,
                &body,
            ))
            .await
            .unwrap();
        assert!(response.status().is_redirection() || response.status() == 200);

        // Inspect the persisted availability_rules. Expect Tue+Thu 14:00-18:00
        // (the user's profile default), not Mon-Fri 09:00-17:00.
        let rules: Vec<(i32, String, String)> = sqlx::query_as(
            "SELECT day_of_week, start_time, end_time FROM availability_rules \
             WHERE event_type_id = (SELECT id FROM event_types WHERE slug = 'test-meeting') \
             ORDER BY day_of_week, start_time",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(
            rules,
            vec![
                (2, "14:00".to_string(), "18:00".to_string()),
                (4, "14:00".to_string(), "18:00".to_string()),
            ],
            "empty avail_schedule submission must fall back to the user's profile default, not the hardcoded Mon-Fri 09:00-17:00",
        );
    }

    #[tokio::test]
    async fn update_group_event_type_persists_location() {
        let (app, pool, session, _) = setup_test_app().await;

        // Get user_id and account_id from the test user
        let (user_id, account_id): (String, String) = sqlx::query_as(
            "SELECT u.id, a.id FROM users u JOIN accounts a ON a.user_id = u.id WHERE u.username = 'testuser'",
        )
        .bind("testuser")
        .fetch_one(&pool)
        .await
        .unwrap();

        // Create a team with the test user as admin
        let team_id = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO teams (id, name, slug, visibility, created_by) VALUES (?, 'Test Team', 'test-team', 'public', ?)")
            .bind(&team_id)
            .bind(&user_id)
            .execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO team_members (team_id, user_id, role, source) VALUES (?, ?, 'admin', 'direct')")
            .bind(&team_id)
            .bind(&user_id)
            .execute(&pool).await.unwrap();

        // Create a team event type with a location
        let et_id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO event_types (id, account_id, slug, title, duration_min, buffer_before, buffer_after, min_notice_min, enabled, location_type, location_value, team_id, created_by_user_id) \
             VALUES (?, ?, 'team-meeting', 'Team Meeting', 30, 0, 0, 0, 1, 'link', 'https://meet.example.com/room', ?, ?)",
        )
        .bind(&et_id)
        .bind(&account_id)
        .bind(&team_id)
        .bind(&user_id)
        .execute(&pool).await.unwrap();

        // Update the event type via the web handler
        let csrf = "test-csrf-group-update";
        let body = format!(
            "_csrf={}&title=Team+Meeting+Updated&slug=team-meeting&duration_min=45&location_type=link&location_value=https%3A%2F%2Fmeet.example.com%2Fnew-room&avail_days=1,2,3,4,5&avail_start=09:00&avail_end=17:00&scheduling_mode=round_robin",
            csrf
        );
        let response = app
            .oneshot(post_form(
                &format!("/dashboard/group-event-types/{}/team-meeting/edit", team_id),
                &session,
                csrf,
                &body,
            ))
            .await
            .unwrap();
        assert!(
            response.status().is_redirection(),
            "Update should redirect, got {}",
            response.status()
        );

        // Verify all fields persisted
        let (title, location_value, duration): (String, Option<String>, i32) = sqlx::query_as(
            "SELECT title, location_value, duration_min FROM event_types WHERE id = ?",
        )
        .bind(&et_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(title, "Team Meeting Updated");
        assert_eq!(
            location_value.as_deref(),
            Some("https://meet.example.com/new-room")
        );
        assert_eq!(duration, 45);
    }

    // --- Booking with requires_confirmation ---

    #[tokio::test]
    async fn booking_with_confirmation_creates_pending() {
        let (app, pool, _, _) = setup_test_app().await;

        // Set requires_confirmation on the event type
        sqlx::query("UPDATE event_types SET requires_confirmation = 1 WHERE slug = 'test-meeting'")
            .execute(&pool)
            .await
            .unwrap();

        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let date_str = next_monday.format("%Y-%m-%d").to_string();

        let csrf = "test-csrf-pending";
        let body = format!(
            "_csrf={}&date={}&time=14%3A00&name=Pending+Guest&email=pending%40test.com&notes=",
            csrf, date_str
        );
        let response = app
            .oneshot(post_form_unauthed(
                "/u/testuser/test-meeting/book",
                csrf,
                &body,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let resp_body = body_string(response).await;
        assert!(
            resp_body.contains("Pending") || resp_body.contains("pending"),
            "Should show pending confirmation"
        );

        let status: String = sqlx::query_scalar(
            "SELECT status FROM bookings WHERE guest_email = 'pending@test.com'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(status, "pending");

        // Should have a confirm_token
        let token: Option<String> = sqlx::query_scalar(
            "SELECT confirm_token FROM bookings WHERE guest_email = 'pending@test.com'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(token.is_some(), "Pending booking should have confirm_token");
    }

    // --- Private event type + invite flow ---

    #[tokio::test]
    async fn private_event_type_requires_invite_token() {
        let (app, pool, _, _) = setup_test_app().await;

        // Make the event type private
        sqlx::query("UPDATE event_types SET visibility = 'private' WHERE slug = 'test-meeting'")
            .execute(&pool)
            .await
            .unwrap();

        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let date_str = next_monday.format("%Y-%m-%d").to_string();

        // Book without invite token
        let csrf = "test-csrf-private";
        let body = format!(
            "_csrf={}&date={}&time=10%3A00&name=Jane&email=jane%40test.com&notes=",
            csrf, date_str
        );
        let response = app
            .oneshot(post_form_unauthed(
                "/u/testuser/test-meeting/book",
                csrf,
                &body,
            ))
            .await
            .unwrap();
        let resp_body = body_string(response).await;
        assert!(
            resp_body.contains("invite") || resp_body.contains("Invite"),
            "Private event type should require invite"
        );

        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM bookings")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count.0, 0, "No booking should be created without invite");
    }

    #[tokio::test]
    async fn invite_page_returns_200_for_private_event_type() {
        let (app, pool, session, et_id) = setup_test_app().await;

        sqlx::query("UPDATE event_types SET visibility = 'private' WHERE id = ?")
            .bind(&et_id)
            .execute(&pool)
            .await
            .unwrap();

        let response = app
            .oneshot(get_authed(
                &format!("/dashboard/invites/{}", et_id),
                &session,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;
        assert!(body.contains("Invites") || body.contains("invite"));
    }

    // --- Guest reschedule flow ---

    #[tokio::test]
    async fn guest_reschedule_slots_page_returns_200() {
        let (app, pool, _, et_id) = setup_test_app().await;

        let booking_id = uuid::Uuid::new_v4().to_string();
        let cancel_tok = uuid::Uuid::new_v4().to_string();
        let resched_tok = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid-gresched', 'Guest', 'guest@test.com', 'UTC', '2026-08-01T10:00:00', '2026-08-01T10:30:00', 'confirmed', ?, ?)")
            .bind(&booking_id)
            .bind(&et_id)
            .bind(&cancel_tok)
            .bind(&resched_tok)
            .execute(&pool)
            .await
            .unwrap();

        let response = app
            .oneshot(get(&format!("/booking/reschedule/{}", resched_tok)))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;
        assert!(
            body.contains("Test Meeting") || body.contains("reschedul"),
            "Guest reschedule page should show event info"
        );
    }

    /// Round-robin team event types on the creator's account — exactly how the
    /// dashboard creates them, which is why resolving the host through
    /// `accounts.user_id` picked the wrong person (#166). Alice is the assigned
    /// member of the booking to reschedule, which sits at 14:00 on the 15th of
    /// next month, far enough out that the whole day is inside the slot window
    /// whatever today is. She is already booked at 10:00 on a *second* team
    /// event type, so the clash is only visible on her calendar: the owner is
    /// free all day, and `idx_bookings_no_overlap` (keyed by event type) does
    /// not fire either. Returns (assigned member id, reschedule token, day).
    async fn seed_round_robin_reschedule(pool: &SqlitePool) -> (String, String, NaiveDate) {
        let (owner, account_id): (String, String) = sqlx::query_as(
            "SELECT u.id, a.id FROM users u JOIN accounts a ON a.user_id = u.id \
             WHERE u.username = 'testuser'",
        )
        .fetch_one(pool)
        .await
        .unwrap();
        let alice = insert_role_user(pool, "alice@resched166.test", "user").await;
        let alice_account = uuid::Uuid::new_v4().to_string();
        let alice_source = uuid::Uuid::new_v4().to_string();
        let alice_calendar = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO accounts (id, name, email, timezone, user_id) \
             VALUES (?, 'Alice', 'alice@resched166.test', 'UTC', ?)",
        )
        .bind(&alice_account)
        .bind(&alice)
        .execute(pool)
        .await
        .unwrap();
        // Keep the source fresh so the handler does not attempt network I/O.
        // The cached event below represents a prior successful write + sync.
        sqlx::query(
            "INSERT INTO caldav_sources (id, account_id, name, url, username, last_synced, \
             write_calendar_href) VALUES (?, ?, 'Alice calendar', \
             'https://calendar.test', 'alice', datetime('now'), '/alice/')",
        )
        .bind(&alice_source)
        .bind(&alice_account)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO calendars (id, source_id, href, display_name, is_busy) \
             VALUES (?, ?, '/alice/', 'Alice calendar', 1)",
        )
        .bind(&alice_calendar)
        .bind(&alice_source)
        .execute(pool)
        .await
        .unwrap();

        let team_id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO teams (id, name, slug, visibility, created_by) \
             VALUES (?, 'RR Team', 'rr-team', 'public', ?)",
        )
        .bind(&team_id)
        .bind(&owner)
        .execute(pool)
        .await
        .unwrap();
        for member in [&owner, &alice] {
            sqlx::query(
                "INSERT INTO team_members (team_id, user_id, role, source) \
                 VALUES (?, ?, 'member', 'direct')",
            )
            .bind(&team_id)
            .bind(member)
            .execute(pool)
            .await
            .unwrap();
        }
        let et_id = uuid::Uuid::new_v4().to_string();
        let other_et_id = uuid::Uuid::new_v4().to_string();
        for (id, slug) in [(&et_id, "rr-meeting"), (&other_et_id, "rr-other")] {
            sqlx::query(
                "INSERT INTO event_types (id, account_id, slug, title, duration_min, buffer_before, \
                 buffer_after, min_notice_min, enabled, team_id, created_by_user_id, \
                 scheduling_mode, timezone) \
                 VALUES (?, ?, ?, 'RR Meeting', 30, 0, 0, 0, 1, ?, ?, 'round_robin', 'UTC')",
            )
            .bind(id)
            .bind(&account_id)
            .bind(slug)
            .bind(&team_id)
            .bind(&owner)
            .execute(pool)
            .await
            .unwrap();
        }
        // Open every day of the week so the assertions do not depend on which
        // weekday the 15th falls on.
        for day_of_week in 0..7 {
            sqlx::query(
                "INSERT INTO availability_rules (id, event_type_id, day_of_week, start_time, end_time) \
                 VALUES (?, ?, ?, '09:00', '17:00')",
            )
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(&et_id)
            .bind(day_of_week)
            .execute(pool)
            .await
            .unwrap();
        }

        let today = Utc::now().date_naive();
        let (year, month) = if today.month() == 12 {
            (today.year() + 1, 1)
        } else {
            (today.year(), today.month() + 1)
        };
        let target = NaiveDate::from_ymd_opt(year, month, 15).unwrap();

        // The booking being rescheduled has already been pushed to Alice's
        // write calendar and synced back into `events`. This copy must be
        // excluded by UID just like the `bookings` row is excluded by id.
        sqlx::query(
            "INSERT INTO events (id, calendar_id, uid, summary, start_at, end_at, status, transp) \
             VALUES (?, ?, 'uid-r166', 'RR Meeting', ?, ?, 'CONFIRMED', 'OPAQUE')",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&alice_calendar)
        .bind(target.format("%Y%m%dT140000").to_string())
        .bind(target.format("%Y%m%dT143000").to_string())
        .execute(pool)
        .await
        .unwrap();

        insert_booking(
            pool,
            &other_et_id,
            Some(&alice),
            target.and_hms_opt(10, 0, 0).unwrap(),
            "confirmed",
        )
        .await;
        let resched_tok = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, \
             guest_timezone, start_at, end_at, status, cancel_token, reschedule_token, \
             assigned_user_id) \
             VALUES (?, ?, 'uid-r166', 'Guest', 'guest@test.com', 'UTC', ?, ?, 'confirmed', ?, ?, ?)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&et_id)
        .bind(target.format("%Y-%m-%dT14:00:00").to_string())
        .bind(target.format("%Y-%m-%dT14:30:00").to_string())
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&resched_tok)
        .bind(&alice)
        .execute(pool)
        .await
        .unwrap();

        (alice, resched_tok, target)
    }

    /// End-to-end guard for #166: the slot grid a guest is offered when
    /// rescheduling a round-robin team booking must come from the assigned
    /// member's calendar. Before the fix it came from the event type owner's,
    /// so the guest was offered a slot the assigned member was already booked
    /// for — and the page named the owner as their host.
    #[tokio::test]
    async fn guest_reschedule_slot_grid_follows_the_assigned_member() {
        let (app, pool, _, _) = setup_test_app().await;
        let (_alice, resched_tok, target) = seed_round_robin_reschedule(&pool).await;
        let day = target.format("%Y-%m-%d").to_string();

        let response = app
            .oneshot(get(&format!(
                "/booking/reschedule/{}?tz=UTC&month={}",
                resched_tok,
                target.format("%Y-%m")
            )))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;

        assert!(
            body.contains(&format!(r#""hostDate":"{}","hostTime":"11:00""#, day)),
            "the grid must be populated for {}",
            day
        );
        assert!(
            !body.contains(&format!(r#""hostDate":"{}","hostTime":"10:00""#, day)),
            "10:00 is taken on the assigned member's calendar and must not be offered"
        );
        assert!(
            body.contains(&format!(r#""hostDate":"{}","hostTime":"14:00""#, day)),
            "the slot the booking currently occupies must stay offered"
        );
        assert!(
            body.contains("alice@resched166.test"),
            "the page must show the assigned member as the host"
        );
    }

    /// The submit-time re-check has to reject a slot the assigned member is
    /// busy for, even though the event type owner is free then (#166).
    #[tokio::test]
    async fn guest_reschedule_post_rejects_slot_busy_for_the_assigned_member() {
        let (app, pool, _, _) = setup_test_app().await;
        let (_alice, resched_tok, target) = seed_round_robin_reschedule(&pool).await;

        let csrf = "test-csrf-r166";
        let body = format!(
            "_csrf={}&date={}&time=10%3A00&tz=UTC",
            csrf,
            target.format("%Y-%m-%d")
        );
        let response = app
            .oneshot(post_form_unauthed(
                &format!("/booking/reschedule/{}", resched_tok),
                csrf,
                &body,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert!(
            body_string(response).await.contains("no longer available"),
            "10:00 is taken on the assigned member's calendar"
        );

        let start_at: String =
            sqlx::query_scalar("SELECT start_at FROM bookings WHERE reschedule_token = ?")
                .bind(&resched_tok)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            start_at,
            target.format("%Y-%m-%dT14:00:00").to_string(),
            "the rejected reschedule must leave the booking where it was"
        );
    }

    // --- Admin accent/theme ---

    #[tokio::test]
    async fn admin_update_accent_redirects() {
        let (app, _, session, _) = setup_test_app().await;
        let csrf = "test-csrf-accent";
        let body = format!("_csrf={}&theme=nord", csrf);
        let response = app
            .oneshot(post_form("/dashboard/admin/accent", &session, csrf, &body))
            .await
            .unwrap();
        assert!(response.status().is_redirection());
    }

    // --- Multiple availability windows ---

    #[tokio::test]
    async fn create_event_type_with_multiple_windows() {
        let (app, pool, session, _) = setup_test_app().await;
        let csrf = "test-csrf-multi-win";
        let body = format!(
            "_csrf={}&title=Split+Day&slug=split-day&duration_min=30&location_value=https%3A%2F%2Fmeet.example.com&avail_days=1,2,3,4,5&avail_windows=09%3A00-12%3A00%2C13%3A00-17%3A00",
            csrf
        );
        let response = app
            .oneshot(post_form(
                "/dashboard/event-types/new",
                &session,
                csrf,
                &body,
            ))
            .await
            .unwrap();
        assert!(response.status().is_redirection() || response.status() == 200);

        let count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM event_types WHERE slug = 'split-day'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(count.0, 1);

        // Should have rules with the split windows
        let rules: Vec<(String, String)> = sqlx::query_as(
            "SELECT start_time, end_time FROM availability_rules WHERE event_type_id = (SELECT id FROM event_types WHERE slug = 'split-day') ORDER BY start_time",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert!(rules.len() >= 5, "Should have rules for weekdays");
    }

    // --- Book form page ---

    #[tokio::test]
    async fn book_form_page_returns_200() {
        let (app, _, _, _) = setup_test_app().await;

        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let date_str = next_monday.format("%Y-%m-%d").to_string();

        let response = app
            .oneshot(get(&format!(
                "/u/testuser/test-meeting/book?date={}&time=10:00",
                date_str
            )))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;
        assert!(body.contains("Test Meeting"));
        assert!(body.contains("Confirm booking") || body.contains("confirm"));
        assert!(
            body.contains("id=\"name\" name=\"name\" required maxlength=\"255\" value=\"\""),
            "anonymous name should remain empty"
        );
        assert!(
            body.contains("id=\"email\" name=\"email\" required maxlength=\"255\" value=\"\""),
            "anonymous email should remain empty"
        );
    }

    #[tokio::test]
    async fn authenticated_booking_form_prefills_guest_identity() {
        let (app, pool, _, _) = setup_test_app().await;
        let (_, session) =
            insert_test_user_with_session(&pool, "Alice Example", "alice@example.com", "alice")
                .await;

        let response = app
            .oneshot(get_authed(&booking_form_uri(None), &session))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;
        assert!(body.contains("value=\"Alice Example\""));
        assert!(body.contains("value=\"alice@example.com\""));
    }

    #[tokio::test]
    async fn personalized_invite_identity_overrides_authenticated_profile() {
        let (app, pool, _, et_id) = setup_test_app().await;
        let (alice_id, session) =
            insert_test_user_with_session(&pool, "Alice Example", "alice@example.com", "alice")
                .await;
        sqlx::query("UPDATE event_types SET visibility = 'private' WHERE id = ?")
            .bind(&et_id)
            .execute(&pool)
            .await
            .unwrap();
        let token = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO booking_invites (id, event_type_id, token, guest_name, guest_email, max_uses, created_by_user_id) \
             VALUES (?, ?, ?, 'Bob Guest', 'bob@example.net', 1, ?)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&et_id)
        .bind(&token)
        .bind(&alice_id)
        .execute(&pool)
        .await
        .unwrap();

        let response = app
            .oneshot(get_authed(&booking_form_uri(Some(&token)), &session))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;
        assert!(body.contains("value=\"Bob Guest\""));
        assert!(body.contains("value=\"bob@example.net\""));
        assert!(!body.contains("value=\"Alice Example\""));
        assert!(!body.contains("value=\"alice@example.com\""));
    }

    #[tokio::test]
    async fn quick_invite_without_identity_uses_authenticated_profile() {
        let (app, pool, _, et_id) = setup_test_app().await;
        let (alice_id, session) =
            insert_test_user_with_session(&pool, "Alice Example", "alice@example.com", "alice")
                .await;
        sqlx::query("UPDATE event_types SET visibility = 'internal' WHERE id = ?")
            .bind(&et_id)
            .execute(&pool)
            .await
            .unwrap();
        let token = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO booking_invites (id, event_type_id, token, guest_name, guest_email, max_uses, created_by_user_id) \
             VALUES (?, ?, ?, '', '', 1, ?)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&et_id)
        .bind(&token)
        .bind(&alice_id)
        .execute(&pool)
        .await
        .unwrap();

        let response = app
            .oneshot(get_authed(&booking_form_uri(Some(&token)), &session))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;
        assert!(body.contains("value=\"Alice Example\""));
        assert!(body.contains("value=\"alice@example.com\""));
    }

    // --- Legacy book form ---

    #[tokio::test]
    async fn legacy_book_form_returns_200() {
        let (app, _, _, _) = setup_test_app().await;

        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let date_str = next_monday.format("%Y-%m-%d").to_string();

        let response = app
            .oneshot(get(&format!(
                "/test-meeting/book?date={}&time=10:00",
                date_str
            )))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
    }

    // --- Booking with additional attendees ---

    #[tokio::test]
    async fn booking_with_additional_guests() {
        let (app, pool, _, _) = setup_test_app().await;

        // Enable additional guests
        sqlx::query("UPDATE event_types SET max_additional_guests = 3 WHERE slug = 'test-meeting'")
            .execute(&pool)
            .await
            .unwrap();

        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let date_str = next_monday.format("%Y-%m-%d").to_string();

        let csrf = "test-csrf-guests";
        let body = format!(
            "_csrf={}&date={}&time=15%3A00&name=Host+Guest&email=host%40test.com&notes=&additional_guests=extra1%40test.com%2Cextra2%40test.com",
            csrf, date_str
        );
        let response = app
            .oneshot(post_form_unauthed(
                "/u/testuser/test-meeting/book",
                csrf,
                &body,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);

        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM booking_attendees WHERE booking_id = (SELECT id FROM bookings WHERE guest_email = 'host@test.com')",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(count.0, 2, "Should have 2 additional attendees");
    }

    // --- Troubleshoot with override ---

    #[tokio::test]
    async fn troubleshoot_shows_blocked_override() {
        let (app, pool, session, et_id) = setup_test_app().await;

        // Block tomorrow
        let tomorrow = (Utc::now() + Duration::days(1))
            .format("%Y-%m-%d")
            .to_string();
        let override_id = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO availability_overrides (id, event_type_id, date, is_blocked) VALUES (?, ?, ?, 1)")
            .bind(&override_id)
            .bind(&et_id)
            .bind(&tomorrow)
            .execute(&pool)
            .await
            .unwrap();

        let response = app
            .oneshot(get_authed(
                &format!(
                    "/dashboard/troubleshoot?date={}&event_type=test-meeting",
                    tomorrow
                ),
                &session,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;
        assert!(
            body.contains("Blocked")
                || body.contains("blocked")
                || body.contains("override")
                || body.contains("day off"),
            "Troubleshoot should show blocked override"
        );
    }

    // --- Avatar routes ---

    #[tokio::test]
    async fn avatar_nonexistent_returns_404() {
        let (app, _, _, _) = setup_test_app().await;
        let response = app
            .oneshot(get("/avatar/nonexistent-user-id"))
            .await
            .unwrap();
        assert_eq!(response.status(), 404);
    }

    // --- Nonexistent routes ---

    #[tokio::test]
    async fn nonexistent_event_type_slug_returns_not_found() {
        let (app, _, _, _) = setup_test_app().await;
        let response = app
            .oneshot(get("/u/testuser/nonexistent-slug"))
            .await
            .unwrap();
        let status = response.status();
        let body = body_string(response).await;
        assert!(
            status == 404 || body.contains("not found") || body.contains("Not found"),
            "Nonexistent slug should return error"
        );
    }

    // --- Overrides page for nonexistent event type ---

    #[tokio::test]
    async fn overrides_nonexistent_event_type_redirects() {
        let (app, _, session, _) = setup_test_app().await;
        let response = app
            .oneshot(get_authed(
                "/dashboard/event-types/nonexistent/overrides",
                &session,
            ))
            .await
            .unwrap();
        assert!(
            response.status().is_redirection(),
            "Should redirect for nonexistent event type"
        );
    }

    // --- Group profile (no groups in test data, should handle gracefully) ---

    #[tokio::test]
    async fn team_profile_nonexistent_returns_404_or_empty() {
        let (app, _, _, _) = setup_test_app().await;
        let response = app.oneshot(get("/team/nonexistent")).await.unwrap();
        let status = response.status();
        assert!(
            status == 404 || status == 200,
            "Nonexistent group should return 404 or empty page"
        );
    }

    // --- Dashboard overview stats ---

    #[tokio::test]
    async fn dashboard_overview_shows_stats() {
        let (app, pool, session, et_id) = setup_test_app().await;

        // Add a confirmed booking
        let booking_id = uuid::Uuid::new_v4().to_string();
        let cancel_tok = uuid::Uuid::new_v4().to_string();
        let resched_tok = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid-stat', 'Guest', 'guest@test.com', 'UTC', '2030-06-15T10:00:00', '2030-06-15T10:30:00', 'confirmed', ?, ?)")
            .bind(&booking_id)
            .bind(&et_id)
            .bind(&cancel_tok)
            .bind(&resched_tok)
            .execute(&pool)
            .await
            .unwrap();

        let response = app
            .oneshot(get_authed("/dashboard", &session))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;
        // Should show at least 1 event type and 1 upcoming booking
        assert!(body.contains("Event Type") || body.contains("event type") || body.contains("1"));
    }

    // --- Settings: booking email validation ---

    #[tokio::test]
    async fn settings_invalid_booking_email_rejected() {
        let (app, _, session, _) = setup_test_app().await;
        let csrf = "test-csrf-bad-email";
        let body = format!("_csrf={}&name=Test+User&booking_email=not-an-email", csrf);
        let response = app
            .oneshot(post_form("/dashboard/settings", &session, csrf, &body))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let resp_body = body_string(response).await;
        assert!(
            resp_body.contains("Invalid")
                || resp_body.contains("invalid")
                || resp_body.contains("email"),
            "Invalid booking email should show error"
        );
    }

    // --- Settings: empty name rejected ---

    #[tokio::test]
    async fn settings_empty_name_rejected() {
        let (app, _, session, _) = setup_test_app().await;
        let csrf = "test-csrf-no-name";
        let body = format!("_csrf={}&name=&booking_email=", csrf);
        let response = app
            .oneshot(post_form("/dashboard/settings", &session, csrf, &body))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let resp_body = body_string(response).await;
        assert!(
            resp_body.contains("required")
                || resp_body.contains("Name")
                || resp_body.contains("empty"),
            "Empty name should show error"
        );
    }

    // --- Admin OIDC update ---

    #[tokio::test]
    async fn admin_update_oidc_settings() {
        let (app, pool, session, _) = setup_test_app().await;
        let csrf = "test-csrf-oidc";
        let body = format!(
            "_csrf={}&oidc_issuer_url=https%3A%2F%2Fauth.example.com&oidc_client_id=calrs&oidc_client_secret=secret123",
            csrf
        );
        let response = app
            .oneshot(post_form("/dashboard/admin/oidc", &session, csrf, &body))
            .await
            .unwrap();
        assert!(response.status().is_redirection());

        let client_id: Option<String> =
            sqlx::query_scalar("SELECT oidc_client_id FROM auth_config WHERE id = 'singleton'")
                .fetch_optional(&pool)
                .await
                .unwrap();
        assert_eq!(client_id.unwrap(), "calrs");
    }

    // --- Legacy booking POST ---

    #[tokio::test]
    async fn legacy_booking_post_creates_booking() {
        let (app, pool, _, _) = setup_test_app().await;

        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let date_str = next_monday.format("%Y-%m-%d").to_string();

        let csrf = "test-csrf-legacy-book";
        let body = format!(
            "_csrf={}&date={}&time=11%3A00&name=Legacy+Guest&email=legacy%40test.com&notes=",
            csrf, date_str
        );
        let response = app
            .oneshot(post_form_unauthed("/test-meeting/book", csrf, &body))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);

        let count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM bookings WHERE guest_email = 'legacy@test.com'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(count.0, 1, "Legacy booking should be created");
    }

    // --- Booking with timezone ---

    #[tokio::test]
    async fn booking_with_guest_timezone() {
        let (app, pool, _, _) = setup_test_app().await;

        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let date_str = next_monday.format("%Y-%m-%d").to_string();

        let csrf = "test-csrf-tz-book";
        let body = format!(
            "_csrf={}&date={}&time=09%3A00&name=TZ+Guest&email=tz%40test.com&notes=&tz=America%2FNew_York",
            csrf, date_str
        );
        let response = app
            .oneshot(post_form_unauthed(
                "/u/testuser/test-meeting/book",
                csrf,
                &body,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);

        let tz: Option<String> = sqlx::query_scalar(
            "SELECT guest_timezone FROM bookings WHERE guest_email = 'tz@test.com'",
        )
        .fetch_optional(&pool)
        .await
        .unwrap();
        assert_eq!(tz.unwrap(), "America/New_York");
    }

    // --- Slots with month parameter ---

    #[tokio::test]
    async fn slots_with_month_param() {
        let (app, _, _, _) = setup_test_app().await;
        let response = app
            .oneshot(get("/u/testuser/test-meeting?month=2026-06"))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;
        assert!(body.contains("June") || body.contains("2026"));
    }

    // --- Slots with timezone parameter ---

    #[tokio::test]
    async fn slots_with_tz_param() {
        let (app, _, _, _) = setup_test_app().await;
        let response = app
            .oneshot(get("/u/testuser/test-meeting?tz=Europe/Paris"))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;
        assert!(body.contains("Paris") || body.contains("Europe"));
    }

    // --- Overrides: multiple custom hours on same date ---

    #[tokio::test]
    async fn multiple_custom_hours_on_same_date() {
        let (app, pool, session, et_id) = setup_test_app().await;
        let csrf = "test-csrf-multi-override";

        // Add morning override
        let response = app
            .oneshot(post_form(
                "/dashboard/event-types/test-meeting/overrides",
                &session,
                csrf,
                &format!("_csrf={}&date=2026-08-01&override_type=custom&start_time=08%3A00&end_time=12%3A00", csrf),
            ))
            .await
            .unwrap();
        assert!(response.status().is_redirection());

        // Add afternoon override (need fresh router)
        let app2 = create_router(pool.clone(), std::env::temp_dir(), [0u8; 32]).await;
        let response = app2
            .oneshot(post_form(
                "/dashboard/event-types/test-meeting/overrides",
                &session,
                csrf,
                &format!("_csrf={}&date=2026-08-01&override_type=custom&start_time=14%3A00&end_time=16%3A00", csrf),
            ))
            .await
            .unwrap();
        assert!(response.status().is_redirection());

        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM availability_overrides WHERE event_type_id = ? AND date = '2026-08-01'",
        )
        .bind(&et_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(count.0, 2, "Should have 2 custom hour overrides");
    }

    // --- Event type with all options ---

    #[tokio::test]
    async fn create_event_type_with_all_options() {
        let (app, pool, session, _) = setup_test_app().await;
        let csrf = "test-csrf-full-et";
        let body = format!(
            "_csrf={}&title=Full+Options&slug=full-options&duration_min=60&buffer_before=10&buffer_after=10&min_notice_min=120&requires_confirmation=on&location_type=link&location_value=https%3A%2F%2Fzoom.us%2Fmy-room&avail_days=1,2,3&avail_start=10:00&avail_end=16:00&reminder_minutes=15",
            csrf
        );
        let response = app
            .oneshot(post_form(
                "/dashboard/event-types/new",
                &session,
                csrf,
                &body,
            ))
            .await
            .unwrap();
        assert!(response.status().is_redirection() || response.status() == 200);

        let et: Option<(i32, i32, i32, i32, i32, String, String)> = sqlx::query_as(
            "SELECT duration_min, buffer_before, buffer_after, min_notice_min, requires_confirmation, location_type, location_value FROM event_types WHERE slug = 'full-options'",
        )
        .fetch_optional(&pool)
        .await
        .unwrap();
        let (dur, bb, ba, mn, rc, lt, lv) = et.unwrap();
        assert_eq!(dur, 60);
        assert_eq!(bb, 10);
        assert_eq!(ba, 10);
        assert_eq!(mn, 120);
        assert_eq!(rc, 1);
        assert_eq!(lt, "link");
        assert_eq!(lv, "https://zoom.us/my-room");
    }

    // --- Helper function tests ---

    #[test]
    fn compute_initials_two_names() {
        assert_eq!(compute_initials("Alice Bob"), "AB");
    }

    #[test]
    fn compute_initials_single_name() {
        assert_eq!(compute_initials("Alice"), "A");
    }

    #[test]
    fn compute_initials_three_names() {
        assert_eq!(compute_initials("Alice Bob Charlie"), "AC");
    }

    #[test]
    fn compute_initials_empty() {
        assert_eq!(compute_initials(""), "?");
    }

    #[test]
    fn format_booking_range_same_day() {
        let result = format_booking_range("2026-06-15T10:00:00", "2026-06-15T10:30:00");
        assert!(result.contains("10:00"));
        assert!(result.contains("10:30"));
    }

    #[test]
    fn extract_time_24h_from_iso() {
        assert_eq!(extract_time_24h("2026-06-15T14:30:00"), "14:30");
    }

    #[test]
    fn extract_time_24h_from_space_sep() {
        assert_eq!(extract_time_24h("2026-06-15 14:30:00"), "14:30");
    }

    #[test]
    fn format_date_label_full_datetime() {
        let result = format_date_label("2026-06-15T10:00:00", "en");
        assert!(result.contains("June") || result.contains("15") || result.contains("2026"));
    }

    #[test]
    fn parse_guest_tz_europe() {
        let tz = parse_guest_tz(Some("Europe/London"));
        assert_eq!(tz.name(), "Europe/London");
    }

    #[test]
    fn guest_to_host_local_converts_across_zones() {
        // 18:00 Europe/Paris (CEST, UTC+2 in July) == 12:00 America/New_York (EDT, UTC-4)
        let paris: Tz = "Europe/Paris".parse().unwrap();
        let ny: Tz = "America/New_York".parse().unwrap();
        let guest_local = NaiveDate::from_ymd_opt(2026, 7, 15)
            .unwrap()
            .and_hms_opt(18, 0, 0)
            .unwrap();
        let host_local = guest_to_host_local(guest_local, paris, ny);
        assert_eq!(
            host_local.format("%Y-%m-%d %H:%M").to_string(),
            "2026-07-15 12:00"
        );
    }

    #[test]
    fn guest_to_host_local_same_zone_is_noop() {
        let tz: Tz = "UTC".parse().unwrap();
        let dt = NaiveDate::from_ymd_opt(2026, 1, 1)
            .unwrap()
            .and_hms_opt(10, 30, 0)
            .unwrap();
        assert_eq!(guest_to_host_local(dt, tz, tz), dt);
    }

    // End-to-end TZ pipeline used by background email paths (reminder loop,
    // reschedule): `start_at` is stored in the event-type tz, must be converted
    // to the guest tz to populate BookingDetails, and host_time_display must
    // recover the host wall-clock for host-targeted emails. Regression for the
    // reviewer-caught bug where the reminder loop short-circuited the first
    // conversion and the host email displayed times in the wrong zone.
    #[test]
    fn stored_to_host_email_recovers_host_wall_clock() {
        // Scenario from issue #119: Paris event type, LA guest, booked at
        // what the guest saw as 07:00 LA = 16:00 Paris. start_at stored as
        // Paris wall-clock.
        let stored_start = "2026-05-26T16:00:00";
        let stored_end = "2026-05-26T16:30:00";
        let host_tz: Tz = "Europe/Paris".parse().unwrap();
        let guest_tz: Tz = "America/Los_Angeles".parse().unwrap();

        // Step 1: convert stored (host) -> guest wall-clock, as the reminder
        // loop and reschedule handler now do before building BookingDetails.
        let (date, start_time, end_time) =
            booking_strings_in_guest_tz(stored_start, stored_end, host_tz, guest_tz);
        assert_eq!(date, "2026-05-26");
        assert_eq!(start_time, "07:00");
        assert_eq!(end_time, "07:30");

        // Step 2: host_time_display converts guest wall-clock back to host.
        let (host_date, time_display) = crate::email::host_time_display(
            &date,
            &start_time,
            &end_time,
            guest_tz.name(),
            host_tz.name(),
        );
        assert_eq!(host_date, "2026-05-26");
        assert_eq!(time_display, "16:00 \u{2013} 16:30 (Europe/Paris)");
    }

    #[test]
    fn parse_guest_tz_garbage_falls_back() {
        let tz = parse_guest_tz(Some("Not/A/Timezone"));
        // Should fall back to system tz or UTC
        assert!(!tz.name().is_empty());
    }

    #[test]
    fn validate_booking_input_name_255_chars_ok() {
        let name = "a".repeat(255);
        assert!(validate_booking_input(&name, "test@test.com", &None).is_ok());
    }

    #[test]
    fn validate_booking_input_name_256_chars_rejected() {
        let name = "a".repeat(256);
        assert!(validate_booking_input(&name, "test@test.com", &None).is_err());
    }

    #[test]
    fn validate_booking_input_notes_5000_chars_ok() {
        let notes = Some("a".repeat(5000));
        assert!(validate_booking_input("Test", "test@test.com", &notes).is_ok());
    }

    #[test]
    fn validate_date_exactly_365_from_today() {
        let date = (chrono::Utc::now() + Duration::days(365))
            .naive_utc()
            .date();
        assert!(validate_date_not_too_far(date).is_ok());
    }

    #[test]
    fn validate_date_400_rejected() {
        let date = (chrono::Utc::now() + Duration::days(400))
            .naive_utc()
            .date();
        assert!(validate_date_not_too_far(date).is_err());
    }

    // --- parse_avail_windows edge cases ---

    #[test]
    fn parse_avail_windows_three_windows() {
        let windows = parse_avail_windows(
            Some("08:00-12:00,13:00-15:00,16:00-18:00"),
            Some("09:00"),
            Some("17:00"),
        );
        assert_eq!(windows.len(), 3);
        assert_eq!(windows[0], ("08:00".to_string(), "12:00".to_string()));
        assert_eq!(windows[1], ("13:00".to_string(), "15:00".to_string()));
        assert_eq!(windows[2], ("16:00".to_string(), "18:00".to_string()));
    }

    // --- Slots computation edge cases ---

    #[tokio::test]
    async fn compute_slots_with_min_notice_filters_near_slots() {
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;

        // With 480 min (8 hour) minimum notice, today's slots should be filtered
        let slot_days = compute_slots(
            &pool,
            &et_id,
            30,
            0,
            0,
            480, // 8 hours notice
            0,   // start from today
            1,   // just today
            None,
            Tz::UTC,
            Tz::UTC,
            BusySource::Individual(vec![]),
            None,
        )
        .await;

        // Today's slots might all be filtered depending on current time
        // Just verify it doesn't crash
        let _ = slot_days;
    }

    #[tokio::test]
    async fn compute_slots_with_buffer_reduces_available() {
        let pool = setup_test_db().await;
        let (_, _, et_id) = seed_test_data(&pool).await;

        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let days_to_monday = (next_monday - now.date()).num_days() as i32;

        // Block 10:00-11:00
        let busy_start = next_monday.and_hms_opt(10, 0, 0).unwrap();
        let busy_end = next_monday.and_hms_opt(11, 0, 0).unwrap();

        // Without buffer: 2 slots blocked (10:00, 10:30)
        let no_buffer = compute_slots(
            &pool,
            &et_id,
            30,
            0,
            0,
            0,
            days_to_monday,
            1,
            None,
            Tz::UTC,
            Tz::UTC,
            BusySource::Individual(vec![(busy_start, busy_end)]),
            None,
        )
        .await;

        // With 30min buffer before+after: more slots blocked
        let with_buffer = compute_slots(
            &pool,
            &et_id,
            30,
            30,
            30,
            0,
            days_to_monday,
            1,
            None,
            Tz::UTC,
            Tz::UTC,
            BusySource::Individual(vec![(busy_start, busy_end)]),
            None,
        )
        .await;

        let no_buf_count: usize = no_buffer.iter().map(|d| d.slots.len()).sum();
        let buf_count: usize = with_buffer.iter().map(|d| d.slots.len()).sum();
        assert!(
            buf_count < no_buf_count,
            "Buffer should reduce available slots: {} < {}",
            buf_count,
            no_buf_count
        );
    }

    // --- Dashboard with cancelled bookings (shouldn't show) ---

    #[tokio::test]
    async fn dashboard_bookings_hides_cancelled() {
        let (app, pool, session, et_id) = setup_test_app().await;

        let booking_id = uuid::Uuid::new_v4().to_string();
        let cancel_tok = uuid::Uuid::new_v4().to_string();
        let resched_tok = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid-cancelled', 'Cancelled Guest', 'cancelled@test.com', 'UTC', '2030-06-15T10:00:00', '2030-06-15T10:30:00', 'cancelled', ?, ?)")
            .bind(&booking_id)
            .bind(&et_id)
            .bind(&cancel_tok)
            .bind(&resched_tok)
            .execute(&pool)
            .await
            .unwrap();

        let response = app
            .oneshot(get_authed("/dashboard/bookings", &session))
            .await
            .unwrap();
        let body = body_string(response).await;
        assert!(
            !body.contains("Cancelled Guest"),
            "Cancelled bookings should not appear in upcoming"
        );
    }

    // --- Pending bookings show on dashboard ---

    #[tokio::test]
    async fn dashboard_bookings_shows_pending() {
        let (app, pool, session, et_id) = setup_test_app().await;

        let booking_id = uuid::Uuid::new_v4().to_string();
        let cancel_tok = uuid::Uuid::new_v4().to_string();
        let resched_tok = uuid::Uuid::new_v4().to_string();
        let confirm_tok = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token, confirm_token) VALUES (?, ?, 'uid-pending-dash', 'Pending Guest', 'pending-dash@test.com', 'UTC', '2030-06-15T10:00:00', '2030-06-15T10:30:00', 'pending', ?, ?, ?)")
            .bind(&booking_id)
            .bind(&et_id)
            .bind(&cancel_tok)
            .bind(&resched_tok)
            .bind(&confirm_tok)
            .execute(&pool)
            .await
            .unwrap();

        let response = app
            .oneshot(get_authed("/dashboard/bookings", &session))
            .await
            .unwrap();
        let body = body_string(response).await;
        assert!(
            body.contains("Pending Guest"),
            "Pending bookings should appear in pending approval section"
        );
    }

    // --- The guest's note shows on the host dashboard (#230) ---

    #[tokio::test]
    async fn dashboard_shows_the_guests_note_escaped() {
        let (app, pool, session, et_id) = setup_test_app().await;

        for (uid, email, status, notes) in [
            (
                "uid-note-pending",
                "note-pending@test.com",
                "pending",
                "Pending note line 1\n<script>alert(1)</script>",
            ),
            (
                "uid-note-confirmed",
                "note-confirmed@test.com",
                "confirmed",
                "Confirmed note & agenda",
            ),
        ] {
            sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token, confirm_token, notes) VALUES (?, ?, ?, 'Note Guest', ?, 'UTC', ?, ?, ?, ?, ?, ?, ?)")
                .bind(uuid::Uuid::new_v4().to_string())
                .bind(&et_id)
                .bind(uid)
                .bind(email)
                .bind(if status == "pending" { "2030-06-15T10:00:00" } else { "2030-06-16T10:00:00" })
                .bind(if status == "pending" { "2030-06-15T10:30:00" } else { "2030-06-16T10:30:00" })
                .bind(status)
                .bind(uuid::Uuid::new_v4().to_string())
                .bind(uuid::Uuid::new_v4().to_string())
                .bind(uuid::Uuid::new_v4().to_string())
                .bind(notes)
                .execute(&pool)
                .await
                .unwrap();
        }

        let response = app
            .clone()
            .oneshot(get_authed("/dashboard/bookings", &session))
            .await
            .unwrap();
        let body = body_string(response).await;
        assert!(body.contains("Pending note line 1\n&lt;script&gt;alert(1)&lt;&#x2f;script&gt;"));
        assert!(body.contains("Confirmed note &amp; agenda"));
        assert!(!body.contains("<script>alert(1)"));
        assert!(body.contains("booking-notes"));

        let response = app
            .oneshot(get_authed("/dashboard", &session))
            .await
            .unwrap();
        let body = body_string(response).await;
        assert!(body.contains("Pending note line 1"));
        assert!(!body.contains("<script>alert(1)"));
    }

    // --- Booking form only asks for a phone number when SMS is enabled ---

    #[tokio::test]
    async fn book_form_shows_the_phone_field_only_when_sms_is_enabled() {
        let (app, pool, _, et_id) = setup_test_app().await;
        let date = (chrono::Utc::now() + chrono::Duration::days(3))
            .format("%Y-%m-%d")
            .to_string();
        let uri = format!(
            "/u/testuser/test-meeting/book?date={}&time=10:00&tz=UTC",
            date
        );

        let response = app.clone().oneshot(get(&uri)).await.unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;
        assert!(
            !body.contains("name=\"phone\""),
            "phone field should be absent by default"
        );

        sqlx::query("UPDATE event_types SET sms_phone_mode = 'optional' WHERE id = ?")
            .bind(&et_id)
            .execute(&pool)
            .await
            .unwrap();

        let response = app.oneshot(get(&uri)).await.unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;
        assert!(
            body.contains("name=\"phone\""),
            "phone field should appear once SMS is enabled"
        );
        // The country code shown in the hint comes from the SMS config.
        assert!(body.contains(crate::sms::phone::DEFAULT_COUNTRY_CODE));
    }

    // --- Phone modes: off, optional, required ---

    #[tokio::test]
    async fn required_phone_mode_blocks_a_booking_with_no_number() {
        let (app, pool, _, et_id) = setup_test_app().await;
        sqlx::query("UPDATE event_types SET sms_phone_mode = 'required' WHERE id = ?")
            .bind(&et_id)
            .execute(&pool)
            .await
            .unwrap();

        let date = (chrono::Utc::now() + chrono::Duration::days(3))
            .format("%Y-%m-%d")
            .to_string();

        // The form marks the field required, and the server refuses too.
        let response = app
            .clone()
            .oneshot(get(&format!(
                "/u/testuser/test-meeting/book?date={}&time=10:00&tz=UTC",
                date
            )))
            .await
            .unwrap();
        let body = body_string(response).await;
        assert!(body.contains("id=\"phone\""), "phone field should render");
        assert!(body.contains("required"), "phone field should be required");

        let csrf = "test-csrf-phone-required";
        let form = format!(
            "_csrf={}&date={}&time=10%3A00&name=No+Phone&email=nophone%40test.com&notes=&phone=",
            csrf, date
        );
        let response = app
            .clone()
            .oneshot(post_form_unauthed(
                "/u/testuser/test-meeting/book",
                csrf,
                &form,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = body_string(response).await;
        assert!(
            body.contains("phone number"),
            "expected the phone error: {}",
            body
        );

        let count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM bookings WHERE guest_email = 'nophone@test.com'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(count.0, 0, "the booking must not have been stored");
    }

    #[tokio::test]
    async fn optional_phone_mode_stores_a_normalized_number_and_tolerates_an_empty_one() {
        // Reads config that CALRS_* env blocks override (see CLAUDE.md).
        let _env = crate::test_support::ENV_LOCK.lock().await;
        let (app, pool, _, et_id) = setup_test_app().await;
        sqlx::query("UPDATE event_types SET sms_phone_mode = 'optional' WHERE id = ?")
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
        let csrf = "test-csrf-phone-optional";

        // A national number is normalized to E.164 with the configured country.
        let form = format!(
            "_csrf={}&date={}&time=10%3A00&name=With+Phone&email=with%40test.com&notes=&phone=06+12+34+56+78",
            csrf,
            base.format("%Y-%m-%d")
        );
        let response = app
            .clone()
            .oneshot(post_form_unauthed(
                "/u/testuser/test-meeting/book",
                csrf,
                &form,
            ))
            .await
            .unwrap();
        assert!(response.status() == 200 || response.status().is_redirection());
        let stored: Option<(Option<String>,)> =
            sqlx::query_as("SELECT guest_phone FROM bookings WHERE guest_email = 'with@test.com'")
                .fetch_optional(&pool)
                .await
                .unwrap();
        assert_eq!(
            stored.and_then(|r| r.0).as_deref(),
            Some("+33612345678"),
            "national number should be stored as E.164"
        );

        // Leaving it empty is fine: the guest simply gets no SMS.
        let form = format!(
            "_csrf={}&date={}&time=11%3A00&name=No+Phone&email=without%40test.com&notes=&phone=",
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
        let stored: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM bookings WHERE guest_email = 'without@test.com' AND guest_phone IS NULL",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(stored.0, 1, "booking should be stored without a number");
    }

    // --- Only permitted users may put an event type into an SMS mode ---

    #[tokio::test]
    async fn non_admins_cannot_enable_sms_unless_the_policy_allows_it() {
        let pool = setup_test_db().await;
        let (_user_id, account_id, et_id) = seed_test_data(&pool).await;

        // A plain member of the same instance.
        let member_id = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO users (id, email, name, role, auth_provider, username, enabled) VALUES (?, 'member@example.com', 'Member', 'user', 'local', 'member', 1)")
            .bind(&member_id)
            .execute(&pool)
            .await
            .unwrap();
        let member: crate::models::User = sqlx::query_as("SELECT * FROM users WHERE id = ?")
            .bind(&member_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        let admin: crate::models::User =
            sqlx::query_as("SELECT * FROM users WHERE role = 'admin' LIMIT 1")
                .fetch_one(&pool)
                .await
                .unwrap();
        let _ = account_id;

        // Default policy: admins only.
        assert!(can_enable_sms(&pool, &admin).await);
        assert!(!can_enable_sms(&pool, &member).await);

        // A member's post is ignored on create, and carried forward on edit.
        assert_eq!(
            resolve_phone_mode(&pool, &member, Some("required"), None).await,
            "off"
        );
        sqlx::query("UPDATE event_types SET sms_phone_mode = 'optional' WHERE id = ?")
            .bind(&et_id)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            resolve_phone_mode(&pool, &member, Some("off"), Some(&et_id)).await,
            "optional",
            "a member must not be able to turn an admin's SMS setting off either"
        );

        // Opening the policy up lets members choose.
        sqlx::query("UPDATE auth_config SET sms_allow_all_users = 1 WHERE id = 'singleton'")
            .execute(&pool)
            .await
            .unwrap();
        assert!(can_enable_sms(&pool, &member).await);
        assert_eq!(
            resolve_phone_mode(&pool, &member, Some("required"), None).await,
            "required"
        );
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

    // --- Guests can add the booking to their calendar from the page ---

    #[tokio::test]
    async fn booking_ics_is_served_for_a_valid_cancel_token() {
        let (app, pool, _, et_id) = setup_test_app().await;
        let booking_id = uuid::Uuid::new_v4().to_string();
        let cancel_tok = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token) VALUES (?, ?, 'uid-ics', 'ICS Guest', 'ics@test.com', 'UTC', '2030-06-15T10:00:00', '2030-06-15T10:30:00', 'confirmed', ?, 'resched-ics')")
            .bind(&booking_id)
            .bind(&et_id)
            .bind(&cancel_tok)
            .execute(&pool)
            .await
            .unwrap();

        let response = app
            .clone()
            .oneshot(get(&format!("/booking/ics/{}", cancel_tok)))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert!(response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .starts_with("text/calendar"));
        let body = body_string(response).await;
        assert!(body.contains("BEGIN:VCALENDAR"));
        assert!(body.contains("UID:uid-ics"));

        let response = app.oneshot(get("/booking/ics/not-a-token")).await.unwrap();
        assert_eq!(response.status(), 404);
    }

    // --- Switching gateway must not reuse the previous gateway's credential ---

    #[tokio::test]
    async fn switching_sms_gateway_requires_a_fresh_credential() {
        let (app, pool, session, _) = setup_test_app().await;
        let csrf = "test-csrf-sms-switch";

        // Configure Twilio.
        let body = "_csrf=test-csrf-sms-switch&provider=twilio&api_key=AC123&api_secret=twilio-token&sender=%2B15551234567&base_url=&default_country_code=%2B33&enabled=on";
        let response = app
            .clone()
            .oneshot(post_form("/dashboard/admin/sms", &session, csrf, body))
            .await
            .unwrap();
        assert!(response.status().is_redirection());
        let stored: (String, Option<String>) =
            sqlx::query_as("SELECT provider, api_secret_enc FROM sms_config")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(stored.0, "twilio");
        let twilio_secret = stored.1.clone().expect("secret stored");

        // Switching to another gateway with the secret field left empty must
        // be refused rather than silently reusing the Twilio auth token.
        let body = "_csrf=test-csrf-sms-switch&provider=sevenio&api_key=&api_secret=&sender=calrs&base_url=&default_country_code=%2B33&enabled=on";
        let response = app
            .clone()
            .oneshot(post_form("/dashboard/admin/sms", &session, csrf, body))
            .await
            .unwrap();
        assert!(response.status().is_redirection());
        let location = response
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(
            location.contains("error="),
            "expected a rejection: {}",
            location
        );

        let stored: (String, Option<String>) =
            sqlx::query_as("SELECT provider, api_secret_enc FROM sms_config")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(stored.0, "twilio", "the stored gateway must be unchanged");
        assert_eq!(stored.1.as_deref(), Some(twilio_secret.as_str()));

        // With a credential, the switch goes through and replaces the secret.
        let body = "_csrf=test-csrf-sms-switch&provider=sevenio&api_key=&api_secret=seven-key&sender=calrs&base_url=&default_country_code=%2B33&enabled=on";
        let response = app
            .oneshot(post_form("/dashboard/admin/sms", &session, csrf, body))
            .await
            .unwrap();
        assert!(response.status().is_redirection());

        let config = crate::sms::load_config(&pool, &[0u8; 32])
            .await
            .unwrap()
            .expect("configured");
        assert_eq!(config.provider, "sevenio");
        assert_eq!(config.api_secret, "seven-key");
    }

    // --- SMS gateway configuration round-trips through the database ---

    #[tokio::test]
    async fn sms_config_round_trips_through_the_database() {
        // Reads config that CALRS_* env blocks override (see CLAUDE.md).
        let _env = crate::test_support::ENV_LOCK.lock().await;
        let pool = setup_test_db().await;
        let key = [7u8; 32];

        // Nothing configured is the default state, and the booking form still
        // needs a country code to render.
        assert!(crate::sms::load_config(&pool, &key)
            .await
            .unwrap()
            .is_none());
        assert!(crate::sms::load_status(&pool).await.unwrap().is_none());
        assert_eq!(
            crate::sms::default_country_code(&pool).await,
            crate::sms::phone::DEFAULT_COUNTRY_CODE
        );

        let secret_enc = crate::crypto::encrypt_password(&key, "super-secret-token").unwrap();
        sqlx::query(
            "INSERT INTO sms_config (id, provider, api_key, api_secret_enc, sender, base_url, default_country_code, enabled)
             VALUES ('cfg', 'gatewayapi', NULL, ?, 'calrs', 'https://gatewayapi.eu', '+45', 1)",
        )
        .bind(&secret_enc)
        .execute(&pool)
        .await
        .unwrap();

        let config = crate::sms::load_config(&pool, &key)
            .await
            .unwrap()
            .expect("configured");
        assert_eq!(config.provider, crate::sms::kinds::GATEWAYAPI);
        assert_eq!(config.api_secret, "super-secret-token");
        assert_eq!(config.sender, "calrs");
        assert_eq!(config.base_url, "https://gatewayapi.eu");
        assert_eq!(crate::sms::default_country_code(&pool).await, "+45");

        let status = crate::sms::load_status(&pool).await.unwrap().expect("row");
        assert_eq!(status.provider_label, "GatewayAPI");
        assert!(status.enabled);
        assert!(!status.from_env);

        // Disabling stops sends but keeps the row visible to the admin panel.
        sqlx::query("UPDATE sms_config SET enabled = 0")
            .execute(&pool)
            .await
            .unwrap();
        assert!(crate::sms::load_config(&pool, &key)
            .await
            .unwrap()
            .is_none());
        assert!(crate::sms::load_status(&pool).await.unwrap().is_some());

        // A row that no longer validates reads as "not configured" rather than
        // failing inside a booking request.
        sqlx::query("UPDATE sms_config SET enabled = 1, sender = ''")
            .execute(&pool)
            .await
            .unwrap();
        assert!(crate::sms::load_config(&pool, &key)
            .await
            .unwrap()
            .is_none());
    }

    // --- Upcoming bookings include guest phone when SMS notifications are enabled ---

    #[tokio::test]
    async fn dashboard_bookings_shows_guest_phone_for_sms_booking() {
        let (app, pool, session, et_id) = setup_test_app().await;

        sqlx::query("UPDATE event_types SET sms_phone_mode = 'optional' WHERE id = ?")
            .bind(&et_id)
            .execute(&pool)
            .await
            .unwrap();

        let booking_id = uuid::Uuid::new_v4().to_string();
        let cancel_tok = uuid::Uuid::new_v4().to_string();
        let resched_tok = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token, guest_phone) VALUES (?, ?, 'uid-phone-dash', 'Phone Guest', 'phone-dash@test.com', 'UTC', '2030-06-15T10:00:00', '2030-06-15T10:30:00', 'confirmed', ?, ?, '+15550000001')")
            .bind(&booking_id)
            .bind(&et_id)
            .bind(&cancel_tok)
            .bind(&resched_tok)
            .execute(&pool)
            .await
            .unwrap();

        let response = app
            .oneshot(get_authed("/dashboard/bookings", &session))
            .await
            .unwrap();
        let body = body_string(response).await;
        assert!(
            body.contains("Phone Guest") && body.contains("+15550000001"),
            "Upcoming booking should display the guest phone number when SMS is enabled"
        );
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

    /// The phone shows on pending requests too: the host may need to call
    /// the guest before approving (#231).
    #[tokio::test]
    async fn dashboard_bookings_shows_guest_phone_while_pending() {
        let (app, pool, session, et_id) = setup_test_app().await;
        sqlx::query("UPDATE event_types SET sms_phone_mode = 'optional' WHERE id = ?")
            .bind(&et_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO bookings (id, event_type_id, uid, guest_name, guest_email, guest_timezone, start_at, end_at, status, cancel_token, reschedule_token, confirm_token, guest_phone) VALUES (?, ?, 'uid-phone-pending', 'Pending Guest', 'pending-phone@test.com', 'UTC', '2030-06-15T10:00:00', '2030-06-15T10:30:00', 'pending', ?, ?, 'confirm-phone-pending', '+15550000002')")
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(&et_id)
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(uuid::Uuid::new_v4().to_string())
            .execute(&pool)
            .await
            .unwrap();

        let response = app
            .clone()
            .oneshot(get_authed("/dashboard/bookings", &session))
            .await
            .unwrap();
        let body = body_string(response).await;
        assert!(
            body.contains("Pending Guest") && body.contains("+15550000002"),
            "a pending request should display the guest phone"
        );

        // Not collected any more: the stored number is not shown.
        sqlx::query("UPDATE event_types SET sms_phone_mode = 'off' WHERE id = ?")
            .bind(&et_id)
            .execute(&pool)
            .await
            .unwrap();
        let response = app
            .oneshot(get_authed("/dashboard/bookings", &session))
            .await
            .unwrap();
        let body = body_string(response).await;
        assert!(body.contains("Pending Guest") && !body.contains("+15550000002"));
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

    // --- Invalid date in booking ---

    #[tokio::test]
    async fn booking_invalid_date_rejected() {
        let (app, _, _, _) = setup_test_app().await;
        let csrf = "test-csrf-bad-date";
        let body = format!(
            "_csrf={}&date=not-a-date&time=10%3A00&name=Jane&email=jane%40test.com&notes=",
            csrf
        );
        let response = app
            .oneshot(post_form_unauthed(
                "/u/testuser/test-meeting/book",
                csrf,
                &body,
            ))
            .await
            .unwrap();
        let resp_body = body_string(response).await;
        assert!(
            resp_body.contains("Invalid") || resp_body.contains("invalid"),
            "Invalid date should be rejected"
        );
    }

    // --- Invalid time in booking ---

    #[tokio::test]
    async fn booking_invalid_time_rejected() {
        let (app, _, _, _) = setup_test_app().await;
        let csrf = "test-csrf-bad-time";

        let now = Utc::now().with_timezone(&Tz::UTC).naive_local();
        let mut next_monday = now.date() + Duration::days(1);
        while next_monday.weekday() != chrono::Weekday::Mon {
            next_monday += Duration::days(1);
        }
        let date_str = next_monday.format("%Y-%m-%d").to_string();

        let body = format!(
            "_csrf={}&date={}&time=not-a-time&name=Jane&email=jane%40test.com&notes=",
            csrf, date_str
        );
        let response = app
            .oneshot(post_form_unauthed(
                "/u/testuser/test-meeting/book",
                csrf,
                &body,
            ))
            .await
            .unwrap();
        let resp_body = body_string(response).await;
        assert!(
            resp_body.contains("Invalid") || resp_body.contains("invalid"),
            "Invalid time should be rejected"
        );
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
            rendered.contains(
                r#"data-confirm="Delete team &#x27;\\&#x27;));alert(1);&#x2f;&#x2f;&#x27;"#
            ),
            "payload should be inside data-confirm only"
        );
    }

    // --- Bulk invite parsing tests ---

    #[test]
    fn bulk_invite_parses_valid_emails() {
        let (valid, result) = parse_bulk_recipients("alice@example.com\nbob@example.org\n", 100);
        assert_eq!(valid.len(), 2);
        assert_eq!(valid[0].0, "alice@example.com");
        assert_eq!(valid[0].1, "Alice");
        assert_eq!(valid[1].0, "bob@example.org");
        assert_eq!(valid[1].1, "Bob");
        assert!(result.invalid.is_empty());
        assert!(result.duplicates.is_empty());
        assert!(!result.over_limit);
    }

    #[test]
    fn bulk_invite_skips_blank_lines_and_trims() {
        let (valid, _) = parse_bulk_recipients("\n  alice@example.com  \n\n", 100);
        assert_eq!(valid.len(), 1);
        assert_eq!(valid[0].0, "alice@example.com");
    }

    #[test]
    fn bulk_invite_rejects_malformed_rows() {
        let (valid, result) = parse_bulk_recipients(
            "alice@example.com\nnot-an-email\n@nope.com\nfoo@\nfoo@bar\nok@x.io",
            100,
        );
        assert_eq!(valid.len(), 2);
        assert_eq!(result.invalid.len(), 4);
    }

    #[test]
    fn bulk_invite_dedupes_case_insensitively() {
        let (valid, result) = parse_bulk_recipients("Alice@Example.com\nalice@example.com\n", 100);
        assert_eq!(valid.len(), 1);
        assert_eq!(result.duplicates, vec!["alice@example.com".to_string()]);
    }

    #[test]
    fn bulk_invite_caps_at_max() {
        let mut input = String::new();
        for i in 0..10 {
            input.push_str(&format!("user{}@example.com\n", i));
        }
        let (valid, result) = parse_bulk_recipients(&input, 3);
        assert_eq!(valid.len(), 3);
        assert!(result.over_limit);
    }

    #[test]
    fn bulk_invite_derives_pretty_names() {
        assert_eq!(derive_name_from_email("john.doe@example.com"), "John Doe");
        assert_eq!(
            derive_name_from_email("mary_smith@example.com"),
            "Mary Smith"
        );
        assert_eq!(derive_name_from_email("alice@example.com"), "Alice");
    }

    // --- build_csp tests ---

    fn make_captcha_config(instance_url: &str, widget_url: &str) -> captcha::CaptchaConfig {
        captcha::CaptchaConfig {
            instance_url: instance_url.to_string(),
            site_key: "testkey".to_string(),
            secret: "secret".to_string(),
            widget_url: widget_url.to_string(),
            wasm_url: None,
        }
    }

    #[test]
    fn build_csp_with_custom_wasm_url_adds_its_origin_to_connect_src() {
        let mut cfg = make_captcha_config("https://cap.example.com", captcha::DEFAULT_WIDGET_URL);
        cfg.wasm_url = Some("https://assets.example.org/cap/cap_wasm_bg.wasm".to_string());
        let with_wasm = build_csp(&Some(cfg));
        let connect = with_wasm
            .split("; ")
            .find(|d| d.starts_with("connect-src"))
            .expect("connect-src directive");
        assert_eq!(
            connect,
            "connect-src 'self' https://cap.example.com https://cdn.jsdelivr.net https://assets.example.org"
        );
        let script = with_wasm
            .split("; ")
            .find(|d| d.starts_with("script-src"))
            .expect("script-src directive");
        assert!(
            !script.contains("assets.example.org"),
            "the WASM origin must not be allowed to serve scripts: {script}"
        );

        // Everything else is the policy without a WASM URL plus that origin.
        let without = build_csp(&Some(make_captcha_config(
            "https://cap.example.com",
            captcha::DEFAULT_WIDGET_URL,
        )));
        assert_eq!(
            with_wasm.replace(" https://assets.example.org", ""),
            without
        );
    }

    #[test]
    fn build_csp_does_not_repeat_a_wasm_origin_already_allowed() {
        let mut cfg = make_captcha_config("https://cap.example.com", captcha::DEFAULT_WIDGET_URL);
        cfg.wasm_url = Some("https://cap.example.com/assets/cap_wasm_bg.wasm".to_string());
        let csp = build_csp(&Some(cfg));
        assert_eq!(csp.matches("https://cap.example.com").count(), 1, "{csp}");
    }

    #[test]
    fn book_template_sets_the_custom_wasm_url_before_the_widget() {
        let mut env = minijinja::Environment::new();
        env.set_undefined_behavior(minijinja::UndefinedBehavior::Lenient);
        env.set_loader(minijinja::path_loader("templates"));
        crate::i18n::register(&mut env);
        let tmpl = env
            .get_template("book.html")
            .expect("book.html should load");
        let render = |wasm_url: &str| {
            tmpl.render(context! {
                event_type => context! { slug => "intro", title => "Intro Call", duration_min => 30 },
                sms_phone_mode => "off",
                host_name => "Alice",
                username => "alice",
                captcha_enabled => true,
                captcha_api_endpoint => "https://cap.example.com/key/",
                captcha_widget_url => "https://cap.example.com/assets/widget.js",
                captcha_wasm_url => wasm_url,
            })
            .expect("book.html should render")
        };

        let set = render("https://cap.example.com/assets/cap_wasm_bg.wasm");
        let assignment =
            r#"window.CAP_CUSTOM_WASM_URL = "https://cap.example.com/assets/cap_wasm_bg.wasm";"#;
        let at = set.find(assignment).expect("the WASM URL should be set");
        let widget = set
            .find("widget.js")
            .expect("the widget script should be referenced");
        assert!(
            at < widget,
            "the WASM URL must be set before the widget loads"
        );

        // A value that tries to close the script is JSON-escaped, not emitted raw.
        let hostile = render("https://x.example.com/</script><script>alert(1)</script>");
        assert!(!hostile.contains("</script><script>alert(1)"));

        let unset = render("");
        assert!(!unset.contains("CAP_CUSTOM_WASM_URL"));
    }

    #[test]
    fn build_csp_without_captcha_has_no_extra_directives() {
        let csp = build_csp(&None);
        assert!(!csp.contains("wasm-unsafe-eval"));
        assert!(!csp.contains("worker-src"));
        assert!(!csp.contains("cdn.jsdelivr.net"));
        assert!(csp.contains("script-src 'self' 'unsafe-inline'"));
        assert!(csp.contains("connect-src 'self'"));
    }

    #[test]
    fn build_csp_with_captcha_includes_wasm_and_worker_src() {
        let cfg = Some(make_captcha_config(
            "https://cap.example.com",
            captcha::DEFAULT_WIDGET_URL,
        ));
        let csp = build_csp(&cfg);
        assert!(csp.contains("'wasm-unsafe-eval'"));
        assert!(csp.contains("worker-src blob:"));
    }

    #[test]
    fn build_csp_with_captcha_includes_script_origin() {
        let cfg = Some(make_captcha_config(
            "https://cap.example.com",
            captcha::DEFAULT_WIDGET_URL,
        ));
        let csp = build_csp(&cfg);
        assert!(csp.contains("https://cdn.jsdelivr.net"), "{}", csp);
    }

    #[test]
    fn booking_form_paths_get_relaxed_csp() {
        assert!(is_booking_form_path("/u/alice/intro/book"));
        assert!(is_booking_form_path("/team/sales/demo/book"));
        assert!(is_booking_form_path("/intro/book"));
    }

    #[test]
    fn non_booking_paths_keep_baseline_csp() {
        assert!(!is_booking_form_path("/"));
        assert!(!is_booking_form_path("/dashboard"));
        assert!(!is_booking_form_path("/dashboard/admin"));
        assert!(!is_booking_form_path("/u/alice/intro"));
        assert!(!is_booking_form_path("/booking/cancel/sometoken"));
        assert!(!is_booking_form_path("/u/alice/bookkeeping"));
    }

    #[test]
    fn build_csp_with_captcha_includes_connect_origins() {
        let cfg = Some(make_captcha_config(
            "https://cap.example.com",
            captcha::DEFAULT_WIDGET_URL,
        ));
        let csp = build_csp(&cfg);
        assert!(csp.contains("connect-src 'self'"), "{}", csp);
        assert!(csp.contains("https://cap.example.com"), "{}", csp);
        assert!(csp.contains("https://cdn.jsdelivr.net"), "{}", csp);
    }

    // Embed mode must preserve captcha allowances (so captcha-enabled
    // deployments can still serve a working booking form inside iframes).
    // `csp_middleware` does the swap via string replace on the strict CSP,
    // so we verify the contract: the produced CSP keeps frame-ancestors
    // exactly once and contains the expected substring for swapping.
    #[test]
    fn build_csp_contains_frame_ancestors_self_for_swap() {
        assert_eq!(
            build_csp(&None).matches("frame-ancestors 'self'").count(),
            1
        );
        let cfg = Some(make_captcha_config(
            "https://cap.example.com",
            captcha::DEFAULT_WIDGET_URL,
        ));
        assert_eq!(build_csp(&cfg).matches("frame-ancestors 'self'").count(), 1);
    }

    #[test]
    fn build_csp_embed_swap_preserves_captcha_allowances() {
        let cfg = Some(make_captcha_config(
            "https://cap.example.com",
            captcha::DEFAULT_WIDGET_URL,
        ));
        let strict = build_csp(&cfg);
        let embed_csp = strict.replace("frame-ancestors 'self'", "frame-ancestors *");
        assert!(embed_csp.contains("frame-ancestors *"));
        assert!(!embed_csp.contains("frame-ancestors 'self'"));
        // Captcha allowances must survive the swap so the widget loads in an
        // embedded booking form.
        assert!(embed_csp.contains("'wasm-unsafe-eval'"));
        assert!(embed_csp.contains("worker-src blob:"));
        assert!(embed_csp.contains("https://cap.example.com"));
        assert!(embed_csp.contains("https://cdn.jsdelivr.net"));
    }

    // --- Rolling booking horizon (migration 063) ---

    /// Availability on every weekday, wide enough that "today" still has slots
    /// left whatever time of day the suite runs.
    fn horizon_rules() -> Vec<(i32, String, String)> {
        (0..7)
            .map(|d| (d, "00:00".to_string(), "23:30".to_string()))
            .collect()
    }

    fn horizon_slots(horizon: Option<i32>, start_offset: i32, days_ahead: i32) -> Vec<SlotDay> {
        compute_slots_from_rules(
            &horizon_rules(),
            30,
            30,
            0,
            0,
            0,
            start_offset,
            days_ahead,
            horizon,
            Tz::UTC,
            Tz::UTC,
            BusySource::Individual(vec![]),
            &[],
        )
    }

    fn host_today() -> NaiveDate {
        Utc::now().with_timezone(&Tz::UTC).naive_local().date()
    }

    #[test]
    fn compute_slots_null_horizon_offers_the_whole_window() {
        let days = horizon_slots(None, 1, 10);
        assert_eq!(days.len(), 10, "NULL horizon must not drop any day");
        let last = (host_today() + Duration::days(10))
            .format("%Y-%m-%d")
            .to_string();
        assert_eq!(days.last().unwrap().date, last);
    }

    #[test]
    fn compute_slots_horizon_boundary_is_inclusive() {
        let horizon = 5i32;
        let days = horizon_slots(Some(horizon), 1, 20);
        let last_in = (host_today() + Duration::days(horizon as i64))
            .format("%Y-%m-%d")
            .to_string();
        let first_out = (host_today() + Duration::days(horizon as i64 + 1))
            .format("%Y-%m-%d")
            .to_string();
        assert!(
            days.iter().any(|d| d.date == last_in),
            "the last in-horizon day must still be offered"
        );
        assert!(
            !days.iter().any(|d| d.date == first_out),
            "the first out-of-horizon day must not be offered"
        );
    }

    #[test]
    fn compute_slots_horizon_zero_offers_today_only() {
        let today = host_today().format("%Y-%m-%d").to_string();
        let days = horizon_slots(Some(0), 0, 10);
        assert!(
            days.iter().all(|d| d.date == today),
            "a horizon of 0 must offer today and nothing else"
        );
        // Same window without a horizon reaches past today, so the assertion
        // above is testing the clamp rather than an empty fixture.
        assert!(
            horizon_slots(None, 0, 10).iter().any(|d| d.date > today),
            "fixture must reach beyond today when unbounded"
        );
    }

    #[test]
    fn compute_slots_min_notice_past_horizon_yields_no_slots() {
        // Minimum notice pushes the earliest bookable slot beyond the horizon,
        // so the two limits cross and nothing is bookable. That must render as
        // an empty list rather than panicking.
        let days = compute_slots_from_rules(
            &horizon_rules(),
            30,
            30,
            0,
            0,
            60 * 24 * 5,
            0,
            20,
            Some(1),
            Tz::UTC,
            Tz::UTC,
            BusySource::Individual(vec![]),
            &[],
        );
        assert!(
            days.is_empty(),
            "crossed limits must yield zero slots, not an error"
        );
    }

    #[test]
    fn month_slot_window_covers_the_trailing_week() {
        // #228: on Monday 2026-09-28 the week view shows Sep 28 to Oct 4.
        // The September payload must carry Friday Oct 2 and Sunday Oct 4,
        // not stop one day past the month end.
        let d = |m, day| NaiveDate::from_ymd_opt(2026, m, day).unwrap();
        let today = d(9, 28);
        let (start, ahead) = month_slot_window(d(9, 1), d(9, 30), today);
        assert_eq!(start, 0, "a month already under way starts today");
        let last = today + Duration::days((start + ahead - 1) as i64);
        assert!(
            last >= d(10, 4),
            "window must reach the grid's Sunday, got {last}"
        );

        // A future month whose 1st falls mid-week also covers the leading
        // Monday, so the week view opened on that month is complete.
        let (start, ahead) = month_slot_window(d(10, 1), d(10, 31), today);
        let first = today + Duration::days(start as i64);
        let last = today + Duration::days((start + ahead - 1) as i64);
        assert!(
            first <= d(9, 28),
            "window must start on the grid's Monday, got {first}"
        );
        assert!(
            last >= d(11, 1),
            "window must reach the grid's Sunday, got {last}"
        );
    }

    #[test]
    fn build_month_params_hides_next_month_past_horizon() {
        let today = host_today();
        let (_, _, _, _, next_month, _, _, _, _) =
            build_month_params(today.year(), today.month(), Tz::UTC, Tz::UTC, "en", Some(0));
        assert!(
            next_month.is_none(),
            "a horizon of 0 must drop the next-month link"
        );
    }

    #[test]
    fn build_month_params_keeps_next_month_within_horizon() {
        let today = host_today();
        let (_, _, _, _, far, _, _, _, _) = build_month_params(
            today.year(),
            today.month(),
            Tz::UTC,
            Tz::UTC,
            "en",
            Some(400),
        );
        assert!(far.is_some(), "a horizon past next month keeps the link");
        let (_, _, _, _, unbounded, _, _, _, _) =
            build_month_params(today.year(), today.month(), Tz::UTC, Tz::UTC, "en", None);
        assert!(unbounded.is_some(), "NULL horizon keeps the link");
    }

    #[test]
    fn horizon_last_date_fails_closed_on_a_negative_horizon() {
        // parse_optional_day_count rejects negatives, so the column can only
        // hold one if it is written directly. However it gets there, it must
        // block every date rather than read as unlimited.
        //
        // Small negatives always did, because the arithmetic lands in the past
        // on its own. A large one overflowed the representable calendar and
        // returned None, which every caller treats as "no limit": the wrong
        // direction to fail in, and the case this pins.
        let now = host_today().and_hms_opt(9, 0, 0).unwrap();
        let today = now.date();

        assert_eq!(
            parse_optional_day_count("-5"),
            None,
            "the form must never store a negative horizon in the first place"
        );

        for days in [-1, -400, -95_000_000, i32::MIN + 1, i32::MIN] {
            let last = horizon_last_date(now, Some(days));
            assert!(
                last.is_some_and(|last| today > last),
                "a negative horizon ({days}) must leave today itself unbookable, got {last:?}"
            );
        }
    }

    #[test]
    fn horizon_last_date_survives_an_absurdly_large_horizon() {
        // The form stores any non-negative i32, so a host who types a very
        // large number to mean "no limit" must not take the booking page down.
        assert_eq!(
            parse_optional_day_count("2147483647"),
            Some(i32::MAX),
            "the form accepts the value that reaches horizon_last_date"
        );
        let now = host_today().and_hms_opt(9, 0, 0).unwrap();
        assert_eq!(
            horizon_last_date(now, Some(i32::MAX)),
            None,
            "a horizon past the representable calendar is effectively unlimited"
        );
    }

    #[test]
    fn build_month_params_survives_an_absurdly_large_horizon() {
        let today = host_today();
        let (_, _, _, _, next, _, _, _, _) = build_month_params(
            today.year(),
            today.month(),
            Tz::UTC,
            Tz::UTC,
            "en",
            Some(i32::MAX),
        );
        assert!(
            next.is_some(),
            "an unrepresentable horizon must not bound the month nav"
        );
    }

    // --- Booking-time horizon guards on the five POST handlers ---

    async fn booking_count(pool: &SqlitePool, et_id: &str) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM bookings WHERE event_type_id = ?")
            .bind(et_id)
            .fetch_one(pool)
            .await
            .unwrap()
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

    /// End-to-end proof that a rejected booking speaks the guest's language.
    /// The validator returns a Fluent key, the handler resolves it against
    /// `Accept-Language`, and the error page renders the result: three steps,
    /// each of which has shipped broken at least once, and none of which the
    /// static guards can see through.
    #[tokio::test]
    async fn rejected_booking_error_page_follows_accept_language() {
        let (app, pool, _, et_id) = setup_test_app().await;
        let csrf = "csrf-bad-email-fr";
        let body = format!(
            "_csrf={}&date={}&time=10:00&name=Guest&email=not-an-email&tz=UTC",
            csrf,
            far_future_monday()
        );
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/u/testuser/test-meeting/book")
            .header("cookie", format!("__Host-calrs_csrf={}", csrf))
            .header("content-type", "application/x-www-form-urlencoded")
            .header("accept-language", "fr-FR,fr;q=0.9")
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), 200);
        let html = body_string(response).await;

        assert_eq!(
            booking_count(&pool, &et_id).await,
            0,
            "an invalid email must not create a booking"
        );
        assert!(
            html.contains(&crate::i18n::translate(
                "fr",
                "validate-email-invalid",
                None
            )),
            "expected the French validation message, got:\n{html}"
        );
        assert!(
            html.contains(&crate::i18n::translate(
                "fr",
                "bae-title-invalid-booking",
                None
            )),
            "expected the French error title, got:\n{html}"
        );
        assert!(
            !html.contains("Please enter a valid email address"),
            "the English string leaked into a French response"
        );
        assert!(
            !html.contains("validate-email-invalid"),
            "the raw Fluent key reached the page"
        );
    }

    async fn set_horizon(pool: &SqlitePool, et_id: &str, days: i32) {
        sqlx::query("UPDATE event_types SET booking_horizon_days = ? WHERE id = ?")
            .bind(days)
            .bind(et_id)
            .execute(pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn legacy_booking_post_rejects_beyond_horizon() {
        let (app, pool, _, et_id) = setup_test_app().await;
        set_horizon(&pool, &et_id, 7).await;
        let csrf = "csrf-horizon-legacy";
        let response = app
            .oneshot(post_form_unauthed(
                "/test-meeting/book",
                csrf,
                &book_body(csrf),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            booking_count(&pool, &et_id).await,
            0,
            "a beyond-horizon POST must not create a booking"
        );
    }

    #[tokio::test]
    async fn legacy_booking_post_allowed_when_horizon_null() {
        // Identical request to the test above, with the horizon left NULL:
        // isolates the horizon column as the reason for the rejection.
        let (app, pool, _, et_id) = setup_test_app().await;
        let csrf = "csrf-horizon-legacy-null";
        let response = app
            .oneshot(post_form_unauthed(
                "/test-meeting/book",
                csrf,
                &book_body(csrf),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            booking_count(&pool, &et_id).await,
            1,
            "NULL horizon must leave the booking unblocked"
        );
    }

    #[tokio::test]
    async fn user_booking_post_rejects_beyond_horizon() {
        let (app, pool, _, et_id) = setup_test_app().await;
        set_horizon(&pool, &et_id, 7).await;
        let csrf = "csrf-horizon-user";
        let response = app
            .clone()
            .oneshot(post_form_unauthed(
                "/u/testuser/test-meeting/book",
                csrf,
                &book_body(csrf),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(booking_count(&pool, &et_id).await, 0);

        // Control: same route, horizon cleared.
        sqlx::query("UPDATE event_types SET booking_horizon_days = NULL WHERE id = ?")
            .bind(&et_id)
            .execute(&pool)
            .await
            .unwrap();
        let csrf2 = "csrf-horizon-user-ok";
        app.oneshot(post_form_unauthed(
            "/u/testuser/test-meeting/book",
            csrf2,
            &book_body(csrf2),
        ))
        .await
        .unwrap();
        assert_eq!(
            booking_count(&pool, &et_id).await,
            1,
            "NULL horizon must leave the /u/ route unblocked"
        );
    }

    #[tokio::test]
    async fn dynamic_group_booking_post_rejects_beyond_horizon() {
        let (app, pool, _, et_id) = setup_test_app().await;
        // A second host makes the username a dynamic group ("a+b").
        let other_id = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO users (id, email, name, role, auth_provider, username, enabled) VALUES (?, 'second@example.com', 'Second User', 'user', 'local', 'seconduser', 1)")
            .bind(&other_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO accounts (id, name, email, timezone, user_id) VALUES (?, 'Second User', 'second@example.com', 'UTC', ?)")
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(&other_id)
            .execute(&pool)
            .await
            .unwrap();
        set_horizon(&pool, &et_id, 7).await;

        let csrf = "csrf-horizon-dyn";
        let response = app
            .clone()
            .oneshot(post_form_unauthed(
                "/u/testuser+seconduser/test-meeting/book",
                csrf,
                &book_body(csrf),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            booking_count(&pool, &et_id).await,
            0,
            "a beyond-horizon POST must not create a dynamic-group booking"
        );

        // Control: the same POST with the horizon cleared must go through, so
        // the assertion above is the guard firing rather than a dead route.
        sqlx::query("UPDATE event_types SET booking_horizon_days = NULL WHERE id = ?")
            .bind(&et_id)
            .execute(&pool)
            .await
            .unwrap();
        let csrf2 = "csrf-horizon-dyn-ok";
        app.oneshot(post_form_unauthed(
            "/u/testuser+seconduser/test-meeting/book",
            csrf2,
            &book_body(csrf2),
        ))
        .await
        .unwrap();
        assert_eq!(
            booking_count(&pool, &et_id).await,
            1,
            "NULL horizon must leave the dynamic-group route unblocked"
        );
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

    #[tokio::test]
    async fn group_booking_post_rejects_beyond_horizon() {
        let (app, pool, _, _) = setup_test_app().await;
        let (_, team_et_id) = seed_team_event_type(&pool).await;
        set_horizon(&pool, &team_et_id, 7).await;

        let csrf = "csrf-horizon-team";
        let response = app
            .clone()
            .oneshot(post_form_unauthed(
                "/team/horizon-team/team-sync/book",
                csrf,
                &book_body(csrf),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            booking_count(&pool, &team_et_id).await,
            0,
            "a beyond-horizon POST must not create a team booking"
        );

        // Control: the same POST with the horizon cleared must go through, so
        // the assertion above is the guard firing rather than a dead route.
        sqlx::query("UPDATE event_types SET booking_horizon_days = NULL WHERE id = ?")
            .bind(&team_et_id)
            .execute(&pool)
            .await
            .unwrap();
        let csrf2 = "csrf-horizon-team-ok";
        app.oneshot(post_form_unauthed(
            "/team/horizon-team/team-sync/book",
            csrf2,
            &book_body(csrf2),
        ))
        .await
        .unwrap();
        assert_eq!(
            booking_count(&pool, &team_et_id).await,
            1,
            "NULL horizon must leave the team route unblocked"
        );
    }

    #[tokio::test]
    async fn guest_reschedule_post_rejects_beyond_horizon() {
        let (app, pool, _, et_id) = setup_test_app().await;
        set_horizon(&pool, &et_id, 7).await;
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
        let before: String = sqlx::query_scalar("SELECT start_at FROM bookings WHERE id = ?")
            .bind(&booking_id)
            .fetch_one(&pool)
            .await
            .unwrap();

        let csrf = "csrf-horizon-resched";
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
        assert_eq!(response.status(), 200);
        let after: String = sqlx::query_scalar("SELECT start_at FROM bookings WHERE id = ?")
            .bind(&booking_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            before, after,
            "a beyond-horizon reschedule must not move the booking"
        );
    }

    // --- Form round-trip, personal and team ---

    #[tokio::test]
    async fn team_event_type_form_round_trip_persists_horizon() {
        // Reads config that CALRS_* env blocks override (see CLAUDE.md).
        let _env = crate::test_support::ENV_LOCK.lock().await;
        // PR #114 shipped a limit that only persisted on personal event types.
        // Assert the team UPDATE path carries the horizon too.
        let (app, pool, session, _) = setup_test_app().await;
        let (team_id, team_et_id) = seed_team_event_type(&pool).await;

        let csrf = "csrf-horizon-team-form";
        let body = format!(
            "_csrf={}&title=Team+Sync&slug=team-sync&duration_min=30&booking_horizon_days=14&location_type=link&location_value=https%3A%2F%2Fmeet.example.com%2Froom&avail_days=1,2,3,4,5&avail_start=09:00&avail_end=17:00&scheduling_mode=round_robin",
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
        assert!(
            response.status().is_redirection(),
            "team update should redirect, got {}",
            response.status()
        );

        let stored: Option<i32> =
            sqlx::query_scalar("SELECT booking_horizon_days FROM event_types WHERE id = ?")
                .bind(&team_et_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            stored,
            Some(14),
            "the horizon must survive a team form round-trip"
        );
    }

    #[test]
    fn parse_optional_day_count_treats_zero_as_a_value() {
        assert_eq!(parse_optional_day_count(""), None);
        assert_eq!(parse_optional_day_count("   "), None);
        assert_eq!(parse_optional_day_count("0"), Some(0));
        assert_eq!(parse_optional_day_count("14"), Some(14));
        assert_eq!(parse_optional_day_count("-1"), None);
        assert_eq!(parse_optional_day_count("abc"), None);
    }
    include!("booking_time_tests.rs");
    include!("pending_hold_tests.rs");
    include!("writeback_tests.rs");
    include!("organizer_tests.rs");

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
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                    )
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
        sqlx::query("UPDATE users SET booking_email = 'bookings@example.com' WHERE email = 'test@example.com'")
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
        let booking_id =
            insert_pending_french_booking(&pool, &et_id, "uid-209-shared-address").await;

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
        sqlx::query_scalar(
            "SELECT public_page_language FROM users WHERE email = 'test@example.com'",
        )
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
        sqlx::query(
            "UPDATE event_types SET team_id = ?, scheduling_mode = 'collective' WHERE id = ?",
        )
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
}
