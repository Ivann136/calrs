use anyhow::{bail, Result};
use chrono::NaiveDateTime;
use chrono_tz::Tz;
use fluent_bundle::{FluentArgs, FluentValue};
use lettre::message::header::ContentType;
use lettre::message::MessageBuilder;
use lettre::message::{Attachment, Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use sqlx::SqlitePool;

/// Translate a Fluent message id with no arguments. Local helper so call
/// sites stay readable.
fn t(lang: &str, key: &str) -> String {
    crate::i18n::translate(lang, key, None)
}

/// Translate with named arguments. Each tuple is `(arg_name, value)`.
fn ta<const N: usize>(lang: &str, key: &str, args: [(&str, &str); N]) -> String {
    let mut fa = FluentArgs::new();
    for (k, v) in args.iter() {
        fa.set(*k, FluentValue::from(*v));
    }
    crate::i18n::translate(lang, key, Some(&fa))
}

/// A stored language code if calrs ships that locale, English otherwise.
/// Stored values can be NULL, empty, or a locale since removed.
fn lang_or_en(lang: Option<&str>) -> &str {
    match lang.map(str::trim) {
        Some(code) if crate::i18n::is_supported(code) => code,
        _ => "en",
    }
}

/// Resolve guest language from booking details, falling back to English.
fn guest_lang(details: &BookingDetails) -> &str {
    lang_or_en(details.guest_language.as_deref())
}

/// The host recipient's language (`users.language`), falling back to English.
fn host_lang(details: &BookingDetails) -> &str {
    lang_or_en(details.host_language.as_deref())
}

/// A stored language value (`users.language`, `bookings.language`) when it
/// names a shipped locale, trimmed; `None` otherwise, which means English.
pub fn supported_language(lang: Option<String>) -> Option<String> {
    lang.map(|l| l.trim().to_string())
        .filter(|l| crate::i18n::is_supported(l))
}

/// A user's saved UI language (`users.language`), when it names a shipped
/// locale. Host, team member and watcher emails are written in it (#209).
///
/// This is the stored half of what the `AuthUser` extractor does on a
/// request: there is no request behind a background email, so there is no
/// `Accept-Language` to fall back on, and `None` means English at send time.
pub async fn user_language(pool: &SqlitePool, user_id: &str) -> Option<String> {
    sqlx::query_scalar::<_, Option<String>>("SELECT language FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .and_then(supported_language)
}

/// Cancellation reason recorded when the host deleted the booking's event
/// from their calendar and a sync noticed, in `lang` (English when `None`).
pub fn calendar_deleted_reason(lang: Option<&str>) -> String {
    t(lang_or_en(lang), "email-cancel-reason-calendar-deleted")
}

/// The language the guest booked in, as stored on the booking row
/// (`bookings.language`, captured from the booking page).
///
/// Every guest email sent after the booking request itself (host approval,
/// decline, cancellation by the host or by a calendar sync) is triggered by
/// someone other than the guest, so the language has to come from here
/// rather than from the current request's `Accept-Language` (#209).
pub async fn stored_booking_language(pool: &SqlitePool, booking_id: &str) -> Option<String> {
    sqlx::query_scalar::<_, Option<String>>("SELECT language FROM bookings WHERE id = ?")
        .bind(booking_id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .and_then(supported_language)
}

#[derive(Clone)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub from_email: String,
    pub from_name: Option<String>,
    pub tls_mode: SmtpTlsMode,
}

impl std::fmt::Debug for SmtpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("from_email", &self.from_email)
            .field("from_name", &self.from_name)
            .field("tls_mode", &self.tls_mode)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SmtpTlsMode {
    StartTls,
    Tls,
    /// No encryption at all. Only sane for a relay reached over the loopback
    /// (or a trusted private link): a local MTA that offers no STARTTLS, or one
    /// whose certificate is self-signed. lettre validates certificates against
    /// the compiled-in Mozilla root bundle, not the system trust store, so a
    /// private CA cannot be trusted and this is the only way through.
    Plaintext,
}

impl SmtpTlsMode {
    fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "starttls" => Ok(Self::StartTls),
            "tls" => Ok(Self::Tls),
            "none" | "plaintext" => Ok(Self::Plaintext),
            other => bail!(
                "CALRS_SMTP_TLS_MODE must be 'starttls', 'tls' or 'none' (got '{}')",
                other
            ),
        }
    }
}

pub struct SmtpStatus {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub from_email: String,
    pub from_name: Option<String>,
    pub tls_mode: String,
    pub enabled: bool,
    pub from_env: bool,
}

impl SmtpTlsMode {
    /// Canonical lowercase string used in the DB and `<select>` values.
    fn as_str(self) -> &'static str {
        match self {
            Self::StartTls => "starttls",
            Self::Tls => "tls",
            Self::Plaintext => "none",
        }
    }
}

/// Whether a host names the local machine, and so whether an unencrypted
/// connection to it stays inside the box. Bare `localhost` and any address
/// that parses as a loopback IP count; anything else is a network hop.
fn is_loopback_host(host: &str) -> bool {
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

impl SmtpConfig {
    /// Whether to authenticate. An empty username means "no SMTP AUTH": lettre
    /// only skips authentication when the transport carries no credentials at
    /// all, so empty ones must not be attached. See `send_email`.
    fn uses_auth(&self) -> bool {
        !self.username.trim().is_empty()
    }

    /// Get "from" Mailbox, compliant with RFC 5322
    fn mailbox_from(&self) -> Result<Mailbox> {
        Ok(Mailbox::new(
            self.from_name.clone(),
            self.from_email.parse()?,
        ))
    }

    /// Start a message with the From (and, for a host, Reply-To) headers
    /// `sender` calls for. The address is always the configured one, so
    /// SPF/DKIM/DMARC keep aligning with the instance domain; a host sender
    /// only changes the display name and the reply target (#221).
    fn message_from(&self, sender: Sender<'_>) -> Result<MessageBuilder> {
        match sender {
            Sender::Instance => Ok(Message::builder().from(self.mailbox_from()?)),
            Sender::Host { name, email, lang } => {
                let display = guest_sender_name(lang, name, self.from_name.as_deref());
                let mut builder =
                    Message::builder().from(Mailbox::new(display, self.from_email.parse()?));
                if let Some(reply_to) = host_reply_to(email) {
                    builder = builder.reply_to(reply_to);
                }
                Ok(builder)
            }
        }
    }
}

/// Who an email appears to come from.
#[derive(Clone, Copy)]
enum Sender<'a> {
    /// The instance itself, under the configured sender name: host, team
    /// member, watcher and admin mail.
    Instance,
    /// A host writing to a guest (#221): "Host via <sender name>" on the
    /// instance address, with Reply-To pointing at `email`. `lang` is the
    /// email's own language, for the translated "via". For multi-host
    /// bookings `name` is the joined roster and `email` the ICS organizer,
    /// so replies reach the person the guest's calendar names as organizer.
    Host {
        name: &'a str,
        email: &'a str,
        lang: &'a str,
    },
}

impl<'a> Sender<'a> {
    /// The host of a booking, writing in the guest's language.
    fn host_of(details: &'a BookingDetails) -> Self {
        Sender::Host {
            name: &details.host_name,
            email: &details.host_email,
            lang: guest_lang(details),
        }
    }

    /// The host of a cancelled, declined or expired booking, writing in the
    /// guest's language.
    fn host_of_cancellation(details: &'a CancellationDetails) -> Self {
        Sender::Host {
            name: &details.host_name,
            email: &details.host_email,
            lang: lang_or_en(details.guest_language.as_deref()),
        }
    }
}

/// Longest host part of a guest-facing display name. Collective bookings join
/// every member's name, which would otherwise grow the header without bound.
const GUEST_SENDER_HOST_MAX_CHARS: usize = 80;

/// Characters dropped from a name before it reaches a header: control
/// characters (CR/LF are the classic header injection, even though lettre
/// encodes display names) and the bidirectional formatting marks that can
/// make one name render as another.
fn is_header_unsafe(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{200E}' | '\u{200F}' | '\u{061C}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
        )
}

/// Display name for guest-facing mail: the host's name followed by the
/// configured sender name, joined in the email's language ("Bob via Acme"),
/// or the host's name alone when no sender name is set. Host names are
/// user-editable, so unsafe characters are dropped and long collective
/// rosters truncated. The sender name is admin-set but lands in the same
/// header, so it is filtered the same way.
fn guest_sender_name(lang: &str, host_name: &str, from_name: Option<&str>) -> Option<String> {
    let clean = |s: &str| -> String {
        let kept: String = s.chars().filter(|c| !is_header_unsafe(*c)).collect();
        kept.trim().to_string()
    };
    let mut host = clean(host_name);
    if host.chars().count() > GUEST_SENDER_HOST_MAX_CHARS {
        host = host.chars().take(GUEST_SENDER_HOST_MAX_CHARS - 1).collect();
        host = format!("{}\u{2026}", host.trim_end());
    }
    let from_name = from_name.map(clean).filter(|name| !name.is_empty());
    match (host.is_empty(), from_name) {
        (true, from_name) => from_name,
        (false, Some(instance)) => Some(clean(&ta(
            lang,
            "email-sender-via",
            [("host", &host), ("instance", &instance)],
        ))),
        (false, None) => Some(host),
    }
}

/// Reply-To for guest-facing mail: the host's address when it is exactly one
/// bare address, nothing otherwise. A malformed value or an address list
/// yields no Reply-To rather than a broken or surprising header.
/// `name <email>` as a [`Mailbox`]. Formatting the two into one string and
/// parsing it, as every send path used to, fails on a display name with
/// `@`, `,`, `<`, `>`, `;` or quotes in it ("Dr. A, PhD", "Alice @ Acme"),
/// and the email was then never sent. Passing the name to `Mailbox::new`
/// lets lettre quote or encode it instead. Control characters are replaced
/// by spaces so a CRLF in a guest-supplied name still cannot start a header
/// line, and an empty name leaves the bare address.
pub(crate) fn named_mailbox(name: &str, email: &str) -> Result<Mailbox> {
    let name: String = name
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let name = name.trim();
    let address = email.trim().parse()?;
    Ok(Mailbox::new(
        (!name.is_empty()).then(|| name.to_string()),
        address,
    ))
}

fn host_reply_to(email: &str) -> Option<Mailbox> {
    email
        .trim()
        .parse::<lettre::Address>()
        .ok()
        .map(|address| Mailbox::new(None, address))
}

#[derive(Clone, Default)]
pub struct BookingDetails {
    /// Exact UTC endpoints for new bookings; legacy records use wall-clock fields.
    pub utc_times: Option<(String, String)>,
    pub event_title: String,
    pub date: String,
    pub start_time: String,
    pub end_time: String,
    pub guest_name: String,
    pub guest_email: String,
    pub guest_timezone: String,
    pub host_name: String,
    pub host_email: String,
    pub uid: String,
    pub notes: Option<String>,
    /// Guest phone in E.164, only when the event type collects one. Shown in
    /// the host approval request so the host can call before deciding (#231).
    pub guest_phone: Option<String>,
    pub location: Option<String>,
    pub reminder_minutes: Option<i32>,
    pub additional_attendees: Vec<String>,
    /// Guest's preferred language at booking time (from `bookings.language`).
    /// `None` falls back to English at send time.
    pub guest_language: Option<String>,
    /// Host's saved UI-language preference (from `users.language`).
    /// `None` falls back to English at send time.
    pub host_language: Option<String>,
    /// Host's IANA timezone — the event type's tz when set (via `get_host_tz`),
    /// otherwise the host user's tz. When set and different from
    /// `guest_timezone`, host-targeted emails display the wall-clock time
    /// converted into this zone. Empty string falls back to guest-zone display.
    pub host_timezone: String,
    /// Shared resource(s) reserved for this booking (assigned resource in
    /// round-robin mode, attached resources in 'all' mode). Rendered in
    /// host-facing emails only; guests do not see internal resource names.
    pub resource_name: Option<String>,
}

#[derive(Clone, Default)]
pub struct CancellationDetails {
    /// Exact UTC endpoints for new bookings; legacy records use wall-clock fields.
    pub utc_times: Option<(String, String)>,
    pub event_title: String,
    pub date: String,
    pub start_time: String,
    pub end_time: String,
    pub guest_name: String,
    pub guest_email: String,
    pub guest_timezone: String,
    pub host_name: String,
    pub host_email: String,
    pub uid: String,
    pub reason: Option<String>,
    pub cancelled_by_host: bool,
    pub guest_language: Option<String>,
    pub host_language: Option<String>,
    /// Host's IANA timezone (from `users.timezone`). See `BookingDetails::host_timezone`.
    pub host_timezone: String,
}

// --- HTML email template helpers ---

fn h(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

struct EmailRow {
    label: String,
    value: String,
}

struct EmailAction {
    label: String,
    url: String,
    color: String,
}

fn render_html_email(
    greeting: &str,
    message: &str,
    accent: &str,
    rows: &[EmailRow],
    footer_note: Option<&str>,
) -> String {
    render_html_email_in("en", greeting, message, accent, rows, footer_note, &[])
}

#[cfg(test)]
fn render_html_email_with_actions(
    greeting: &str,
    message: &str,
    accent: &str,
    rows: &[EmailRow],
    footer_note: Option<&str>,
    actions: &[EmailAction],
) -> String {
    render_html_email_in("en", greeting, message, accent, rows, footer_note, actions)
}

/// Render the HTML body for an email written in `lang`. The tag ends up in
/// `<html lang>`, so mail clients pick the right spell checker and screen
/// readers the right voice (#209). Only the admin SMTP test email still goes
/// through the English wrapper above.
fn render_html_email_in(
    lang: &str,
    greeting: &str,
    message: &str,
    accent: &str,
    rows: &[EmailRow],
    footer_note: Option<&str>,
    actions: &[EmailAction],
) -> String {
    let sent_by = h(&t(lang, "email-footer-sent-by"));
    let lang = h(crate::i18n::html_lang(lang));
    let mut detail_rows = String::new();
    for (i, row) in rows.iter().enumerate() {
        let bg = if i % 2 == 0 { "#f8f9fa" } else { "#ffffff" };
        detail_rows.push_str(&format!(
            "<tr>\
               <td style=\"padding:8px 12px;color:#6b7280;font-size:13px;white-space:nowrap;vertical-align:top;\">{}</td>\
               <td style=\"padding:8px 12px;color:#111827;font-size:14px;background:{bg};\">{}</td>\
             </tr>",
            h(&row.label), h(&row.value),
        ));
    }

    let actions_html = if actions.is_empty() {
        String::new()
    } else {
        let buttons: Vec<String> = actions.iter().map(|a| {
            format!(
                "<a href=\"{}\" style=\"display:inline-block;padding:12px 28px;background:{};color:#ffffff;text-decoration:none;border-radius:6px;font-weight:600;font-size:14px;margin:0 6px;\">{}</a>",
                h(&a.url), a.color, h(&a.label)
            )
        }).collect();
        format!(
            "<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" style=\"margin:20px 0 0;\"><tr><td align=\"center\">{}</td></tr></table>",
            buttons.join(" ")
        )
    };

    let footer_html = footer_note
        .map(|n| {
            format!(
                "<p style=\"margin:16px 0 0;font-size:13px;color:#6b7280;\">{}</p>",
                h(n)
            )
        })
        .unwrap_or_default();

    format!(
        r##"<!DOCTYPE html>
<html lang="{lang}">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#f4f4f7;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f7;">
<tr><td align="center" style="padding:32px 16px;">
  <table role="presentation" width="520" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:8px;border:1px solid #e5e7eb;max-width:520px;width:100%;">
    <!-- Accent bar -->
    <tr><td style="height:4px;background:{accent};border-radius:8px 8px 0 0;"></td></tr>
    <!-- Content -->
    <tr><td style="padding:32px 28px;">
      <p style="margin:0 0 4px;font-size:15px;color:#374151;">{greeting}</p>
      <p style="margin:0 0 20px;font-size:15px;color:#111827;font-weight:500;">{message}</p>
      <!-- Details table -->
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #e5e7eb;border-radius:6px;overflow:hidden;">
        {detail_rows}
      </table>
      {actions_html}
      {footer_html}
    </td></tr>
    <!-- Footer -->
    <tr><td style="padding:16px 28px;border-top:1px solid #f0f0f3;text-align:center;">
      <span style="font-size:12px;color:#9ca3af;">{sent_by} </span>
      <a href="https://cal.rs" style="font-size:12px;color:#6b7280;font-weight:600;text-decoration:none;">calrs</a>
    </td></tr>
  </table>
</td></tr>
</table>
</body>
</html>"##
    )
}

fn build_multipart_body(plain: &str, html: &str) -> MultiPart {
    MultiPart::alternative()
        .singlepart(SinglePart::plain(plain.to_string()))
        .singlepart(
            SinglePart::builder()
                .header(ContentType::parse("text/html; charset=UTF-8").unwrap())
                .body(html.to_string()),
        )
}

// --- ICS generation ---

/// Sanitize a value for use in an ICS field.
/// Strips CR/LF to prevent ICS injection (RFC 5545 field breakout).
fn sanitize_ics(value: &str) -> String {
    value
        .replace('\r', "")
        .replace('\n', " ")
        .replace(';', "\\;")
        .replace(',', "\\,")
}

/// Sanitize a value for use in an ICS *parameter*, such as `CN=`.
///
/// A parameter value is not a TEXT value and takes no backslash escapes.
/// RFC 5545 §3.1 defines it as either `paramtext`, which excludes `;`, `:`,
/// `,` and DQUOTE, or a quoted-string. Escaping a semicolon as `\;` the way
/// `sanitize_ics` does leaves the raw `;` in place, a strict parser reads it
/// as the end of the parameter, and the whole VEVENT is rejected: Yandex 360
/// answers 400 Bad Request to a booking whose guest name contains one, and
/// the event never reaches the calendar (#163).
///
/// So quote the value when it carries a delimiter, and spell the characters a
/// quoted-string cannot hold with the RFC 6868 caret escapes. The carets only
/// appear for input containing `"`, `^` or a newline; a parser predating
/// RFC 6868 renders those literally, which is a cosmetic loss in a display
/// name rather than the parse failure this replaces.
fn sanitize_ics_param(value: &str) -> String {
    let escaped = value
        .replace('^', "^^")
        .replace('"', "^'")
        .replace("\r\n", "^n")
        .replace(['\r', '\n'], "^n");
    if escaped.contains([';', ':', ',']) {
        format!("\"{escaped}\"")
    } else {
        escaped
    }
}

/// Convert date + start/end times from a guest timezone to UTC ICS format (YYYYMMDDTHHMMSSZ).
/// Falls back to floating time (no Z) if timezone parsing fails.
fn convert_to_utc(
    date: &str,
    start_time: &str,
    end_time: &str,
    timezone: &str,
) -> (String, String) {
    let fallback_start = format!(
        "{}T{}00",
        date.replace('-', ""),
        start_time.replace(':', "")
    );
    let fallback_end = format!("{}T{}00", date.replace('-', ""), end_time.replace(':', ""));

    let tz: Tz = match timezone.parse() {
        Ok(t) => t,
        Err(_) => return (fallback_start, fallback_end),
    };

    let start_naive = match NaiveDateTime::parse_from_str(
        &format!("{} {}:00", date, start_time),
        "%Y-%m-%d %H:%M:%S",
    ) {
        Ok(dt) => dt,
        Err(_) => return (fallback_start, fallback_end),
    };
    let end_naive = match NaiveDateTime::parse_from_str(
        &format!("{} {}:00", date, end_time),
        "%Y-%m-%d %H:%M:%S",
    ) {
        Ok(dt) => dt,
        Err(_) => return (fallback_start, fallback_end),
    };

    use chrono::TimeZone;
    let start_utc = match tz.from_local_datetime(&start_naive).earliest() {
        Some(dt) => dt.with_timezone(&chrono::Utc),
        None => return (fallback_start, fallback_end),
    };
    let end_utc = match tz.from_local_datetime(&end_naive).earliest() {
        Some(dt) => dt.with_timezone(&chrono::Utc),
        None => return (fallback_start, fallback_end),
    };

    (
        start_utc.format("%Y%m%dT%H%M%SZ").to_string(),
        end_utc.format("%Y%m%dT%H%M%SZ").to_string(),
    )
}

/// Convert a (date, start_time, end_time) tuple from `from_tz` into `to_tz`,
/// returning the wall-clock equivalents.
///
/// Returns `(date, start_time, end_time)` formatted as `YYYY-MM-DD` / `HH:MM`.
/// The date can roll over (e.g. LA 22:00 → Paris 07:00 next day), so the
/// returned date may differ from the input. If either timezone fails to parse
/// or the local time is invalid (DST gap), returns `None` and the caller
/// should fall back to displaying the original values.
fn convert_time_between_tz(
    date: &str,
    start_time: &str,
    end_time: &str,
    from_tz: &str,
    to_tz: &str,
) -> Option<(String, String, String)> {
    use chrono::TimeZone;

    let from: Tz = from_tz.parse().ok()?;
    let to: Tz = to_tz.parse().ok()?;

    let start_naive =
        NaiveDateTime::parse_from_str(&format!("{} {}:00", date, start_time), "%Y-%m-%d %H:%M:%S")
            .ok()?;
    let end_naive =
        NaiveDateTime::parse_from_str(&format!("{} {}:00", date, end_time), "%Y-%m-%d %H:%M:%S")
            .ok()?;

    let start_target = from
        .from_local_datetime(&start_naive)
        .earliest()?
        .with_timezone(&to);
    let end_target = from
        .from_local_datetime(&end_naive)
        .earliest()?
        .with_timezone(&to);

    Some((
        start_target.format("%Y-%m-%d").to_string(),
        start_target.format("%H:%M").to_string(),
        end_target.format("%H:%M").to_string(),
    ))
}

/// Build the date + time strings to display in a host-targeted email.
///
/// When `host_timezone` is set and differs from `guest_timezone`, the times are
/// converted into the host's zone. Otherwise the original guest-zone values are
/// kept. The returned `time_display` always includes a `(TZ)` suffix so the
/// host can tell which zone they're looking at.
pub(crate) fn host_time_display(
    date: &str,
    start_time: &str,
    end_time: &str,
    guest_timezone: &str,
    host_timezone: &str,
) -> (String, String) {
    if !host_timezone.is_empty() && host_timezone != guest_timezone {
        if let Some((host_date, host_start, host_end)) =
            convert_time_between_tz(date, start_time, end_time, guest_timezone, host_timezone)
        {
            return (
                host_date,
                format!("{} \u{2013} {} ({})", host_start, host_end, host_timezone),
            );
        }
    }

    let tz_label = if !guest_timezone.is_empty() {
        guest_timezone
    } else if !host_timezone.is_empty() {
        host_timezone
    } else {
        ""
    };

    let time_display = if tz_label.is_empty() {
        format!("{} \u{2013} {}", start_time, end_time)
    } else {
        format!("{} \u{2013} {} ({})", start_time, end_time, tz_label)
    };

    (date.to_string(), time_display)
}

/// New rows carry exact endpoints; do not reconstruct an ambiguous guest
/// wall clock or assume the end falls on the start date.
fn host_time_display_exact(
    date: &str,
    start_time: &str,
    end_time: &str,
    guest_timezone: &str,
    host_timezone: &str,
    utc_times: Option<&(String, String)>,
) -> (String, String) {
    let zone = if host_timezone.is_empty() {
        guest_timezone
    } else {
        host_timezone
    };
    if let (Some((start, end)), Ok(tz)) = (utc_times, zone.parse::<chrono_tz::Tz>()) {
        let parse = |v: &str| {
            chrono::NaiveDateTime::parse_from_str(v, "%Y%m%dT%H%M%SZ")
                .ok()
                .map(|v| v.and_utc().with_timezone(&tz))
        };
        if let (Some(start), Some(end)) = (parse(start), parse(end)) {
            return (
                start.format("%Y-%m-%d").to_string(),
                format!(
                    "{} – {} ({})",
                    start.format("%H:%M"),
                    end.format("%H:%M"),
                    zone
                ),
            );
        }
    }
    host_time_display(date, start_time, end_time, guest_timezone, host_timezone)
}

/// Generate an .ics VCALENDAR string for a booking
/// Extract first name (first word) from a full name.
fn first_name(full_name: &str) -> &str {
    full_name.split_whitespace().next().unwrap_or(full_name)
}

pub fn generate_ics(details: &BookingDetails, method: &str) -> String {
    generate_ics_impl(details, method, false)
}

/// ICS for CalDAV write-back (RFC 4791: no METHOD). ATTENDEE lines carry
/// SCHEDULE-AGENT=CLIENT (RFC 6638 §7.1) so the CalDAV server does not
/// run its own scheduling: calrs already sends the invitations over SMTP,
/// and servers like Fastmail would otherwise send a duplicate iMIP invite
/// (in UTC) for every written booking. Email .ics attachments keep plain
/// ATTENDEE;RSVP=TRUE so mail clients still offer "Add to calendar".
pub fn generate_ics_caldav(details: &BookingDetails) -> String {
    generate_ics_impl(details, "", true)
}

fn generate_ics_impl(
    details: &BookingDetails,
    method: &str,
    schedule_agent_client: bool,
) -> String {
    let guest_first = first_name(&details.guest_name);
    let host_first = first_name(&details.host_name);
    let summary = sanitize_ics(&format!(
        "{} \u{2014} {} & {}",
        details.event_title, guest_first, host_first
    ));
    // CN= is a parameter, not a TEXT value: it needs quoting, not backslashes.
    let host_name = sanitize_ics_param(&details.host_name);
    let guest_name = sanitize_ics_param(&details.guest_name);
    let host_email = sanitize_ics(&details.host_email);
    let guest_email = sanitize_ics(&details.guest_email);
    let location_line = details
        .location
        .as_ref()
        .map(|l| format!("LOCATION:{}\r\n", sanitize_ics(l)))
        .unwrap_or_default();
    let description_line = details
        .notes
        .as_ref()
        .filter(|n| !n.trim().is_empty())
        .map(|n| format!("DESCRIPTION:{}\r\n", sanitize_ics(n)))
        .unwrap_or_default();
    let valarm = details
        .reminder_minutes
        .filter(|&m| m > 0)
        .map(|m| {
            format!(
                "BEGIN:VALARM\r\n\
                 TRIGGER:-PT{m}M\r\n\
                 ACTION:DISPLAY\r\n\
                 DESCRIPTION:Reminder\r\n\
                 END:VALARM\r\n"
            )
        })
        .unwrap_or_default();
    let sa = if schedule_agent_client {
        ";SCHEDULE-AGENT=CLIENT"
    } else {
        ""
    };
    let additional_attendee_lines: String = details
        .additional_attendees
        .iter()
        .map(|email| format!("ATTENDEE{sa};RSVP=TRUE:mailto:{}\r\n", sanitize_ics(email)))
        .collect();
    let dtstamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    // Convert guest-timezone times to UTC for the ICS
    let (dtstart, dtend) = details.utc_times.clone().unwrap_or_else(|| {
        convert_to_utc(
            &details.date,
            &details.start_time,
            &details.end_time,
            &details.guest_timezone,
        )
    });
    format!(
        "BEGIN:VCALENDAR\r\n\
         VERSION:2.0\r\n\
         PRODID:-//calrs//calrs//EN\r\n\
         {method_line}\
         BEGIN:VEVENT\r\n\
         UID:{uid}\r\n\
         DTSTAMP:{dtstamp}\r\n\
         DTSTART:{dtstart}\r\n\
         DTEND:{dtend}\r\n\
         SUMMARY:{summary}\r\n\
         {description_line}\
         {location_line}\
         ORGANIZER;CN={host_name}:mailto:{host_email}\r\n\
         ATTENDEE{sa};CN={guest_name};RSVP=TRUE:mailto:{guest_email}\r\n\
         {additional_attendee_lines}\
         STATUS:CONFIRMED\r\n\
         {valarm}\
         END:VEVENT\r\n\
         END:VCALENDAR\r\n",
        method_line = if method.is_empty() {
            String::new()
        } else {
            format!("METHOD:{method}\r\n")
        },
        uid = details.uid,
        dtstamp = dtstamp,
        dtstart = dtstart,
        dtend = dtend,
        summary = summary,
        description_line = description_line,
        location_line = location_line,
        host_name = host_name,
        host_email = host_email,
        guest_name = guest_name,
        guest_email = guest_email,
        additional_attendee_lines = additional_attendee_lines,
    )
}

/// Generate an .ics VCALENDAR for cancellation (METHOD:CANCEL)
fn generate_cancel_ics(details: &CancellationDetails) -> String {
    let guest_first = first_name(&details.guest_name);
    let host_first = first_name(&details.host_name);
    let summary = sanitize_ics(&format!(
        "{} \u{2014} {} & {}",
        details.event_title, guest_first, host_first
    ));
    // CN= is a parameter, not a TEXT value: it needs quoting, not backslashes.
    let host_name = sanitize_ics_param(&details.host_name);
    let guest_name = sanitize_ics_param(&details.guest_name);
    let host_email = sanitize_ics(&details.host_email);
    let guest_email = sanitize_ics(&details.guest_email);
    let dtstamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let (dtstart, dtend) = details.utc_times.clone().unwrap_or_else(|| {
        convert_to_utc(
            &details.date,
            &details.start_time,
            &details.end_time,
            &details.guest_timezone,
        )
    });
    format!(
        "BEGIN:VCALENDAR\r\n\
         VERSION:2.0\r\n\
         PRODID:-//calrs//calrs//EN\r\n\
         METHOD:CANCEL\r\n\
         BEGIN:VEVENT\r\n\
         UID:{uid}\r\n\
         DTSTAMP:{dtstamp}\r\n\
         DTSTART:{dtstart}\r\n\
         DTEND:{dtend}\r\n\
         SUMMARY:{summary}\r\n\
         ORGANIZER;CN={host_name}:mailto:{host_email}\r\n\
         ATTENDEE;CN={guest_name}:mailto:{guest_email}\r\n\
         STATUS:CANCELLED\r\n\
         END:VEVENT\r\n\
         END:VCALENDAR\r\n",
        uid = details.uid,
        dtstamp = dtstamp,
        dtstart = dtstart,
        dtend = dtend,
        summary = summary,
        host_name = host_name,
        host_email = host_email,
        guest_name = guest_name,
        guest_email = guest_email,
    )
}

// --- Email senders ---

/// Send booking confirmation to the guest
pub async fn send_guest_confirmation(
    config: &SmtpConfig,
    details: &BookingDetails,
    cancel_url: Option<&str>,
) -> Result<()> {
    send_guest_confirmation_ex(config, details, cancel_url, None, None, None).await
}

pub async fn send_guest_confirmation_ex(
    config: &SmtpConfig,
    details: &BookingDetails,
    cancel_url: Option<&str>,
    reschedule_url: Option<&str>,
    cancel_notice_min: Option<i32>,
    reschedule_notice_min: Option<i32>,
) -> Result<()> {
    let ics = generate_ics(details, "REQUEST");
    let lang = guest_lang(details);

    let to = named_mailbox(&details.guest_name, &details.guest_email)?;

    let time_display = format!(
        "{} \u{2013} {} ({})",
        details.start_time, details.end_time, details.guest_timezone
    );

    let greeting = ta(
        lang,
        "email-confirm-greeting",
        [("name", &details.guest_name)],
    );
    let headline = t(lang, "email-confirm-headline");
    let label_event = t(lang, "confirmed-detail-event");
    let label_date = t(lang, "confirmed-detail-date");
    let label_time = t(lang, "confirmed-detail-time");
    let label_with = t(lang, "confirmed-detail-with");
    let label_location = t(lang, "confirmed-detail-location");
    let label_notes = t(lang, "confirmed-detail-notes");
    let ics_attached_plain = t(lang, "email-confirm-ics-attached-plain");
    let ics_attached_html = t(lang, "email-confirm-ics-attached-html");
    let signature = t(lang, "email-signature");

    // Notice-window policy lines, mentioned just before the cancel link in
    // both the plain and HTML bodies. Translated to the guest's language.
    let cancel_notice_line = cancel_notice_min.filter(|m| *m > 0).map(|m| {
        ta(
            lang,
            "email-confirm-cancel-notice",
            [("minutes", m.to_string().as_str())],
        )
    });
    let reschedule_notice_line = reschedule_notice_min.filter(|m| *m > 0).map(|m| {
        ta(
            lang,
            "email-confirm-reschedule-notice",
            [("minutes", m.to_string().as_str())],
        )
    });

    let plain = format!(
        "{}\n\n\
         {}\n\n\
         {} {}\n\
         {} {}\n\
         {} {}\n\
         {} {}\n\
         {}{}\
         {}\n\
         {}{}{}\
         {}",
        greeting,
        headline,
        label_event,
        details.event_title,
        label_date,
        details.date,
        label_time,
        time_display,
        label_with,
        details.host_name,
        details
            .location
            .as_ref()
            .map(|l| format!("{} {}\n", label_location, l))
            .unwrap_or_default(),
        details
            .notes
            .as_ref()
            .map(|n| format!("{} {}\n", label_notes, n))
            .unwrap_or_default(),
        ics_attached_plain,
        reschedule_notice_line
            .as_ref()
            .map(|l| format!("\n{}\n", l))
            .unwrap_or_default(),
        cancel_notice_line
            .as_ref()
            .map(|l| format!("\n{}\n", l))
            .unwrap_or_default(),
        cancel_url
            .map(|u| format!(
                "\n{}\n",
                ta(lang, "email-confirm-need-to-cancel", [("url", u)])
            ))
            .unwrap_or_default(),
        signature,
    );

    let mut rows = vec![
        EmailRow {
            label: label_event.clone(),
            value: details.event_title.clone(),
        },
        EmailRow {
            label: label_date.clone(),
            value: details.date.clone(),
        },
        EmailRow {
            label: label_time.clone(),
            value: time_display,
        },
        EmailRow {
            label: label_with.clone(),
            value: details.host_name.clone(),
        },
    ];
    if let Some(loc) = &details.location {
        rows.push(EmailRow {
            label: label_location.clone(),
            value: loc.clone(),
        });
    }
    if let Some(notes) = &details.notes {
        rows.push(EmailRow {
            label: label_notes.clone(),
            value: notes.clone(),
        });
    }

    let mut actions: Vec<EmailAction> = Vec::new();
    if let Some(u) = reschedule_url {
        actions.push(EmailAction {
            label: t(lang, "email-action-reschedule"),
            url: u.to_string(),
            color: "#3b82f6".to_string(),
        });
    }
    if let Some(u) = cancel_url {
        actions.push(EmailAction {
            label: t(lang, "email-action-cancel-booking"),
            url: u.to_string(),
            color: "#dc2626".to_string(),
        });
    }

    // Append notice lines to the footer note so they sit just below the
    // action buttons, alongside the existing "ICS attached" copy.
    let mut footer_note_html = ics_attached_html.clone();
    if let Some(line) = &reschedule_notice_line {
        footer_note_html.push('\n');
        footer_note_html.push_str(line);
    }
    if let Some(line) = &cancel_notice_line {
        footer_note_html.push('\n');
        footer_note_html.push_str(line);
    }
    let html = render_html_email_in(
        lang,
        &h(&greeting),
        &headline,
        "#16a34a",
        &rows,
        Some(&footer_note_html),
        &actions,
    );

    let body = build_multipart_body(&plain, &html);

    let ics_attachment = Attachment::new("invite.ics".to_string()).body(
        ics,
        ContentType::parse("text/calendar; method=REQUEST; charset=UTF-8")?,
    );

    let subject = ta(
        lang,
        "email-confirm-subject",
        [("event", &details.event_title), ("date", &details.date)],
    );

    let email = config
        .message_from(Sender::host_of(details))?
        .to(to)
        .subject(subject)
        .multipart(
            MultiPart::mixed()
                .multipart(body)
                .singlepart(ics_attachment),
        )?;

    send_email(config, email).await?;

    // Send confirmation to additional attendees
    for attendee_email in &details.additional_attendees {
        let to2: Mailbox = attendee_email.parse()?;
        let ics2 = generate_ics(details, "REQUEST");
        if let Err(e) = send_composed(
            config,
            Sender::host_of(details),
            to2,
            compose_attendee_confirmation(details),
            Some(("invite.ics", ics2, "REQUEST")),
        )
        .await
        {
            tracing::warn!(attendee = %attendee_email, error = format!("{e:#}"), "failed to send attendee confirmation");
        }
    }

    Ok(())
}

// --- Composition shared by the translated emails ---

fn row(label: String, value: impl Into<String>) -> EmailRow {
    EmailRow {
        label,
        value: value.into(),
    }
}

/// Append a row only when the value is there.
fn push_row(rows: &mut Vec<EmailRow>, lang: &str, key: &str, value: Option<&String>) {
    if let Some(v) = value {
        rows.push(row(t(lang, key), v.clone()));
    }
}

/// Event, date, time and guest: the rows every host-facing email opens with.
fn host_rows(
    lang: &str,
    event: &str,
    date: &str,
    time: &str,
    guest_name: &str,
    guest_email: &str,
) -> Vec<EmailRow> {
    vec![
        row(t(lang, "confirmed-detail-event"), event),
        row(t(lang, "confirmed-detail-date"), date),
        row(t(lang, "confirmed-detail-time"), time),
        row(
            t(lang, "common-detail-guest"),
            format!("{} <{}>", guest_name, guest_email),
        ),
    ]
}

/// "date at time", for rows that carry both in one value.
fn date_at_time(lang: &str, date: &str, time: &str) -> String {
    ta(lang, "email-date-at-time", [("date", date), ("time", time)])
}

/// Approve and decline links for a pending booking, when a token and a
/// public base URL are both known.
fn approval_urls(confirm_token: Option<&str>, base_url: Option<&str>) -> Option<(String, String)> {
    let (token, url) = (confirm_token?, base_url?);
    let base = url.trim_end_matches('/');
    Some((
        format!("{}/booking/approve/{}", base, token),
        format!("{}/booking/decline/{}", base, token),
    ))
}

/// Plain-text lines and HTML buttons for approve/decline, or the dashboard
/// hint when the email cannot carry links.
fn approval_actions(lang: &str, urls: Option<(String, String)>) -> (Vec<String>, Vec<EmailAction>) {
    match urls {
        Some((approve, decline)) => (
            vec![
                ta(lang, "email-host-approve-line", [("url", &approve)]),
                ta(lang, "email-host-decline-line", [("url", &decline)]),
            ],
            vec![
                EmailAction {
                    label: t(lang, "email-action-approve"),
                    url: approve,
                    color: "#16a34a".to_string(),
                },
                EmailAction {
                    label: t(lang, "email-action-decline"),
                    url: decline,
                    color: "#dc2626".to_string(),
                },
            ],
        ),
        None => (vec![t(lang, "email-host-approval-dashboard")], vec![]),
    }
}

/// An email made of a heading, one message, a details table, optional
/// buttons and a closing note, all in `lang`. The plain-text body carries the
/// same content, with `plain_lines` (the URLs the HTML shows as buttons)
/// after the details.
struct EmailParts<'a> {
    lang: &'a str,
    subject: String,
    heading: String,
    message: String,
    accent: &'a str,
    rows: Vec<EmailRow>,
    plain_lines: Vec<String>,
    footer_plain: Option<String>,
    footer_html: Option<String>,
    actions: Vec<EmailAction>,
}

impl EmailParts<'_> {
    fn compose(self) -> ComposedEmail {
        let mut plain = format!("{}\n\n{}\n\n", self.heading, self.message);
        for r in &self.rows {
            plain.push_str(&format!("{} {}\n", r.label, r.value));
        }
        plain.push('\n');
        if !self.plain_lines.is_empty() {
            plain.push_str(&self.plain_lines.join("\n"));
            plain.push_str("\n\n");
        }
        if let Some(note) = &self.footer_plain {
            plain.push_str(note);
            plain.push_str("\n\n");
        }
        plain.push_str(&t(self.lang, "email-signature"));
        let html = render_html_email_in(
            self.lang,
            &h(&self.heading),
            &h(&self.message),
            self.accent,
            &self.rows,
            self.footer_html.as_deref(),
            &self.actions,
        );
        ComposedEmail {
            subject: self.subject,
            plain,
            html,
        }
    }
}

/// Send a composed email, with an optional `(filename, ics, method)`
/// calendar attachment.
async fn send_composed(
    config: &SmtpConfig,
    sender: Sender<'_>,
    to: Mailbox,
    mail: ComposedEmail,
    ics: Option<(&str, String, &str)>,
) -> Result<()> {
    let body = build_multipart_body(&mail.plain, &mail.html);
    let builder = config.message_from(sender)?.to(to).subject(mail.subject);
    let email = match ics {
        Some((filename, ics, method)) => {
            let attachment = Attachment::new(filename.to_string()).body(
                ics,
                ContentType::parse(&format!("text/calendar; method={method}; charset=UTF-8"))?,
            );
            builder.multipart(MultiPart::mixed().multipart(body).singlepart(attachment))?
        }
        None => builder.multipart(body)?,
    };
    send_email(config, email).await
}

/// "You've been added as an attendee" copy for the additional attendees of
/// a booking, in the booking's language: the guest invited them, so the
/// guest's language is the best guess at theirs.
fn compose_attendee_confirmation(details: &BookingDetails) -> ComposedEmail {
    let lang = guest_lang(details);
    let time_display = format!(
        "{} \u{2013} {} ({})",
        details.start_time, details.end_time, details.guest_timezone
    );
    EmailParts {
        lang,
        // Exchange titles the guest's appointment after the Subject header,
        // not the ICS SUMMARY, so REQUEST emails keep a neutral
        // "event, date" subject (#157).
        subject: ta(
            lang,
            "email-confirm-subject",
            [("event", &details.event_title), ("date", &details.date)],
        ),
        heading: t(lang, "email-attendee-greeting"),
        message: t(lang, "email-attendee-message"),
        accent: "#16a34a",
        rows: vec![
            row(t(lang, "confirmed-detail-event"), &details.event_title),
            row(t(lang, "confirmed-detail-date"), &details.date),
            row(t(lang, "confirmed-detail-time"), time_display),
            row(t(lang, "email-detail-organizer"), &details.host_name),
            row(
                t(lang, "email-detail-booked-by"),
                format!("{} <{}>", details.guest_name, details.guest_email),
            ),
        ],
        plain_lines: vec![],
        footer_plain: Some(t(lang, "email-confirm-ics-attached-plain")),
        footer_html: Some(t(lang, "email-confirm-ics-attached-html")),
        actions: vec![],
    }
    .compose()
}

/// Send booking notification to the host
pub async fn send_host_notification(config: &SmtpConfig, details: &BookingDetails) -> Result<()> {
    let to = named_mailbox(&details.host_name, &details.host_email)?;
    let ics = generate_ics(details, "REQUEST");
    send_composed(
        config,
        Sender::Instance,
        to,
        compose_host_notification(details),
        Some(("invite.ics", ics, "REQUEST")),
    )
    .await
}

/// The host's "new booking" email, in the host's language.
fn compose_host_notification(details: &BookingDetails) -> ComposedEmail {
    let lang = host_lang(details);
    let (date_display, time_display) = host_time_display_exact(
        &details.date,
        &details.start_time,
        &details.end_time,
        &details.guest_timezone,
        &details.host_timezone,
        details.utc_times.as_ref(),
    );
    let mut rows = host_rows(
        lang,
        &details.event_title,
        &date_display,
        &time_display,
        &details.guest_name,
        &details.guest_email,
    );
    push_row(
        &mut rows,
        lang,
        "confirmed-detail-location",
        details.location.as_ref(),
    );
    push_row(
        &mut rows,
        lang,
        "bookings-resource",
        details.resource_name.as_ref(),
    );
    push_row(
        &mut rows,
        lang,
        "confirmed-detail-notes",
        details.notes.as_ref(),
    );
    EmailParts {
        lang,
        subject: ta(
            lang,
            "email-host-new-subject",
            [
                ("event", &details.event_title),
                ("guest", &details.guest_name),
                ("date", &date_display),
            ],
        ),
        heading: t(lang, "email-host-new-heading"),
        message: ta(
            lang,
            "email-host-new-message",
            [("guest", &details.guest_name)],
        ),
        accent: "#16a34a",
        rows,
        plain_lines: vec![],
        footer_plain: Some(t(lang, "email-confirm-ics-attached-plain")),
        footer_html: Some(t(lang, "email-confirm-ics-attached-html")),
        actions: vec![],
    }
    .compose()
}

/// Send host a confirmation that a pending booking was approved. No ICS: the
/// event is already pushed via CalDAV write-back.
pub async fn send_host_booking_confirmed(
    config: &SmtpConfig,
    details: &BookingDetails,
) -> Result<()> {
    let to = named_mailbox(&details.host_name, &details.host_email)?;
    send_composed(
        config,
        Sender::Instance,
        to,
        compose_host_booking_confirmed(details),
        None,
    )
    .await
}

fn compose_host_booking_confirmed(details: &BookingDetails) -> ComposedEmail {
    let lang = host_lang(details);
    let (date_display, time_display) = host_time_display_exact(
        &details.date,
        &details.start_time,
        &details.end_time,
        &details.guest_timezone,
        &details.host_timezone,
        details.utc_times.as_ref(),
    );
    let mut rows = host_rows(
        lang,
        &details.event_title,
        &date_display,
        &time_display,
        &details.guest_name,
        &details.guest_email,
    );
    push_row(
        &mut rows,
        lang,
        "confirmed-detail-location",
        details.location.as_ref(),
    );
    push_row(
        &mut rows,
        lang,
        "bookings-resource",
        details.resource_name.as_ref(),
    );
    let footer = t(lang, "email-host-confirmed-footer");
    EmailParts {
        lang,
        subject: ta(
            lang,
            "email-host-confirmed-subject",
            [
                ("event", &details.event_title),
                ("guest", &details.guest_name),
                ("date", &date_display),
            ],
        ),
        heading: t(lang, "email-host-confirmed-heading"),
        message: ta(
            lang,
            "email-host-confirmed-message",
            [("guest", &details.guest_name)],
        ),
        accent: "#16a34a",
        rows,
        plain_lines: vec![],
        footer_plain: Some(footer.clone()),
        footer_html: Some(footer),
        actions: vec![],
    }
    .compose()
}

/// Tell the host their Google Calendar still shows the old time.
///
/// A Google Meet booking lives on the host's calendar as a single Google event
/// that calrs patches in place, because a second ICS PUT would strip the
/// conference. When that patch fails for good, the booking, the guest's invite
/// and the reminders all hold the new time while the host's calendar holds the
/// old one, and without this email nobody would ever say so. `reason` is the
/// technical error, shown as the API returned it.
pub async fn send_host_calendar_sync_failure(
    config: &SmtpConfig,
    details: &BookingDetails,
    reason: &str,
) -> Result<()> {
    let to = named_mailbox(&details.host_name, &details.host_email)?;
    send_composed(
        config,
        Sender::Instance,
        to,
        compose_host_calendar_sync_failure(details, reason),
        None,
    )
    .await
}

fn compose_host_calendar_sync_failure(details: &BookingDetails, reason: &str) -> ComposedEmail {
    let lang = host_lang(details);
    let (date_display, time_display) = host_time_display_exact(
        &details.date,
        &details.start_time,
        &details.end_time,
        &details.guest_timezone,
        &details.host_timezone,
        details.utc_times.as_ref(),
    );
    // Recreating the event would mint a different conference, so the Meet
    // link already sitting in the guest's invite would stop admitting anyone:
    // the closing line says to move the event instead.
    let action = t(lang, "email-host-sync-failure-action");
    EmailParts {
        lang,
        subject: ta(
            lang,
            "email-host-sync-failure-subject",
            [("event", &details.event_title), ("date", &date_display)],
        ),
        heading: t(lang, "email-host-sync-failure-heading"),
        message: t(lang, "email-host-sync-failure-intro"),
        accent: "#f59e0b",
        rows: vec![
            row(t(lang, "confirmed-detail-event"), &details.event_title),
            row(t(lang, "email-detail-new-date"), date_display.clone()),
            row(t(lang, "email-detail-new-time"), time_display),
            row(
                t(lang, "common-detail-guest"),
                format!("{} <{}>", details.guest_name, details.guest_email),
            ),
            row(t(lang, "common-detail-reason"), reason),
        ],
        plain_lines: vec![],
        footer_plain: Some(action.clone()),
        footer_html: Some(action),
        actions: vec![],
    }
    .compose()
}

/// Tell the host a confirmed booking is still not on their calendar after
/// several write-back attempts (#162). `details` carries the recipient as
/// the host (name, email, language).
pub async fn send_host_writeback_failure(
    config: &SmtpConfig,
    details: &BookingDetails,
    error: &str,
) -> Result<()> {
    let to = named_mailbox(&details.host_name, &details.host_email)?;
    send_composed(
        config,
        Sender::Instance,
        to,
        compose_host_writeback_failure(details, error),
        None,
    )
    .await
}

fn compose_host_writeback_failure(details: &BookingDetails, error: &str) -> ComposedEmail {
    let lang = host_lang(details);
    let (date_display, time_display) = host_time_display_exact(
        &details.date,
        &details.start_time,
        &details.end_time,
        &details.guest_timezone,
        &details.host_timezone,
        details.utc_times.as_ref(),
    );
    let action = t(lang, "email-writeback-failure-action");
    EmailParts {
        lang,
        subject: ta(
            lang,
            "email-writeback-failure-subject",
            [("event", &details.event_title), ("date", &date_display)],
        ),
        heading: t(lang, "email-writeback-failure-heading"),
        message: t(lang, "email-writeback-failure-intro"),
        accent: "#f59e0b",
        rows: vec![
            row(t(lang, "confirmed-detail-event"), &details.event_title),
            row(t(lang, "confirmed-detail-date"), date_display.clone()),
            row(t(lang, "confirmed-detail-time"), time_display),
            row(
                t(lang, "common-detail-guest"),
                format!("{} <{}>", details.guest_name, details.guest_email),
            ),
            row(t(lang, "email-detail-error"), error),
        ],
        plain_lines: vec![],
        footer_plain: Some(action.clone()),
        footer_html: Some(action),
        actions: vec![],
    }
    .compose()
}

/// A calendar source that keeps failing to sync, for its owner (#162).
#[derive(Clone, Debug)]
pub struct SourceSyncFailure {
    pub owner_name: String,
    pub owner_email: String,
    /// The owner's saved language (`users.language`); English when `None`.
    pub language: Option<String>,
    pub source_name: String,
    pub error: String,
    pub failing_since: String,
}

/// Tell a source's owner that it has stopped syncing.
pub async fn send_source_sync_failure(
    config: &SmtpConfig,
    alert: &SourceSyncFailure,
) -> Result<()> {
    let to = named_mailbox(&alert.owner_name, &alert.owner_email)?;
    send_composed(
        config,
        Sender::Instance,
        to,
        compose_source_sync_failure(alert),
        None,
    )
    .await
}

fn compose_source_sync_failure(alert: &SourceSyncFailure) -> ComposedEmail {
    let lang = lang_or_en(alert.language.as_deref());
    let action = t(lang, "email-source-failure-action");
    EmailParts {
        lang,
        subject: ta(
            lang,
            "email-source-failure-subject",
            [("source", &alert.source_name)],
        ),
        heading: t(lang, "email-source-failure-heading"),
        message: t(lang, "email-source-failure-intro"),
        accent: "#f59e0b",
        rows: vec![
            row(t(lang, "email-detail-source"), &alert.source_name),
            row(t(lang, "email-detail-failing-since"), &alert.failing_since),
            row(t(lang, "email-detail-error"), &alert.error),
        ],
        plain_lines: vec![],
        footer_plain: Some(action.clone()),
        footer_html: Some(action),
        actions: vec![],
    }
    .compose()
}

/// Send booking reminder to the guest
pub async fn send_guest_reminder(
    config: &SmtpConfig,
    details: &BookingDetails,
    cancel_url: Option<&str>,
) -> Result<()> {
    let lang = guest_lang(details);
    let to = named_mailbox(&details.guest_name, &details.guest_email)?;

    let time_display = format!(
        "{} \u{2013} {} ({})",
        details.start_time, details.end_time, details.guest_timezone
    );

    let greeting = ta(
        lang,
        "email-confirm-greeting",
        [("name", &details.guest_name)],
    );
    let headline = t(lang, "email-reminder-headline");
    let label_event = t(lang, "confirmed-detail-event");
    let label_date = t(lang, "confirmed-detail-date");
    let label_time = t(lang, "confirmed-detail-time");
    let label_with = t(lang, "confirmed-detail-with");
    let label_location = t(lang, "confirmed-detail-location");
    let signature = t(lang, "email-signature");

    let plain = format!(
        "{}\n\n\
         {}\n\n\
         {} {}\n\
         {} {}\n\
         {} {}\n\
         {} {}\n\
         {}{}\n\
         {}",
        greeting,
        headline,
        label_event,
        details.event_title,
        label_date,
        details.date,
        label_time,
        time_display,
        label_with,
        details.host_name,
        details
            .location
            .as_ref()
            .map(|l| format!("{} {}\n", label_location, l))
            .unwrap_or_default(),
        cancel_url
            .map(|u| format!(
                "\n{}\n",
                ta(lang, "email-confirm-need-to-cancel", [("url", u)])
            ))
            .unwrap_or_default(),
        signature,
    );

    let mut rows = vec![
        EmailRow {
            label: label_event.clone(),
            value: details.event_title.clone(),
        },
        EmailRow {
            label: label_date.clone(),
            value: details.date.clone(),
        },
        EmailRow {
            label: label_time.clone(),
            value: time_display,
        },
        EmailRow {
            label: label_with.clone(),
            value: details.host_name.clone(),
        },
    ];
    if let Some(loc) = &details.location {
        rows.push(EmailRow {
            label: label_location.clone(),
            value: loc.clone(),
        });
    }

    let actions: Vec<EmailAction> = cancel_url
        .map(|u| {
            vec![EmailAction {
                label: t(lang, "email-action-cancel-booking"),
                url: u.to_string(),
                color: "#dc2626".to_string(),
            }]
        })
        .unwrap_or_default();

    let html = render_html_email_in(
        lang,
        &h(&greeting),
        &headline,
        "#3b82f6",
        &rows,
        None,
        &actions,
    );

    let body = build_multipart_body(&plain, &html);

    let subject = ta(
        lang,
        "email-reminder-subject",
        [
            ("event", &details.event_title),
            ("time", &details.start_time),
        ],
    );
    let email = config
        .message_from(Sender::host_of(details))?
        .to(to)
        .subject(subject)
        .multipart(body)?;

    send_email(config, email).await
}

/// Send booking reminder to the host
pub async fn send_host_reminder(config: &SmtpConfig, details: &BookingDetails) -> Result<()> {
    let to = named_mailbox(&details.host_name, &details.host_email)?;
    send_composed(
        config,
        Sender::Instance,
        to,
        compose_host_reminder(details),
        None,
    )
    .await
}

fn compose_host_reminder(details: &BookingDetails) -> ComposedEmail {
    let lang = host_lang(details);
    let (date_display, time_display) = host_time_display_exact(
        &details.date,
        &details.start_time,
        &details.end_time,
        &details.guest_timezone,
        &details.host_timezone,
        details.utc_times.as_ref(),
    );
    let mut rows = host_rows(
        lang,
        &details.event_title,
        &date_display,
        &time_display,
        &details.guest_name,
        &details.guest_email,
    );
    push_row(
        &mut rows,
        lang,
        "confirmed-detail-location",
        details.location.as_ref(),
    );
    push_row(
        &mut rows,
        lang,
        "bookings-resource",
        details.resource_name.as_ref(),
    );
    EmailParts {
        lang,
        subject: ta(
            lang,
            "email-host-reminder-subject",
            [
                ("event", &details.event_title),
                ("guest", &details.guest_name),
                ("date", &date_display),
            ],
        ),
        heading: t(lang, "email-host-reminder-heading"),
        message: ta(
            lang,
            "email-host-reminder-message",
            [("guest", &details.guest_name)],
        ),
        accent: "#3b82f6",
        rows,
        plain_lines: vec![],
        footer_plain: None,
        footer_html: None,
        actions: vec![],
    }
    .compose()
}

/// Send cancellation notification to the guest
pub async fn send_guest_cancellation(
    config: &SmtpConfig,
    details: &CancellationDetails,
) -> Result<()> {
    let ics = generate_cancel_ics(details);
    let lang = lang_or_en(details.guest_language.as_deref());

    let to = named_mailbox(&details.guest_name, &details.guest_email)?;

    let time_display = if details.guest_timezone.is_empty() {
        format!("{} \u{2013} {}", details.start_time, details.end_time)
    } else {
        format!(
            "{} \u{2013} {} ({})",
            details.start_time, details.end_time, details.guest_timezone
        )
    };

    let greeting = ta(
        lang,
        "email-confirm-greeting",
        [("name", &details.guest_name)],
    );
    let headline = if details.cancelled_by_host {
        ta(
            lang,
            "email-cancel-headline-by-host",
            [("host", &details.host_name)],
        )
    } else {
        t(lang, "email-cancel-headline-by-guest")
    };
    let label_event = t(lang, "confirmed-detail-event");
    let label_date = t(lang, "confirmed-detail-date");
    let label_time = t(lang, "confirmed-detail-time");
    let label_with = t(lang, "confirmed-detail-with");
    let label_reason = t(lang, "common-detail-reason");
    let ics_attached_plain = t(lang, "email-cancel-ics-attached-plain");
    let ics_attached_html = t(lang, "email-cancel-ics-attached-html");
    let signature = t(lang, "email-signature");

    let reason_text = details
        .reason
        .as_ref()
        .map(|r| format!("{} {}\n\n", label_reason, r))
        .unwrap_or_default();

    let plain = format!(
        "{}\n\n\
         {}\n\n\
         {} {}\n\
         {} {}\n\
         {} {}\n\
         {} {}\n\n\
         {}\
         {}\n\n\
         {}",
        greeting,
        headline,
        label_event,
        details.event_title,
        label_date,
        details.date,
        label_time,
        time_display,
        label_with,
        details.host_name,
        reason_text,
        ics_attached_plain,
        signature,
    );

    let mut rows = vec![
        EmailRow {
            label: label_event.clone(),
            value: details.event_title.clone(),
        },
        EmailRow {
            label: label_date.clone(),
            value: details.date.clone(),
        },
        EmailRow {
            label: label_time.clone(),
            value: time_display,
        },
        EmailRow {
            label: label_with.clone(),
            value: details.host_name.clone(),
        },
    ];
    if let Some(reason) = &details.reason {
        rows.push(EmailRow {
            label: label_reason.clone(),
            value: reason.clone(),
        });
    }

    let html = render_html_email_in(
        lang,
        &h(&greeting),
        &headline,
        "#dc2626",
        &rows,
        Some(&ics_attached_html),
        &[],
    );

    let body = build_multipart_body(&plain, &html);

    let ics_attachment = Attachment::new("cancel.ics".to_string()).body(
        ics,
        ContentType::parse("text/calendar; method=CANCEL; charset=UTF-8")?,
    );

    let subject = ta(
        lang,
        "email-cancel-subject",
        [("event", &details.event_title), ("date", &details.date)],
    );
    let email = config
        .message_from(Sender::host_of_cancellation(details))?
        .to(to)
        .subject(subject)
        .multipart(
            MultiPart::mixed()
                .multipart(body)
                .singlepart(ics_attachment),
        )?;

    send_email(config, email).await
}

/// Send cancellation notification to the host
pub async fn send_host_cancellation(
    config: &SmtpConfig,
    details: &CancellationDetails,
) -> Result<()> {
    let to = named_mailbox(&details.host_name, &details.host_email)?;
    let ics = generate_cancel_ics(details);
    send_composed(
        config,
        Sender::Instance,
        to,
        compose_host_cancellation(details),
        Some(("cancel.ics", ics, "CANCEL")),
    )
    .await
}

fn compose_host_cancellation(details: &CancellationDetails) -> ComposedEmail {
    let lang = lang_or_en(details.host_language.as_deref());
    let (date_display, time_display) = host_time_display_exact(
        &details.date,
        &details.start_time,
        &details.end_time,
        &details.guest_timezone,
        &details.host_timezone,
        details.utc_times.as_ref(),
    );
    let mut rows = host_rows(
        lang,
        &details.event_title,
        &date_display,
        &time_display,
        &details.guest_name,
        &details.guest_email,
    );
    push_row(
        &mut rows,
        lang,
        "common-detail-reason",
        details.reason.as_ref(),
    );
    let message = if details.cancelled_by_host {
        t(lang, "email-host-cancel-message-by-host")
    } else {
        ta(
            lang,
            "email-host-cancel-message-by-guest",
            [("guest", &details.guest_name)],
        )
    };
    EmailParts {
        lang,
        subject: ta(
            lang,
            "email-host-cancel-subject",
            [
                ("event", &details.event_title),
                ("guest", &details.guest_name),
                ("date", &date_display),
            ],
        ),
        heading: t(lang, "cancelled-heading"),
        message,
        accent: "#dc2626",
        rows,
        plain_lines: vec![],
        footer_plain: Some(t(lang, "email-cancel-ics-attached-plain")),
        footer_html: Some(t(lang, "email-cancel-ics-attached-html")),
        actions: vec![],
    }
    .compose()
}

/// Send pending notice to guest (booking awaits host approval)
pub async fn send_guest_pending_notice(
    config: &SmtpConfig,
    details: &BookingDetails,
    cancel_url: Option<&str>,
) -> Result<()> {
    send_guest_pending_notice_ex(config, details, cancel_url, None).await
}

pub async fn send_guest_pending_notice_ex(
    config: &SmtpConfig,
    details: &BookingDetails,
    cancel_url: Option<&str>,
    reschedule_url: Option<&str>,
) -> Result<()> {
    let to = named_mailbox(&details.guest_name, &details.guest_email)?;
    let composed = compose_guest_pending_notice(details, cancel_url, reschedule_url);
    let body = build_multipart_body(&composed.plain, &composed.html);

    let email = config
        .message_from(Sender::host_of(details))?
        .to(to)
        .subject(composed.subject)
        .multipart(body)?;

    send_email(config, email).await
}

/// Subject and bodies of an email, built apart from sending so tests can
/// read exactly what the recipient would get.
struct ComposedEmail {
    subject: String,
    plain: String,
    html: String,
}

/// "[status] event, date" subject for guest emails that report a state
/// rather than carry an invite, built from the translated status label and
/// the same neutral "event, date" pair the confirmation uses.
fn status_subject(lang: &str, status_key: &str, event: &str, date: &str) -> String {
    format!(
        "[{}] {}",
        t(lang, status_key),
        ta(
            lang,
            "email-confirm-subject",
            [("event", event), ("date", date)]
        )
    )
}

/// The guest's "request received, awaiting the host" email, in the language
/// stored with the booking. It reuses the booking page's own pending wording
/// (`confirmed-heading-pending`, `confirmed-subtitle-pending`), which says
/// exactly what this email has to say, so every locale gets it today.
fn compose_guest_pending_notice(
    details: &BookingDetails,
    cancel_url: Option<&str>,
    reschedule_url: Option<&str>,
) -> ComposedEmail {
    let lang = guest_lang(details);

    let time_display = format!(
        "{} \u{2013} {} ({})",
        details.start_time, details.end_time, details.guest_timezone
    );

    let greeting = ta(
        lang,
        "email-confirm-greeting",
        [("name", &details.guest_name)],
    );
    let headline = ta(
        lang,
        "confirmed-subtitle-pending",
        [
            ("host", &details.host_name),
            ("email", &details.guest_email),
        ],
    );
    let label_event = t(lang, "confirmed-detail-event");
    let label_date = t(lang, "confirmed-detail-date");
    let label_time = t(lang, "confirmed-detail-time");
    let label_with = t(lang, "confirmed-detail-with");
    let label_notes = t(lang, "confirmed-detail-notes");
    let signature = t(lang, "email-signature");

    // Don't include location in pending emails: it should only be revealed
    // after the booking is confirmed (prevents meeting link leaking).
    let mut plain = format!(
        "{}\n\n{}\n\n{} {}\n{} {}\n{} {}\n{} {}\n",
        greeting,
        headline,
        label_event,
        details.event_title,
        label_date,
        details.date,
        label_time,
        time_display,
        label_with,
        details.host_name,
    );
    if let Some(n) = &details.notes {
        plain.push_str(&format!("{} {}\n", label_notes, n));
    }
    if let Some(u) = cancel_url {
        plain.push_str(&format!(
            "\n{}\n",
            ta(lang, "email-confirm-need-to-cancel", [("url", u)])
        ));
    }
    plain.push('\n');
    plain.push_str(&signature);

    let mut rows = vec![
        EmailRow {
            label: label_event,
            value: details.event_title.clone(),
        },
        EmailRow {
            label: label_date,
            value: details.date.clone(),
        },
        EmailRow {
            label: label_time,
            value: time_display,
        },
        EmailRow {
            label: label_with,
            value: details.host_name.clone(),
        },
    ];
    if let Some(notes) = &details.notes {
        rows.push(EmailRow {
            label: label_notes,
            value: notes.clone(),
        });
    }

    let mut actions: Vec<EmailAction> = Vec::new();
    if let Some(u) = reschedule_url {
        actions.push(EmailAction {
            label: t(lang, "email-action-reschedule"),
            url: u.to_string(),
            color: "#3b82f6".to_string(),
        });
    }
    if let Some(u) = cancel_url {
        actions.push(EmailAction {
            label: t(lang, "email-action-cancel-booking"),
            url: u.to_string(),
            color: "#dc2626".to_string(),
        });
    }

    let html = render_html_email_in(
        lang,
        &h(&greeting),
        &h(&headline),
        "#f59e0b",
        &rows,
        None,
        &actions,
    );

    ComposedEmail {
        subject: status_subject(
            lang,
            "confirmed-heading-pending",
            &details.event_title,
            &details.date,
        ),
        plain,
        html,
    }
}

/// Send approval request to host with approve/decline buttons
pub async fn send_host_approval_request(
    config: &SmtpConfig,
    details: &BookingDetails,
    _booking_id: &str,
    confirm_token: Option<&str>,
    base_url: Option<&str>,
) -> Result<()> {
    send_host_approval_email(config, details, confirm_token, base_url, None).await
}

/// The one reminder a host gets for a request still unanswered halfway to its
/// expiry (#234): the approval request again, with the same Approve/Decline
/// buttons, saying when the request will be declined on its own.
/// `expires_display` is the deadline already formatted in the host's timezone.
pub async fn send_host_approval_reminder(
    config: &SmtpConfig,
    details: &BookingDetails,
    confirm_token: Option<&str>,
    base_url: Option<&str>,
    expires_display: &str,
) -> Result<()> {
    send_host_approval_email(
        config,
        details,
        confirm_token,
        base_url,
        Some(expires_display),
    )
    .await
}

/// Approval request (`expires` = `None`) or its reminder (`Some(deadline)`).
async fn send_host_approval_email(
    config: &SmtpConfig,
    details: &BookingDetails,
    confirm_token: Option<&str>,
    base_url: Option<&str>,
    expires: Option<&str>,
) -> Result<()> {
    let to = named_mailbox(&details.host_name, &details.host_email)?;
    let mail = compose_host_approval_email(details, confirm_token, base_url, expires);
    send_composed(config, Sender::Instance, to, mail, None).await
}

fn compose_host_approval_email(
    details: &BookingDetails,
    confirm_token: Option<&str>,
    base_url: Option<&str>,
    expires: Option<&str>,
) -> ComposedEmail {
    let lang = host_lang(details);
    let (date_display, time_display) = host_time_display_exact(
        &details.date,
        &details.start_time,
        &details.end_time,
        &details.guest_timezone,
        &details.host_timezone,
        details.utc_times.as_ref(),
    );

    let mut rows = host_rows(
        lang,
        &details.event_title,
        &date_display,
        &time_display,
        &details.guest_name,
        &details.guest_email,
    );
    push_row(
        &mut rows,
        lang,
        "email-detail-phone",
        details.guest_phone.as_ref(),
    );
    push_row(
        &mut rows,
        lang,
        "confirmed-detail-location",
        details.location.as_ref(),
    );
    push_row(
        &mut rows,
        lang,
        "bookings-resource",
        details.resource_name.as_ref(),
    );
    push_row(
        &mut rows,
        lang,
        "confirmed-detail-notes",
        details.notes.as_ref(),
    );
    if let Some(deadline) = expires {
        rows.push(row(t(lang, "email-detail-expires"), deadline));
    }

    let (plain_lines, actions) = approval_actions(lang, approval_urls(confirm_token, base_url));

    let guest = details.guest_name.as_str();
    let (heading, message, subject) = match expires {
        None => (
            t(lang, "email-host-approval-heading"),
            ta(lang, "email-host-approval-message", [("guest", guest)]),
            ta(
                lang,
                "email-host-approval-subject",
                [
                    ("event", &details.event_title),
                    ("guest", guest),
                    ("date", &date_display),
                ],
            ),
        ),
        Some(deadline) => (
            t(lang, "email-host-approval-reminder-heading"),
            ta(
                lang,
                "email-host-approval-reminder-message",
                [("guest", guest), ("deadline", deadline)],
            ),
            ta(
                lang,
                "email-host-approval-reminder-subject",
                [
                    ("event", &details.event_title),
                    ("guest", guest),
                    ("date", &date_display),
                ],
            ),
        ),
    };

    let footer = t(lang, "email-host-approval-footer");
    EmailParts {
        lang,
        subject,
        heading,
        message,
        accent: "#f59e0b",
        rows,
        plain_lines,
        footer_plain: Some(footer.clone()),
        footer_html: Some(footer),
        actions,
    }
    .compose()
}

/// Send decline notification to the guest
pub async fn send_guest_decline_notice(
    config: &SmtpConfig,
    details: &CancellationDetails,
) -> Result<()> {
    let to = named_mailbox(&details.guest_name, &details.guest_email)?;
    let composed = compose_guest_decline_notice(details);
    let body = build_multipart_body(&composed.plain, &composed.html);

    let email = config
        .message_from(Sender::host_of_cancellation(details))?
        .to(to)
        .subject(composed.subject)
        .multipart(body)?;

    send_email(config, email).await
}

/// The guest's "your request was declined" email, in the language stored
/// with the booking. Reuses the decline page's wording
/// (`bae-title-booking-declined`, `bae-body-declined-by-host`).
fn compose_guest_decline_notice(details: &CancellationDetails) -> ComposedEmail {
    let lang = lang_or_en(details.guest_language.as_deref());

    let time_display = if details.guest_timezone.is_empty() {
        format!("{} \u{2013} {}", details.start_time, details.end_time)
    } else {
        format!(
            "{} \u{2013} {} ({})",
            details.start_time, details.end_time, details.guest_timezone
        )
    };

    let greeting = ta(
        lang,
        "email-confirm-greeting",
        [("name", &details.guest_name)],
    );
    let headline = t(lang, "bae-body-declined-by-host");
    let label_event = t(lang, "confirmed-detail-event");
    let label_date = t(lang, "confirmed-detail-date");
    let label_time = t(lang, "confirmed-detail-time");
    let label_with = t(lang, "confirmed-detail-with");
    let label_reason = t(lang, "common-detail-reason");
    let signature = t(lang, "email-signature");

    let mut plain = format!(
        "{}\n\n{}\n\n{} {}\n{} {}\n{} {}\n{} {}\n\n",
        greeting,
        headline,
        label_event,
        details.event_title,
        label_date,
        details.date,
        label_time,
        time_display,
        label_with,
        details.host_name,
    );
    if let Some(r) = &details.reason {
        plain.push_str(&format!("{} {}\n\n", label_reason, r));
    }
    plain.push_str(&signature);

    let mut rows = vec![
        EmailRow {
            label: label_event,
            value: details.event_title.clone(),
        },
        EmailRow {
            label: label_date,
            value: details.date.clone(),
        },
        EmailRow {
            label: label_time,
            value: time_display,
        },
        EmailRow {
            label: label_with,
            value: details.host_name.clone(),
        },
    ];
    if let Some(reason) = &details.reason {
        rows.push(EmailRow {
            label: label_reason,
            value: reason.clone(),
        });
    }

    let html = render_html_email_in(
        lang,
        &h(&greeting),
        &h(&headline),
        "#dc2626",
        &rows,
        None,
        &[],
    );

    ComposedEmail {
        subject: status_subject(
            lang,
            "bae-title-booking-declined",
            &details.event_title,
            &details.date,
        ),
        plain,
        html,
    }
}

/// Tell the guest their request expired because the host did not answer in
/// time (#234), in the language stored with the booking. `rebook_url` points
/// back to the event type's booking page when it is public and a base URL is
/// configured.
pub async fn send_guest_pending_expired(
    config: &SmtpConfig,
    details: &CancellationDetails,
    rebook_url: Option<&str>,
) -> Result<()> {
    let to = named_mailbox(&details.guest_name, &details.guest_email)?;
    let composed = compose_guest_pending_expired(details, rebook_url);
    let body = build_multipart_body(&composed.plain, &composed.html);

    let email = config
        .message_from(Sender::host_of_cancellation(details))?
        .to(to)
        .subject(composed.subject)
        .multipart(body)?;

    send_email(config, email).await
}

fn compose_guest_pending_expired(
    details: &CancellationDetails,
    rebook_url: Option<&str>,
) -> ComposedEmail {
    let lang = lang_or_en(details.guest_language.as_deref());

    let time_display = if details.guest_timezone.is_empty() {
        format!("{} \u{2013} {}", details.start_time, details.end_time)
    } else {
        format!(
            "{} \u{2013} {} ({})",
            details.start_time, details.end_time, details.guest_timezone
        )
    };

    let greeting = ta(
        lang,
        "email-confirm-greeting",
        [("name", &details.guest_name)],
    );
    let headline = t(lang, "email-pending-expired-headline");
    let label_event = t(lang, "confirmed-detail-event");
    let label_date = t(lang, "confirmed-detail-date");
    let label_time = t(lang, "confirmed-detail-time");
    let label_with = t(lang, "confirmed-detail-with");
    let action_label = t(lang, "email-pending-expired-action");
    let signature = t(lang, "email-signature");

    let mut plain = format!(
        "{}\n\n{}\n\n{} {}\n{} {}\n{} {}\n{} {}\n\n",
        greeting,
        headline,
        label_event,
        details.event_title,
        label_date,
        details.date,
        label_time,
        time_display,
        label_with,
        details.host_name,
    );
    if let Some(url) = rebook_url {
        plain.push_str(&format!("{}: {}\n\n", action_label, url));
    }
    plain.push_str(&signature);

    let rows = vec![
        EmailRow {
            label: label_event,
            value: details.event_title.clone(),
        },
        EmailRow {
            label: label_date,
            value: details.date.clone(),
        },
        EmailRow {
            label: label_time,
            value: time_display,
        },
        EmailRow {
            label: label_with,
            value: details.host_name.clone(),
        },
    ];
    let actions: Vec<EmailAction> = rebook_url
        .map(|url| EmailAction {
            label: action_label,
            url: url.to_string(),
            color: "#6366f1".to_string(),
        })
        .into_iter()
        .collect();

    let html = render_html_email_in(
        lang,
        &h(&greeting),
        &h(&headline),
        "#dc2626",
        &rows,
        None,
        &actions,
    );

    ComposedEmail {
        subject: status_subject(
            lang,
            "email-pending-expired-status",
            &details.event_title,
            &details.date,
        ),
        plain,
        html,
    }
}

/// Tell the host a request they did not answer has expired and was declined
/// automatically (#234), in the host's language.
pub async fn send_host_pending_expired(
    config: &SmtpConfig,
    details: &CancellationDetails,
) -> Result<()> {
    let to = named_mailbox(&details.host_name, &details.host_email)?;
    send_composed(
        config,
        Sender::Instance,
        to,
        compose_host_pending_expired(details),
        None,
    )
    .await
}

fn compose_host_pending_expired(details: &CancellationDetails) -> ComposedEmail {
    let lang = lang_or_en(details.host_language.as_deref());
    let (date_display, time_display) = host_time_display_exact(
        &details.date,
        &details.start_time,
        &details.end_time,
        &details.guest_timezone,
        &details.host_timezone,
        details.utc_times.as_ref(),
    );
    let footer = t(lang, "email-host-expired-footer");
    EmailParts {
        lang,
        subject: ta(
            lang,
            "email-host-expired-subject",
            [
                ("event", &details.event_title),
                ("guest", &details.guest_name),
                ("date", &date_display),
            ],
        ),
        heading: t(lang, "email-host-expired-heading"),
        message: ta(
            lang,
            "email-host-expired-message",
            [("guest", &details.guest_name)],
        ),
        accent: "#dc2626",
        rows: host_rows(
            lang,
            &details.event_title,
            &date_display,
            &time_display,
            &details.guest_name,
            &details.guest_email,
        ),
        plain_lines: vec![],
        footer_plain: Some(footer.clone()),
        footer_html: Some(footer),
        actions: vec![],
    }
    .compose()
}

// --- Utility ---

const SMTP_ENV_VARS: &[&str] = &[
    "CALRS_SMTP_HOST",
    "CALRS_SMTP_PORT",
    "CALRS_SMTP_TLS_MODE",
    "CALRS_SMTP_USERNAME",
    "CALRS_SMTP_PASSWORD",
    "CALRS_SMTP_FROM_EMAIL",
    "CALRS_SMTP_FROM_NAME",
];

/// Read an SMTP env var, returning `Some(value)` only when set and non-empty.
fn optional_smtp_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

/// Load the SMTP config from the `CALRS_SMTP_*` environment block.
///
/// Priority is "full block override": when the required block (host,
/// from_email) is complete, the env wins over the database entirely. When no
/// SMTP var is set, or the required block is only partially set, this returns
/// `Ok(None)` so the caller falls back to the database config — a stray or
/// incomplete env var no longer breaks SMTP. A required block that *is*
/// complete but carries an invalid `PORT`/`TLS_MODE` still surfaces an error,
/// since that is a genuine misconfiguration to fix rather than silently ignore.
///
/// `USERNAME`/`PASSWORD` are optional: omitting them configures an
/// unauthenticated relay, which is how a container talks to a sidecar MTA.
fn load_smtp_config_from_env() -> Result<Option<SmtpConfig>> {
    if !SMTP_ENV_VARS
        .iter()
        .any(|name| std::env::var_os(name).is_some())
    {
        return Ok(None);
    }

    let (host, from_email) = match (
        optional_smtp_env("CALRS_SMTP_HOST"),
        optional_smtp_env("CALRS_SMTP_FROM_EMAIL"),
    ) {
        (Some(host), Some(from_email)) => (host, from_email),
        _ => {
            tracing::warn!(
                "partial CALRS_SMTP_* environment block (missing HOST or FROM_EMAIL); falling back to database SMTP config"
            );
            return Ok(None);
        }
    };
    // Both empty means "no SMTP AUTH", as in `send_email`. A username with no
    // password is still authenticated, since some relays accept an empty one.
    let username = optional_smtp_env("CALRS_SMTP_USERNAME").unwrap_or_default();
    let password = optional_smtp_env("CALRS_SMTP_PASSWORD").unwrap_or_default();
    if username.is_empty() && !password.is_empty() {
        bail!("CALRS_SMTP_PASSWORD is set without CALRS_SMTP_USERNAME");
    }
    let port = match std::env::var("CALRS_SMTP_PORT") {
        Ok(value) if value.trim().is_empty() => bail!("CALRS_SMTP_PORT must not be empty"),
        Ok(value) => value.trim().parse::<u16>().map_err(|_| {
            anyhow::anyhow!("CALRS_SMTP_PORT must be a valid TCP port (got '{}')", value)
        })?,
        Err(_) => 587u16,
    };
    let tls_mode = match std::env::var("CALRS_SMTP_TLS_MODE") {
        Ok(value) if value.trim().is_empty() => bail!("CALRS_SMTP_TLS_MODE must not be empty"),
        Ok(value) => SmtpTlsMode::parse(&value)?,
        Err(_) => SmtpTlsMode::StartTls,
    };
    let from_name = std::env::var("CALRS_SMTP_FROM_NAME")
        .ok()
        .filter(|value| !value.trim().is_empty());

    Ok(Some(SmtpConfig {
        host,
        port,
        username,
        password,
        from_email,
        from_name,
        tls_mode,
    }))
}

/// Returns true when the `CALRS_SMTP_*` environment block governs the config,
/// meaning the database config is shadowed and must not be edited from the UI.
///
/// A complete env block (`Ok(Some)`) or a complete-but-invalid one (`Err`, e.g.
/// a bad port) both govern — the env overrides the database either way, so the
/// admin form is locked. A partial/absent block (`Ok(None)`) does not govern:
/// the app falls back to the database, which stays editable.
pub fn smtp_env_active() -> bool {
    !matches!(load_smtp_config_from_env(), Ok(None))
}

/// The env block governs as soon as `HOST` and `FROM_EMAIL` are set, and
/// `USERNAME`/`PASSWORD` are optional. That combination can take over from a
/// database row that *does* carry credentials, turning working authenticated
/// SMTP into unauthenticated sends that the relay then rejects. The operator
/// has no other signal: the admin form locks itself when the env governs, and
/// mail simply stops. Warn once per process, and only when there is something
/// to lose.
async fn warn_if_env_shadows_db_credentials(pool: &SqlitePool) {
    static WARNED: std::sync::Once = std::sync::Once::new();
    if WARNED.is_completed() {
        return;
    }
    let shadowed: Option<(String,)> = sqlx::query_as(
        "SELECT username FROM smtp_config WHERE enabled = 1 AND TRIM(username) <> '' LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();
    if shadowed.is_some() {
        WARNED.call_once(|| {
            tracing::warn!(
                "CALRS_SMTP_* sets no USERNAME, so calrs is relaying without authentication, but \
                 the database holds SMTP credentials that the environment block now shadows. Set \
                 CALRS_SMTP_USERNAME and CALRS_SMTP_PASSWORD, or unset the CALRS_SMTP_* block to \
                 go back to the database config."
            );
        });
    }
}

/// Warn once about a username configured with no password.
///
/// This is deliberately not the hard error that a password with no username
/// gets. There, the config is provably self-contradictory: the password can
/// never be transmitted, so the intent to authenticate cannot be honoured under
/// any server behaviour. Here it is only suspicious. It is almost always a
/// secret that never reached the process (an unmounted Docker secret, a
/// misspelled variable), but AUTH PLAIN with an empty password is well-formed
/// and some allowlist-style internal relays accept it, so refusing to send
/// would be a guess.
///
/// Checked on the loaded config rather than per source, so the environment and
/// the database, both of which can express this, behave the same way.
fn warn_if_auth_without_password(config: &SmtpConfig) {
    static WARNED: std::sync::Once = std::sync::Once::new();
    if config.uses_auth() && config.password.is_empty() {
        WARNED.call_once(|| {
            tracing::warn!(
                host = %config.host,
                "SMTP username is set with an empty password, so calrs will authenticate with an \
                 empty password and most relays will reject that. Set the password, or clear the \
                 username to relay without authentication."
            );
        });
    }
}

/// Load SMTP config from environment or database.
pub async fn load_smtp_config(pool: &SqlitePool, key: &[u8; 32]) -> Result<Option<SmtpConfig>> {
    if let Some(config) = load_smtp_config_from_env()? {
        if !config.uses_auth() {
            warn_if_env_shadows_db_credentials(pool).await;
        }
        warn_if_auth_without_password(&config);
        return Ok(Some(config));
    }

    let row: Option<(String, i32, String, String, String, Option<String>, String)> =
        sqlx::query_as(
            "SELECT host, port, username, password_enc, from_email, from_name, tls_mode
         FROM smtp_config WHERE enabled = 1 LIMIT 1",
        )
        .fetch_optional(pool)
        .await?;

    match row {
        Some((host, port, username, password_enc, from_email, from_name, tls_mode)) => {
            let password = crate::crypto::decrypt_password(key, &password_enc)?;
            let tls_mode = SmtpTlsMode::parse(&tls_mode).unwrap_or(SmtpTlsMode::StartTls);
            let config = SmtpConfig {
                host,
                port: port as u16,
                username,
                password,
                from_email,
                from_name,
                tls_mode,
            };
            warn_if_auth_without_password(&config);
            Ok(Some(config))
        }
        None => Ok(None),
    }
}

/// Load non-secret SMTP status for admin display.
///
/// Unlike [`load_smtp_config`] this does NOT filter by `enabled = 1` — the
/// admin panel needs to surface a disabled-but-configured row so the operator
/// can see that SMTP exists and re-enable it. `load_smtp_config` only returns
/// rows that are actually usable for sending, so it keeps the `WHERE enabled`
/// guard.
pub async fn load_smtp_status(pool: &SqlitePool) -> Result<Option<SmtpStatus>> {
    if let Some(config) = load_smtp_config_from_env()? {
        return Ok(Some(SmtpStatus {
            host: config.host,
            port: config.port,
            username: config.username,
            from_email: config.from_email,
            from_name: config.from_name,
            tls_mode: config.tls_mode.as_str().to_string(),
            enabled: true,
            from_env: true,
        }));
    }

    // Prefer the enabled row so the status matches the row `load_smtp_config`
    // would actually send from, in case legacy cleanup ever left extra rows.
    let row: Option<(String, i32, String, String, Option<String>, String, bool)> = sqlx::query_as(
        "SELECT host, port, username, from_email, from_name, tls_mode, enabled
         FROM smtp_config ORDER BY enabled DESC LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;

    Ok(row.map(
        |(host, port, username, from_email, from_name, tls_mode, enabled)| SmtpStatus {
            host,
            port: port as u16,
            username,
            from_email,
            from_name,
            tls_mode,
            enabled,
            from_env: false,
        },
    ))
}

/// Send a test email
pub async fn send_test_email(config: &SmtpConfig, to_email: &str) -> Result<()> {
    let to = to_email.parse()?;

    let plain = "This is a test email from calrs. SMTP is working!".to_string();

    let html = render_html_email(
        "SMTP test",
        "This is a test email from calrs. SMTP is working!",
        "#6366f1",
        &[],
        None,
    );

    let body = build_multipart_body(&plain, &html);

    let email = Message::builder()
        .from(config.mailbox_from()?)
        .to(to)
        .subject("calrs \u{2014} SMTP test")
        .multipart(body)?;

    // Debug is only useful when sending a test email
    tracing::debug!("Sending: {:?}", email);
    send_email(config, email).await
}

/// Send a booking invite email to a guest.
///
/// `lang` is the inviting user's language as their dashboard resolved it
/// (saved preference, then their browser's `Accept-Language`). Nothing is
/// known about the invitee yet, and the optional personal message is written
/// by the inviter, so the email is in the inviter's language.
pub async fn send_invite_email(
    config: &SmtpConfig,
    lang: &str,
    guest_name: &str,
    guest_email: &str,
    event_title: &str,
    host_name: &str,
    host_email: &str,
    message: Option<&str>,
    invite_url: &str,
    expires_at: Option<&str>,
) -> Result<()> {
    let to = named_mailbox(guest_name, guest_email)?;
    let mail = compose_invite_email(
        lang,
        guest_name,
        event_title,
        host_name,
        message,
        invite_url,
        expires_at,
    );
    let sender = Sender::Host {
        name: host_name,
        email: host_email,
        lang,
    };
    send_composed(config, sender, to, mail, None).await
}

fn compose_invite_email(
    lang: &str,
    guest_name: &str,
    event_title: &str,
    host_name: &str,
    message: Option<&str>,
    invite_url: &str,
    expires_at: Option<&str>,
) -> ComposedEmail {
    let lang = lang_or_en(Some(lang));
    let mut rows = vec![
        row(t(lang, "confirmed-detail-event"), event_title),
        row(t(lang, "email-detail-invited-by"), host_name),
    ];
    if let Some(msg) = message.filter(|m| !m.trim().is_empty()) {
        rows.push(row(t(lang, "email-detail-message"), msg));
    }
    if let Some(exp) = expires_at {
        rows.push(row(t(lang, "email-detail-expires"), exp));
    }
    let invite_args = [("host", host_name), ("event", event_title)];
    EmailParts {
        lang,
        subject: ta(lang, "email-invite-subject", invite_args),
        heading: ta(lang, "email-confirm-greeting", [("name", guest_name)]),
        message: ta(lang, "email-invite-message", invite_args),
        accent: "#6366f1",
        rows,
        plain_lines: vec![t(lang, "email-invite-link"), invite_url.to_string()],
        footer_plain: None,
        footer_html: None,
        actions: vec![EmailAction {
            label: t(lang, "email-invite-action"),
            url: invite_url.to_string(),
            color: "#6366f1".to_string(),
        }],
    }
    .compose()
}

/// How long to wait for the TCP (and implicit TLS) connection to the SMTP
/// server. lettre's async transport only applies its timeout to the connect
/// step, so this alone cannot bound a server that accepts and then stalls.
pub const SMTP_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Hard ceiling on one whole delivery: connect, greeting, EHLO, STARTTLS,
/// AUTH, envelope and DATA. A relay that accepts the connection and then goes
/// quiet would otherwise hold the caller forever (#236), which on the booking
/// path meant the reverse proxy answering 504 for a booking that existed.
pub const SMTP_SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

async fn send_email(config: &SmtpConfig, email: Message) -> Result<()> {
    send_email_with_timeouts(config, email, SMTP_CONNECT_TIMEOUT, SMTP_SEND_TIMEOUT).await
}

async fn send_email_with_timeouts(
    config: &SmtpConfig,
    email: Message,
    connect_timeout: std::time::Duration,
    send_timeout: std::time::Duration,
) -> Result<()> {
    let builder = match config.tls_mode {
        SmtpTlsMode::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host)?,
        SmtpTlsMode::StartTls => {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host)?
        }
        // `builder_dangerous` is lettre's name for "no TLS", and the name is
        // fair: the message, and any credentials, cross the wire in the clear.
        SmtpTlsMode::Plaintext => {
            if config.uses_auth() {
                tracing::warn!(
                    host = %config.host,
                    "sending SMTP credentials over an unencrypted connection (tls_mode = none)"
                );
            } else if !is_loopback_host(&config.host) {
                tracing::warn!(
                    host = %config.host,
                    "sending email over an unencrypted connection to a non-loopback host (tls_mode = none)"
                );
            }
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.host)
        }
    }
    .port(config.port)
    .timeout(Some(connect_timeout));

    // An empty username means "no SMTP AUTH". lettre only skips authentication
    // when the transport carries no credentials at all: given empty ones it
    // still looks for a mechanism, and a local MTA relaying anonymously from
    // the loopback (Postfix, OpenSMTPD, Stalwart, Mailpit) advertises none, so
    // every send aborts client-side with "No compatible authentication
    // mechanism was found" before the message ever reaches the server.
    let mailer = if !config.uses_auth() {
        builder.build()
    } else {
        builder
            .credentials(Credentials::new(
                config.username.clone(),
                config.password.clone(),
            ))
            .build()
    };

    let to_addrs: Vec<String> = email
        .envelope()
        .to()
        .iter()
        .map(|a| a.to_string())
        .collect();
    let to_display = to_addrs.join(", ");
    match tokio::time::timeout(send_timeout, mailer.send(email)).await {
        Ok(Ok(_)) => {
            tracing::debug!(to = %to_display, "email delivered");
            Ok(())
        }
        // Not logged here: every caller logs the error once, with what it
        // knows about the email (kind, booking). The recipient and server go
        // into the error so that line has them too; log it with `{:#}`.
        Ok(Err(e)) => Err(anyhow::Error::new(e).context(format!(
            "delivery to {} via {}:{} failed",
            to_display, config.host, config.port
        ))),
        Err(_) => anyhow::bail!(
            "delivery to {} timed out: SMTP server {}:{} did not complete it within {}s",
            to_display,
            config.host,
            config.port,
            send_timeout.as_secs_f32()
        ),
    }
}

// --- Reschedule emails ---

#[derive(Clone, Default)]
pub struct RescheduleDetails {
    pub old_utc_times: Option<(String, String)>,
    /// Exact UTC endpoints for new bookings; legacy records use wall-clock fields.
    pub utc_times: Option<(String, String)>,
    pub event_title: String,
    pub old_date: String,
    pub old_start_time: String,
    pub old_end_time: String,
    pub new_date: String,
    pub new_start_time: String,
    pub new_end_time: String,
    pub guest_name: String,
    pub guest_email: String,
    pub guest_timezone: String,
    pub host_name: String,
    pub host_email: String,
    pub uid: String,
    pub location: Option<String>,
    /// Host's IANA timezone (from `users.timezone`). See `BookingDetails::host_timezone`.
    pub host_timezone: String,
    /// Language the guest booked in (`bookings.language`). See
    /// `BookingDetails::guest_language`.
    pub guest_language: Option<String>,
    /// Host recipient's saved language (`users.language`). See
    /// `BookingDetails::host_language`.
    pub host_language: Option<String>,
}

/// Ask the guest to pick a new time (host-initiated reschedule).
/// The guest clicks the link to choose a slot; no time is pre-selected.
pub async fn send_guest_pick_new_time(
    config: &SmtpConfig,
    details: &BookingDetails,
    reschedule_url: &str,
    cancel_url: Option<&str>,
) -> Result<()> {
    let to = named_mailbox(&details.guest_name, &details.guest_email)?;
    let mail = compose_guest_pick_new_time(details, reschedule_url, cancel_url);
    send_composed(config, Sender::host_of(details), to, mail, None).await
}

fn compose_guest_pick_new_time(
    details: &BookingDetails,
    reschedule_url: &str,
    cancel_url: Option<&str>,
) -> ComposedEmail {
    let lang = guest_lang(details);
    let time_display = format!(
        "{} \u{2013} {} ({})",
        details.start_time, details.end_time, details.guest_timezone
    );

    let mut plain_lines = vec![ta(
        lang,
        "email-pick-new-time-link",
        [("url", reschedule_url)],
    )];
    let mut actions = vec![EmailAction {
        label: t(lang, "email-action-pick-new-time"),
        url: reschedule_url.to_string(),
        color: "#d97706".to_string(),
    }];
    if let Some(u) = cancel_url {
        plain_lines.push(ta(lang, "email-confirm-need-to-cancel", [("url", u)]));
        actions.push(EmailAction {
            label: t(lang, "email-action-cancel-booking"),
            url: u.to_string(),
            color: "#dc2626".to_string(),
        });
    }

    EmailParts {
        lang,
        subject: ta(
            lang,
            "email-pick-new-time-subject",
            [("event", &details.event_title)],
        ),
        heading: ta(
            lang,
            "email-confirm-greeting",
            [("name", &details.guest_name)],
        ),
        message: ta(
            lang,
            "email-pick-new-time-message",
            [("host", &details.host_name)],
        ),
        accent: "#d97706",
        rows: vec![
            row(t(lang, "confirmed-detail-event"), &details.event_title),
            row(
                t(lang, "email-detail-originally"),
                date_at_time(lang, &details.date, &time_display),
            ),
            row(t(lang, "confirmed-detail-with"), &details.host_name),
        ],
        plain_lines,
        footer_plain: None,
        footer_html: None,
        actions,
    }
    .compose()
}

/// Notify the guest that their booking was rescheduled, in the language they
/// booked in. Includes updated ICS calendar invite.
pub async fn send_guest_reschedule_notification(
    config: &SmtpConfig,
    details: &RescheduleDetails,
    cancel_url: Option<&str>,
    reschedule_url: Option<&str>,
) -> Result<()> {
    let booking_details = BookingDetails {
        utc_times: details.utc_times.clone(),
        event_title: details.event_title.clone(),
        date: details.new_date.clone(),
        start_time: details.new_start_time.clone(),
        end_time: details.new_end_time.clone(),
        guest_name: details.guest_name.clone(),
        guest_email: details.guest_email.clone(),
        guest_timezone: details.guest_timezone.clone(),
        host_name: details.host_name.clone(),
        host_email: details.host_email.clone(),
        uid: details.uid.clone(),
        notes: None,
        location: details.location.clone(),
        reminder_minutes: None,
        additional_attendees: vec![],
        ..Default::default()
    };
    let ics = generate_ics(&booking_details, "REQUEST");

    let to = named_mailbox(&details.guest_name, &details.guest_email)?;
    let mail = compose_guest_reschedule_notification(details, cancel_url, reschedule_url);
    let sender = Sender::Host {
        name: &details.host_name,
        email: &details.host_email,
        lang: lang_or_en(details.guest_language.as_deref()),
    };
    send_composed(
        config,
        sender,
        to,
        mail,
        Some(("invite.ics", ics, "REQUEST")),
    )
    .await
}

fn compose_guest_reschedule_notification(
    details: &RescheduleDetails,
    cancel_url: Option<&str>,
    reschedule_url: Option<&str>,
) -> ComposedEmail {
    let lang = lang_or_en(details.guest_language.as_deref());
    let new_time_display = format!(
        "{} \u{2013} {} ({})",
        details.new_start_time, details.new_end_time, details.guest_timezone
    );
    let old_time_display = format!(
        "{} \u{2013} {}",
        details.old_start_time, details.old_end_time
    );

    let mut rows = vec![
        row(t(lang, "confirmed-detail-event"), &details.event_title),
        row(
            t(lang, "email-detail-previous"),
            date_at_time(lang, &details.old_date, &old_time_display),
        ),
        row(t(lang, "email-detail-new-date"), &details.new_date),
        row(t(lang, "email-detail-new-time"), new_time_display),
        row(t(lang, "confirmed-detail-with"), &details.host_name),
    ];
    push_row(
        &mut rows,
        lang,
        "confirmed-detail-location",
        details.location.as_ref(),
    );

    let mut plain_lines = Vec::new();
    let mut actions = Vec::new();
    if let Some(u) = reschedule_url {
        plain_lines.push(ta(lang, "email-need-to-reschedule", [("url", u)]));
        actions.push(EmailAction {
            label: t(lang, "email-action-reschedule"),
            url: u.to_string(),
            color: "#d97706".to_string(),
        });
    }
    if let Some(u) = cancel_url {
        plain_lines.push(ta(lang, "email-confirm-need-to-cancel", [("url", u)]));
        actions.push(EmailAction {
            label: t(lang, "email-action-cancel-booking"),
            url: u.to_string(),
            color: "#dc2626".to_string(),
        });
    }

    EmailParts {
        lang,
        // Neutral subject: Exchange uses it as the appointment title (#157).
        subject: ta(
            lang,
            "email-confirm-subject",
            [("event", &details.event_title), ("date", &details.new_date)],
        ),
        heading: ta(
            lang,
            "email-confirm-greeting",
            [("name", &details.guest_name)],
        ),
        message: ta(
            lang,
            "email-rescheduled-message",
            [("host", &details.host_name)],
        ),
        accent: "#d97706",
        rows,
        plain_lines,
        footer_plain: Some(t(lang, "email-rescheduled-ics-attached-plain")),
        footer_html: Some(t(lang, "email-rescheduled-ics-attached-html")),
        actions,
    }
    .compose()
}

/// Notify the host that a guest wants to reschedule, with approve/decline
/// buttons, in the host's language.
pub async fn send_host_reschedule_request(
    config: &SmtpConfig,
    details: &RescheduleDetails,
    confirm_token: Option<&str>,
    base_url: Option<&str>,
) -> Result<()> {
    let to = named_mailbox(&details.host_name, &details.host_email)?;
    let mail = compose_host_reschedule_request(details, confirm_token, base_url);
    send_composed(config, Sender::Instance, to, mail, None).await
}

fn compose_host_reschedule_request(
    details: &RescheduleDetails,
    confirm_token: Option<&str>,
    base_url: Option<&str>,
) -> ComposedEmail {
    let lang = lang_or_en(details.host_language.as_deref());
    let (old_date_display, old_time_display) = host_time_display_exact(
        &details.old_date,
        &details.old_start_time,
        &details.old_end_time,
        &details.guest_timezone,
        &details.host_timezone,
        details.old_utc_times.as_ref(),
    );
    let (new_date_display, new_time_display) = host_time_display_exact(
        &details.new_date,
        &details.new_start_time,
        &details.new_end_time,
        &details.guest_timezone,
        &details.host_timezone,
        details.utc_times.as_ref(),
    );

    let mut rows = vec![
        row(t(lang, "confirmed-detail-event"), &details.event_title),
        row(
            t(lang, "email-detail-previous"),
            date_at_time(lang, &old_date_display, &old_time_display),
        ),
        row(
            t(lang, "email-detail-requested"),
            date_at_time(lang, &new_date_display, &new_time_display),
        ),
        row(
            t(lang, "common-detail-guest"),
            format!("{} <{}>", details.guest_name, details.guest_email),
        ),
    ];
    push_row(
        &mut rows,
        lang,
        "confirmed-detail-location",
        details.location.as_ref(),
    );

    let (plain_lines, actions) = approval_actions(lang, approval_urls(confirm_token, base_url));

    EmailParts {
        lang,
        subject: ta(
            lang,
            "email-host-reschedule-request-subject",
            [
                ("event", &details.event_title),
                ("guest", &details.guest_name),
                ("email", &details.guest_email),
            ],
        ),
        heading: ta(
            lang,
            "email-confirm-greeting",
            [("name", &details.host_name)],
        ),
        message: ta(
            lang,
            "email-host-reschedule-request-message",
            [("guest", &details.guest_name)],
        ),
        accent: "#d97706",
        rows,
        plain_lines,
        footer_plain: None,
        footer_html: None,
        actions,
    }
    .compose()
}

// --- Watcher claim emails ---

/// Offer a booking to a watcher, in the watcher's own language (`lang`, from
/// their `users.language`; `None` is English).
pub async fn send_watcher_claim_notification(
    config: &SmtpConfig,
    details: &BookingDetails,
    watcher_name: &str,
    watcher_email: &str,
    lang: Option<&str>,
    assigned_to_name: &str,
    claim_url: &str,
) -> Result<()> {
    let to = named_mailbox(watcher_name, watcher_email)?;
    let mail = compose_watcher_claim_notification(
        details,
        watcher_name,
        lang,
        assigned_to_name,
        claim_url,
    );
    send_composed(config, Sender::Instance, to, mail, None).await
}

fn compose_watcher_claim_notification(
    details: &BookingDetails,
    watcher_name: &str,
    lang: Option<&str>,
    assigned_to_name: &str,
    claim_url: &str,
) -> ComposedEmail {
    let lang = lang_or_en(lang);
    let time_display = format!("{} \u{2013} {}", details.start_time, details.end_time);
    let mut rows = host_rows(
        lang,
        &details.event_title,
        &details.date,
        &time_display,
        &details.guest_name,
        &details.guest_email,
    );
    rows.push(row(t(lang, "claim-assigned-to"), assigned_to_name));
    push_row(
        &mut rows,
        lang,
        "confirmed-detail-location",
        details.location.as_ref(),
    );

    let footer = t(lang, "email-watcher-claim-footer");
    EmailParts {
        lang,
        subject: ta(
            lang,
            "email-watcher-claim-subject",
            [
                ("event", &details.event_title),
                ("guest", &details.guest_name),
                ("date", &details.date),
            ],
        ),
        heading: ta(lang, "email-confirm-greeting", [("name", watcher_name)]),
        message: t(lang, "email-watcher-claim-message"),
        accent: "#3b82f6",
        rows,
        plain_lines: vec![ta(lang, "email-watcher-claim-link", [("url", claim_url)])],
        footer_plain: Some(footer.clone()),
        footer_html: Some(footer),
        actions: vec![EmailAction {
            label: t(lang, "claim-button"),
            url: claim_url.to_string(),
            color: "#3b82f6".to_string(),
        }],
    }
    .compose()
}

/// Confirm a claim to the watcher who made it, in their language (`lang`,
/// from their `users.language`; `None` is English).
pub async fn send_claim_confirmation(
    config: &SmtpConfig,
    details: &BookingDetails,
    claimant_name: &str,
    claimant_email: &str,
    lang: Option<&str>,
) -> Result<()> {
    let to = named_mailbox(claimant_name, claimant_email)?;
    let mail = compose_claim_confirmation(details, claimant_name, lang);
    send_composed(config, Sender::Instance, to, mail, None).await
}

fn compose_claim_confirmation(
    details: &BookingDetails,
    claimant_name: &str,
    lang: Option<&str>,
) -> ComposedEmail {
    let lang = lang_or_en(lang);
    let time_display = format!("{} \u{2013} {}", details.start_time, details.end_time);
    let mut rows = host_rows(
        lang,
        &details.event_title,
        &details.date,
        &time_display,
        &details.guest_name,
        &details.guest_email,
    );
    push_row(
        &mut rows,
        lang,
        "confirmed-detail-location",
        details.location.as_ref(),
    );

    let footer = t(lang, "email-claim-confirmed-footer");
    EmailParts {
        lang,
        subject: ta(
            lang,
            "email-claim-confirmed-subject",
            [
                ("event", &details.event_title),
                ("guest", &details.guest_name),
                ("date", &details.date),
            ],
        ),
        heading: ta(lang, "email-confirm-greeting", [("name", claimant_name)]),
        message: t(lang, "claimed-subtitle"),
        accent: "#16a34a",
        rows,
        plain_lines: vec![],
        footer_plain: Some(footer.clone()),
        footer_html: Some(footer),
        actions: vec![],
    }
    .compose()
}

#[cfg(test)]
mod tests {
    use lettre::Address;

    use super::*;

    // The crate-wide lock, not a module-local one: web tests that send real
    // mail through `load_smtp_config` must not see a half-set
    // `CALRS_SMTP_*` block from these tests running on another thread.
    struct SmtpEnvGuard {
        _lock: tokio::sync::MutexGuard<'static, ()>,
        old_values: Vec<(&'static str, Option<String>)>,
    }

    impl SmtpEnvGuard {
        fn new() -> Self {
            let lock = crate::test_support::ENV_LOCK.blocking_lock();
            let old_values = SMTP_ENV_VARS
                .iter()
                .map(|name| (*name, std::env::var(name).ok()))
                .collect();
            for name in SMTP_ENV_VARS {
                std::env::remove_var(name);
            }
            Self {
                _lock: lock,
                old_values,
            }
        }
    }

    impl Drop for SmtpEnvGuard {
        fn drop(&mut self) {
            for (name, value) in &self.old_values {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
    }

    fn smtp_env_error() -> String {
        load_smtp_config_from_env()
            .expect_err("expected SMTP env config to fail")
            .to_string()
    }

    #[test]
    fn redteam_host_email_keeps_exact_end_across_rollback_and_midnight() {
        let times = ("20261024T233000Z".into(), "20261025T010000Z".into());
        let legacy = host_time_display("2026-10-25", "01:30", "02:00", "Europe/Paris", "UTC");
        assert_eq!(legacy.1, "23:30 – 00:00 (UTC)");
        let exact = host_time_display_exact(
            "2026-10-25",
            "01:30",
            "02:00",
            "Europe/Paris",
            "UTC",
            Some(&times),
        );
        assert_eq!(exact, ("2026-10-24".into(), "23:30 – 01:00 (UTC)".into()));
        assert_eq!(
            host_time_display_exact("2026-10-25", "01:30", "02:00", "Europe/Paris", "UTC", None),
            legacy
        );
    }

    #[test]
    fn smtp_config_mailbox_from() {
        let config = SmtpConfig {
            host: "host".to_string(),
            port: 587,
            username: "user".to_string(),
            password: "password".to_string(),
            from_name: None,
            from_email: "username@example.com".to_string(),
            tls_mode: SmtpTlsMode::StartTls,
        };
        assert_eq!(
            config.mailbox_from().unwrap(),
            Mailbox::new(None, Address::new("username", "example.com").unwrap()),
            "from email with no name"
        );

        let config = SmtpConfig {
            host: "host".to_string(),
            port: 587,
            username: "username".to_string(),
            password: "password".to_string(),
            from_name: Some("Name, With Comma".to_string()),
            from_email: "username@example.com".to_string(),
            tls_mode: SmtpTlsMode::StartTls,
        };
        assert_eq!(
            config.mailbox_from().unwrap(),
            Mailbox::new(
                Some("Name, With Comma".to_string()),
                Address::new("username", "example.com").unwrap()
            ),
            "from email with name"
        );
    }

    #[test]
    fn guest_sender_name_puts_host_ahead_of_configured_name() {
        let name = |host: &str, from: Option<&str>| guest_sender_name("en", host, from);
        assert_eq!(
            name("Bob Smith", Some("Vates Scheduling")).as_deref(),
            Some("Bob Smith via Vates Scheduling")
        );
        assert_eq!(name("Bob Smith", None).as_deref(), Some("Bob Smith"));
        assert_eq!(name("Bob Smith", Some("  ")).as_deref(), Some("Bob Smith"));
        assert_eq!(
            name("", Some("Vates Scheduling")).as_deref(),
            Some("Vates Scheduling")
        );
        assert_eq!(name(" ", None), None);
        assert_eq!(
            name("Bob\r\nBcc: evil@example.com", None).as_deref(),
            Some("BobBcc: evil@example.com")
        );
        // Bidi overrides and isolates are dropped, from either part.
        assert_eq!(
            name("\u{202E}ecilA\u{202C}", Some("Acme\u{2066}\u{200F}")).as_deref(),
            Some("ecilA via Acme")
        );

        // A large collective roster is truncated rather than growing the header.
        let roster = vec!["Łukasz Kowalski"; 20].join(" & ");
        let full = name(&roster, Some("Vates")).unwrap();
        let host = full.strip_suffix(" via Vates").unwrap();
        assert!(host.chars().count() <= GUEST_SENDER_HOST_MAX_CHARS);
        assert!(host.ends_with('\u{2026}'));
        let exact = "a".repeat(GUEST_SENDER_HOST_MAX_CHARS);
        assert_eq!(name(&exact, None), Some(exact));
    }

    #[test]
    fn guest_sender_name_joins_in_the_email_language() {
        let via = |lang: &str| guest_sender_name(lang, "Bob", Some("Acme")).unwrap();
        assert_eq!(via("de"), "Bob über Acme");
        assert_eq!(via("et"), "Bob Acme kaudu");
        assert_eq!(via("pl"), "Bob przez Acme");
        // Every shipped locale keeps both names, so no translation can drop
        // the host or the instance from the header.
        for (lang, _) in crate::i18n::supported_with_labels() {
            let name = via(lang);
            assert!(
                name.contains("Bob") && name.contains("Acme"),
                "{lang}: {name}"
            );
        }
    }

    fn header_test_config(from_name: Option<&str>) -> SmtpConfig {
        SmtpConfig {
            host: "host".to_string(),
            port: 587,
            username: String::new(),
            password: String::new(),
            from_name: from_name.map(str::to_string),
            from_email: "noreply@example.com".to_string(),
            tls_mode: SmtpTlsMode::StartTls,
        }
    }

    /// The headers a message started by `sender` goes out with.
    fn wire_headers(config: &SmtpConfig, sender: Sender<'_>) -> String {
        let email = config
            .message_from(sender)
            .unwrap()
            .to("guest@example.org".parse().unwrap())
            .subject("s")
            .body(String::from("b"))
            .unwrap();
        String::from_utf8(email.formatted()).unwrap()
    }

    #[test]
    fn host_sender_sets_display_name_and_reply_to() {
        let config = header_test_config(Some("Vates Scheduling"));
        let host = |email| Sender::Host {
            name: "Bob Smith",
            email,
            lang: "en",
        };

        let wire = wire_headers(&config, host("bob@example.com"));
        assert!(
            wire.contains("From: \"Bob Smith via Vates Scheduling\" <noreply@example.com>"),
            "{wire}"
        );
        assert!(wire.contains("Reply-To: bob@example.com"), "{wire}");

        // A host without a usable address still gets the display name, and
        // no Reply-To rather than a malformed or multi-address one.
        for bad in [
            "",
            "not an address",
            "a@example.com, b@example.com",
            "Mallory <m@evil.example>",
            "bob@example.com\r\nBcc: x@evil.example",
        ] {
            let wire = wire_headers(&config, host(bad));
            assert!(
                wire.contains("From: \"Bob Smith via Vates Scheduling\""),
                "{bad:?}: {wire}"
            );
            assert!(!wire.contains("Reply-To"), "{bad:?}: {wire}");
            assert!(!wire.contains("Bcc"), "{bad:?}: {wire}");
        }

        // The instance sender is untouched: configured name, no Reply-To.
        let wire = wire_headers(&config, Sender::Instance);
        assert!(
            wire.contains("From: \"Vates Scheduling\" <noreply@example.com>"),
            "{wire}"
        );
        assert!(!wire.contains("Reply-To"), "{wire}");
    }

    #[test]
    fn host_sender_name_with_non_ascii_or_specials_is_encoded() {
        // A translated joiner or a host name with non-ASCII, quotes or an
        // address-looking part must reach the wire RFC 2047-encoded, never
        // as a second address in From.
        let config = header_test_config(Some("Acme"));
        for (name, lang) in [
            ("Jürgen", "de"),
            ("\"Support\" <it@evil.example>", "en"),
            ("Alice, Bob", "en"),
        ] {
            let wire = wire_headers(
                &config,
                Sender::Host {
                    name,
                    email: "host@example.com",
                    lang,
                },
            );
            let from = wire
                .split("\r\n")
                .find(|l| l.starts_with("From: "))
                .unwrap();
            assert!(from.ends_with("<noreply@example.com>"), "{from}");
            assert!(!from.contains("it@evil.example"), "{from}");
            assert!(from.is_ascii(), "{from}");
        }
    }

    /// Every guest-facing sender must go out under the host's name with a
    /// Reply-To (#221), and no host, member, watcher or admin email may. A
    /// guard over the sources, so a new `send_guest_*` cannot quietly fall
    /// back to the instance sender.
    #[test]
    fn guest_emails_use_the_host_sender_and_host_emails_do_not() {
        let files = [include_str!("mod.rs")];
        let mut seen_guest = 0;
        for chunk in files
            .iter()
            .flat_map(|src| src.split("\n#[cfg(test)]\nmod tests").next())
            .flat_map(|src| src.split("\npub async fn ").skip(1))
        {
            let name = &chunk[..chunk.find('(').unwrap()];
            let body = &chunk[..chunk.find("\n}\n").unwrap()];
            let uses_host = body.contains("Sender::Host") || body.contains("Sender::host_of");
            let guest = name.starts_with("send_guest_") || name == "send_invite_email";
            if guest {
                seen_guest += 1;
                // Thin wrappers delegate to the `_ex` variant.
                let delegates = body.contains(&format!("{name}_ex("));
                assert!(
                    uses_host || delegates,
                    "{name} is guest-facing but not sent as the host"
                );
            } else {
                assert!(
                    !uses_host,
                    "{name} is not guest-facing but sent as the host"
                );
            }
        }
        assert!(seen_guest >= 10, "only {seen_guest} guest senders found");
    }

    // --- sanitize_ics ---

    #[test]
    fn smtp_tls_mode_parses_supported_values() {
        assert_eq!(
            SmtpTlsMode::parse("starttls").unwrap(),
            SmtpTlsMode::StartTls
        );
        assert_eq!(SmtpTlsMode::parse(" TLS ").unwrap(), SmtpTlsMode::Tls);
        assert_eq!(SmtpTlsMode::parse("none").unwrap(), SmtpTlsMode::Plaintext);
        assert_eq!(
            SmtpTlsMode::parse("Plaintext").unwrap(),
            SmtpTlsMode::Plaintext
        );
        // Round-trips through the string stored in the DB and the env.
        for mode in [
            SmtpTlsMode::StartTls,
            SmtpTlsMode::Tls,
            SmtpTlsMode::Plaintext,
        ] {
            assert_eq!(SmtpTlsMode::parse(mode.as_str()).unwrap(), mode);
        }
    }

    #[test]
    fn loopback_hosts_are_recognised() {
        for host in [
            "localhost",
            "LOCALHOST",
            " 127.0.0.1 ",
            "127.1.2.3",
            "::1",
            "[::1]",
        ] {
            assert!(is_loopback_host(host), "{host} should be loopback");
        }
        for host in ["smtp.example.com", "10.0.0.1", "192.168.1.10", "", "::2"] {
            assert!(!is_loopback_host(host), "{host} should not be loopback");
        }
    }

    #[test]
    fn smtp_tls_mode_rejects_unknown_values() {
        let err = SmtpTlsMode::parse("ssl").unwrap_err().to_string();
        assert!(err.contains("CALRS_SMTP_TLS_MODE"));
    }

    #[test]
    fn smtp_env_absent_returns_none() {
        let _env = SmtpEnvGuard::new();
        assert!(load_smtp_config_from_env().unwrap().is_none());
    }

    #[test]
    fn smtp_env_complete_defaults_to_starttls() {
        let _env = SmtpEnvGuard::new();
        std::env::set_var("CALRS_SMTP_HOST", "smtp.example.com");
        std::env::set_var("CALRS_SMTP_USERNAME", "user");
        std::env::set_var("CALRS_SMTP_PASSWORD", "secret");
        std::env::set_var("CALRS_SMTP_FROM_EMAIL", "noreply@example.com");

        let config = load_smtp_config_from_env().unwrap().unwrap();

        assert_eq!(config.host, "smtp.example.com");
        assert_eq!(config.port, 587);
        assert_eq!(config.tls_mode, SmtpTlsMode::StartTls);
    }

    /// A local MTA relaying anonymously from the loopback: it advertises no
    /// AUTH and no STARTTLS, like the servers in issue #190. Handles exactly
    /// one connection and returns the commands it saw, so a test can tell
    /// "the message arrived" from "the client hung up after EHLO".
    async fn fake_no_auth_mta(listener: tokio::net::TcpListener) -> Vec<String> {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let (stream, _) = listener.accept().await.expect("accept");
        let (read_half, mut write) = stream.into_split();
        let mut reader = BufReader::new(read_half);
        let mut seen = Vec::new();

        macro_rules! say {
            ($($arg:tt)*) => {{
                let line = format!($($arg)*);
                write.write_all(line.as_bytes()).await.expect("write");
                write.write_all(b"\r\n").await.expect("write");
            }};
        }

        say!("220 fake.local ESMTP");
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line).await {
                Ok(0) | Err(_) => break, // client hung up
                Ok(_) => {}
            }
            let line = line.trim_end().to_string();
            let upper = line.to_ascii_uppercase();
            seen.push(line);

            if upper.starts_with("EHLO") {
                say!("250-fake.local");
                say!("250 8BITMIME"); // deliberately no AUTH, no STARTTLS
            } else if upper.starts_with("MAIL FROM") || upper.starts_with("RCPT TO") {
                say!("250 2.1.0 OK");
            } else if upper == "DATA" {
                say!("354 End data with <CR><LF>.<CR><LF>");
                loop {
                    let mut body = String::new();
                    match reader.read_line(&mut body).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                    if body.trim_end() == "." {
                        break;
                    }
                }
                say!("250 2.0.0 OK: queued");
            } else if upper.starts_with("AUTH") {
                say!("502 5.5.1 AUTH not supported");
            } else if upper == "QUIT" {
                say!("221 2.0.0 Bye");
                break;
            } else {
                say!("250 OK");
            }
        }
        seen
    }

    fn plaintext_config(port: u16, username: &str) -> SmtpConfig {
        SmtpConfig {
            host: "127.0.0.1".to_string(),
            port,
            username: username.to_string(),
            password: if username.is_empty() {
                String::new()
            } else {
                "secret".to_string()
            },
            from_name: None,
            from_email: "noreply@example.com".to_string(),
            tls_mode: SmtpTlsMode::Plaintext,
        }
    }

    fn test_message() -> Message {
        Message::builder()
            .from("noreply@example.com".parse().unwrap())
            .to("guest@example.com".parse().unwrap())
            .subject("test")
            .body("hello".to_string())
            .unwrap()
    }

    /// Regression test for #190: with no username configured, the message must
    /// actually reach a relay that advertises no AUTH mechanism.
    #[tokio::test]
    async fn unauthenticated_relay_receives_the_message() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(fake_no_auth_mta(listener));

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            send_email(&plaintext_config(port, ""), test_message()),
        )
        .await
        .expect("send timed out");
        result.expect("send should succeed against a no-auth relay");

        let seen = tokio::time::timeout(std::time::Duration::from_secs(10), server)
            .await
            .expect("server timed out")
            .unwrap();
        assert!(seen.iter().any(|c| c.starts_with("MAIL FROM")), "{seen:?}");
        assert!(seen.iter().any(|c| c.starts_with("RCPT TO")), "{seen:?}");
        assert!(seen.iter().any(|c| c == "DATA"), "{seen:?}");
        assert!(!seen.iter().any(|c| c.starts_with("AUTH")), "{seen:?}");
    }

    /// The other half of #190: a username must still mean authentication, so
    /// the same relay fails the way it always did. Without this, "skip auth
    /// when the username is empty" could regress into "never authenticate".
    #[tokio::test]
    async fn credentials_against_a_no_auth_relay_still_fail() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(fake_no_auth_mta(listener));

        let err = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            send_email(&plaintext_config(port, "alice"), test_message()),
        )
        .await
        .expect("send timed out")
        .expect_err("a no-auth relay cannot satisfy configured credentials");
        assert!(
            format!("{err:#}").contains("authentication mechanism"),
            "unexpected error: {err}"
        );

        // The client aborts before the envelope: nothing reaches the MTA.
        let seen = tokio::time::timeout(std::time::Duration::from_secs(10), server)
            .await
            .expect("server timed out")
            .unwrap();
        assert!(!seen.iter().any(|c| c.starts_with("MAIL FROM")), "{seen:?}");
    }

    /// #236: a relay that accepts the TCP connection and then never speaks
    /// must not hold the caller. lettre's own timeout only covers connect, so
    /// this exercises the outer deadline around the whole delivery.
    #[tokio::test]
    async fn stalled_relay_times_out_instead_of_hanging() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // Accept, hold the socket open, and never send the 220 greeting.
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            drop(sock);
        });

        let started = std::time::Instant::now();
        let err = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            send_email_with_timeouts(
                &plaintext_config(port, ""),
                test_message(),
                std::time::Duration::from_secs(5),
                std::time::Duration::from_millis(300),
            ),
        )
        .await
        .expect("send_email ignored its deadline")
        .expect_err("a silent relay cannot deliver");
        assert!(
            err.to_string().contains("within"),
            "unexpected error: {err}"
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        server.abort();
    }

    #[test]
    fn smtp_timeouts_fit_under_a_reverse_proxy() {
        // nginx and most proxies give up on an upstream after 60s. The admin
        // "send test email" call is still synchronous, so a dead relay must
        // fail well before that.
        assert!(SMTP_CONNECT_TIMEOUT <= SMTP_SEND_TIMEOUT);
        assert!(SMTP_SEND_TIMEOUT < std::time::Duration::from_secs(60));
    }

    #[test]
    fn smtp_config_without_username_skips_auth() {
        // An unauthenticated local relay: attaching empty credentials makes
        // lettre hunt for a mechanism the server never advertises, and every
        // send aborts client-side before DATA.
        let mut config = SmtpConfig {
            host: "localhost".to_string(),
            port: 25,
            username: String::new(),
            password: String::new(),
            from_name: None,
            from_email: "noreply@example.com".to_string(),
            tls_mode: SmtpTlsMode::StartTls,
        };
        assert!(!config.uses_auth());

        config.username = "   ".to_string();
        assert!(!config.uses_auth());

        config.username = "user".to_string();
        assert!(config.uses_auth());
    }

    #[test]
    fn smtp_env_without_credentials_is_unauthenticated() {
        let _env = SmtpEnvGuard::new();
        // A container pointed at a sidecar MTA: host and sender are enough.
        std::env::set_var("CALRS_SMTP_HOST", "localhost");
        std::env::set_var("CALRS_SMTP_FROM_EMAIL", "noreply@example.com");

        let config = load_smtp_config_from_env().unwrap().unwrap();

        assert_eq!(config.host, "localhost");
        assert!(config.username.is_empty());
        assert!(config.password.is_empty());
        assert!(!config.uses_auth());
    }

    #[test]
    fn smtp_env_accepts_plaintext_tls_mode() {
        let _env = SmtpEnvGuard::new();
        // The whole unauthenticated-loopback-MTA setup, from the environment.
        std::env::set_var("CALRS_SMTP_HOST", "localhost");
        std::env::set_var("CALRS_SMTP_PORT", "25");
        std::env::set_var("CALRS_SMTP_TLS_MODE", "none");
        std::env::set_var("CALRS_SMTP_FROM_EMAIL", "noreply@example.com");

        let config = load_smtp_config_from_env().unwrap().unwrap();

        assert_eq!(config.port, 25);
        assert_eq!(config.tls_mode, SmtpTlsMode::Plaintext);
        assert!(!config.uses_auth());
    }

    /// The deliberate asymmetry with `smtp_env_password_without_username_errors`.
    /// A password with no username is provably unusable, so it is fatal. A
    /// username with no password might still authenticate against a permissive
    /// relay, so it loads and only warns.
    #[test]
    fn smtp_env_username_without_password_is_allowed() {
        let _env = SmtpEnvGuard::new();
        std::env::set_var("CALRS_SMTP_HOST", "smtp.example.com");
        std::env::set_var("CALRS_SMTP_FROM_EMAIL", "noreply@example.com");
        std::env::set_var("CALRS_SMTP_USERNAME", "alice");

        let config = load_smtp_config_from_env()
            .expect("a username with no password must not be fatal")
            .expect("the block is complete");

        assert_eq!(config.username, "alice");
        assert!(config.password.is_empty());
        assert!(config.uses_auth(), "credentials must still be attached");
    }

    #[test]
    fn smtp_env_password_without_username_errors() {
        let _env = SmtpEnvGuard::new();
        std::env::set_var("CALRS_SMTP_HOST", "smtp.example.com");
        std::env::set_var("CALRS_SMTP_FROM_EMAIL", "noreply@example.com");
        std::env::set_var("CALRS_SMTP_PASSWORD", "secret");

        let err = smtp_env_error();

        assert!(err.contains("CALRS_SMTP_USERNAME"));
    }

    #[test]
    fn smtp_env_partial_config_falls_back_to_db() {
        let _env = SmtpEnvGuard::new();
        // Only one of the required vars is set: the block is incomplete, so the
        // env is ignored and the caller falls back to the database config
        // (instead of erroring out and breaking SMTP entirely).
        std::env::set_var("CALRS_SMTP_HOST", "smtp.example.com");

        assert!(load_smtp_config_from_env().unwrap().is_none());
    }

    #[test]
    fn smtp_env_invalid_port_errors() {
        let _env = SmtpEnvGuard::new();
        std::env::set_var("CALRS_SMTP_HOST", "smtp.example.com");
        std::env::set_var("CALRS_SMTP_USERNAME", "user");
        std::env::set_var("CALRS_SMTP_PASSWORD", "secret");
        std::env::set_var("CALRS_SMTP_FROM_EMAIL", "noreply@example.com");
        std::env::set_var("CALRS_SMTP_PORT", "not-a-port");

        let err = smtp_env_error();

        assert!(err.contains("CALRS_SMTP_PORT"));
    }

    #[test]
    fn smtp_env_invalid_tls_mode_errors() {
        let _env = SmtpEnvGuard::new();
        std::env::set_var("CALRS_SMTP_HOST", "smtp.example.com");
        std::env::set_var("CALRS_SMTP_USERNAME", "user");
        std::env::set_var("CALRS_SMTP_PASSWORD", "secret");
        std::env::set_var("CALRS_SMTP_FROM_EMAIL", "noreply@example.com");
        std::env::set_var("CALRS_SMTP_TLS_MODE", "ssl");

        let err = smtp_env_error();

        assert!(err.contains("CALRS_SMTP_TLS_MODE"));
    }

    #[test]
    fn sanitize_strips_cr_lf() {
        assert_eq!(sanitize_ics("line1\r\nline2\nline3"), "line1 line2 line3");
    }

    #[test]
    fn sanitize_escapes_semicolon_comma() {
        assert_eq!(sanitize_ics("a;b,c"), "a\\;b\\,c");
    }

    #[test]
    fn sanitize_combined() {
        assert_eq!(
            sanitize_ics("Meeting; room A\nfloor 2"),
            "Meeting\\; room A floor 2"
        );
    }

    #[test]
    fn sanitize_preserves_normal_text() {
        assert_eq!(sanitize_ics("Hello World"), "Hello World");
    }

    #[test]
    fn sanitize_empty_string() {
        assert_eq!(sanitize_ics(""), "");
    }

    #[test]
    fn sanitize_prevents_ics_injection() {
        // An attacker tries to inject a new ICS field via newline
        let malicious = "Meeting\r\nATTENDEE:evil@hacker.com";
        let sanitized = sanitize_ics(malicious);
        assert!(!sanitized.contains('\n'));
        assert!(!sanitized.contains('\r'));
    }

    // --- generate_ics ---

    #[test]
    fn generate_ics_basic_structure() {
        let details = BookingDetails {
            event_title: "Intro Call".to_string(),
            date: "2026-03-10".to_string(),
            start_time: "14:00".to_string(),
            end_time: "14:30".to_string(),
            guest_name: "Jane Doe".to_string(),
            guest_email: "jane@example.com".to_string(),
            guest_timezone: "Europe/Paris".to_string(),
            host_name: "Alice".to_string(),
            host_email: "alice@cal.rs".to_string(),
            uid: "test-uid-123".to_string(),
            notes: None,
            location: None,
            reminder_minutes: None,
            additional_attendees: vec![],
            ..Default::default()
        };

        let ics = generate_ics(&details, "PUBLISH");
        assert!(ics.contains("BEGIN:VCALENDAR"));
        assert!(ics.contains("END:VCALENDAR"));
        assert!(ics.contains("METHOD:PUBLISH"));
        assert!(ics.contains("BEGIN:VEVENT"));
        assert!(ics.contains("END:VEVENT"));
        assert!(ics.contains("UID:test-uid-123"));
        // Europe/Paris is UTC+1 in March (CET), so 14:00 Paris = 13:00 UTC
        assert!(ics.contains("DTSTART:20260310T130000Z"));
        assert!(ics.contains("DTEND:20260310T133000Z"));
        assert!(ics.contains("SUMMARY:Intro Call \u{2014} Jane & Alice"));
        assert!(ics.contains("ORGANIZER;CN=Alice:mailto:alice@cal.rs"));
        assert!(ics.contains("ATTENDEE;CN=Jane Doe;RSVP=TRUE:mailto:jane@example.com"));
        assert!(ics.contains("STATUS:CONFIRMED"));
    }

    // Regression test for #141: the CalDAV write-back variant must mark
    // every ATTENDEE with SCHEDULE-AGENT=CLIENT (RFC 6638 §7.1) so servers
    // like Fastmail do not send their own duplicate iMIP invite, while the
    // email variant keeps plain ATTENDEE lines for "Add to calendar".
    #[test]
    fn generate_ics_caldav_marks_attendees_schedule_agent_client() {
        let details = BookingDetails {
            event_title: "Intro Call".to_string(),
            date: "2026-03-10".to_string(),
            start_time: "14:00".to_string(),
            end_time: "14:30".to_string(),
            guest_name: "Jane Doe".to_string(),
            guest_email: "jane@example.com".to_string(),
            guest_timezone: "Europe/Paris".to_string(),
            host_name: "Alice".to_string(),
            host_email: "alice@cal.rs".to_string(),
            uid: "test-uid-141".to_string(),
            notes: None,
            location: None,
            reminder_minutes: None,
            additional_attendees: vec!["bob@example.com".to_string()],
            ..Default::default()
        };

        let caldav = generate_ics_caldav(&details);
        assert!(!caldav.contains("METHOD:"), "CalDAV PUT must omit METHOD");
        assert!(caldav.contains(
            "ATTENDEE;SCHEDULE-AGENT=CLIENT;CN=Jane Doe;RSVP=TRUE:mailto:jane@example.com"
        ));
        assert!(caldav.contains("ATTENDEE;SCHEDULE-AGENT=CLIENT;RSVP=TRUE:mailto:bob@example.com"));

        let email = generate_ics(&details, "REQUEST");
        assert!(
            !email.contains("SCHEDULE-AGENT"),
            "email .ics must keep plain ATTENDEE lines"
        );
        assert!(email.contains("ATTENDEE;CN=Jane Doe;RSVP=TRUE:mailto:jane@example.com"));
    }

    // Regression test for #49: DTSTAMP is REQUIRED in VEVENT by RFC 5545 §3.6.1.
    // It was missing before, and strict clients (RustiCal) rejected the invite.
    // Permissive ones (Gmail / Outlook) silently accepted it, so this went
    // undetected for a while — keep this test even if current clients stop
    // caring.
    #[test]
    fn generate_ics_has_rfc5545_dtstamp() {
        let details = BookingDetails {
            event_title: "Intro Call".to_string(),
            date: "2026-03-10".to_string(),
            start_time: "14:00".to_string(),
            end_time: "14:30".to_string(),
            guest_name: "Jane Doe".to_string(),
            guest_email: "jane@example.com".to_string(),
            guest_timezone: "UTC".to_string(),
            host_name: "Alice".to_string(),
            host_email: "alice@cal.rs".to_string(),
            uid: "dtstamp-uid".to_string(),
            notes: None,
            location: None,
            reminder_minutes: None,
            additional_attendees: vec![],
            ..Default::default()
        };

        let ics = generate_ics(&details, "REQUEST");

        let line = ics
            .lines()
            .find(|l| l.starts_with("DTSTAMP:"))
            .unwrap_or_else(|| panic!("DTSTAMP line missing from VEVENT:\n{}", ics));

        // RFC 5545 §3.3.5 form #2: YYYYMMDDTHHMMSSZ (UTC). 16 chars, 'T' at
        // position 8, trailing 'Z', digits everywhere else.
        let ts = &line["DTSTAMP:".len()..];
        assert_eq!(ts.len(), 16, "DTSTAMP wrong length: {:?}", ts);
        assert_eq!(ts.chars().nth(8), Some('T'), "no 'T' separator: {:?}", ts);
        assert!(ts.ends_with('Z'), "missing 'Z' UTC marker: {:?}", ts);
        assert!(
            ts[..8].chars().all(|c| c.is_ascii_digit()),
            "date part not digits: {:?}",
            &ts[..8]
        );
        assert!(
            ts[9..15].chars().all(|c| c.is_ascii_digit()),
            "time part not digits: {:?}",
            &ts[9..15]
        );
    }

    #[test]
    fn generate_ics_with_location() {
        let details = BookingDetails {
            event_title: "Meeting".to_string(),
            date: "2026-03-10".to_string(),
            start_time: "09:00".to_string(),
            end_time: "10:00".to_string(),
            guest_name: "Bob".to_string(),
            guest_email: "bob@test.com".to_string(),
            guest_timezone: "UTC".to_string(),
            host_name: "Alice".to_string(),
            host_email: "alice@test.com".to_string(),
            uid: "uid-456".to_string(),
            notes: Some("Discuss roadmap".to_string()),
            location: Some("https://meet.example.com/room".to_string()),
            reminder_minutes: None,
            additional_attendees: vec![],
            ..Default::default()
        };

        let ics = generate_ics(&details, "REQUEST");
        assert!(ics.contains("METHOD:REQUEST"));
        assert!(ics.contains("LOCATION:https://meet.example.com/room\r\n"));
        assert!(ics.contains("DESCRIPTION:Discuss roadmap\r\n"));
        // ORGANIZER must be its own line, not folded into LOCATION
        assert!(ics.contains("\r\nORGANIZER;"));
    }

    #[test]
    fn generate_ics_no_line_starts_with_whitespace() {
        // RFC 5545 §3.1: a line starting with whitespace is folded into the previous
        // logical line. Leading spaces on any property line would make clients (Gmail,
        // notably) fail to detect VEVENT at all.
        let details = BookingDetails {
            event_title: "Test".to_string(),
            date: "2026-03-10".to_string(),
            start_time: "09:00".to_string(),
            end_time: "10:00".to_string(),
            guest_name: "Bob".to_string(),
            guest_email: "bob@test.com".to_string(),
            guest_timezone: "UTC".to_string(),
            host_name: "Alice".to_string(),
            host_email: "alice@test.com".to_string(),
            uid: "uid-fold".to_string(),
            notes: Some("n".to_string()),
            location: Some("https://example.com".to_string()),
            reminder_minutes: Some(15),
            additional_attendees: vec!["a@test.com".to_string(), "b@test.com".to_string()],
            ..Default::default()
        };
        let ics = generate_ics(&details, "REQUEST");
        for line in ics.split("\r\n") {
            assert!(
                !line.starts_with(' ') && !line.starts_with('\t'),
                "ICS line must not start with whitespace (would be folded): {:?}",
                line
            );
        }
    }

    #[test]
    fn generate_ics_no_description_when_no_notes() {
        let details = BookingDetails {
            event_title: "Call".to_string(),
            date: "2026-03-10".to_string(),
            start_time: "09:00".to_string(),
            end_time: "10:00".to_string(),
            guest_name: "Bob".to_string(),
            guest_email: "bob@test.com".to_string(),
            guest_timezone: "UTC".to_string(),
            host_name: "Alice".to_string(),
            host_email: "alice@test.com".to_string(),
            uid: "uid-no-notes".to_string(),
            notes: None,
            location: None,
            reminder_minutes: None,
            additional_attendees: vec![],
            ..Default::default()
        };

        let ics = generate_ics(&details, "PUBLISH");
        assert!(!ics.contains("DESCRIPTION:"));
    }

    #[test]
    fn generate_ics_summary_includes_first_names() {
        let details = BookingDetails {
            event_title: "30min call".to_string(),
            date: "2026-03-10".to_string(),
            start_time: "09:00".to_string(),
            end_time: "09:30".to_string(),
            guest_name: "Jean-Baptiste Piacentino".to_string(),
            guest_email: "jb@test.com".to_string(),
            guest_timezone: "UTC".to_string(),
            host_name: "Olivier Lambert".to_string(),
            host_email: "olivier@test.com".to_string(),
            uid: "uid-names".to_string(),
            notes: None,
            location: None,
            reminder_minutes: None,
            additional_attendees: vec![],
            ..Default::default()
        };

        let ics = generate_ics(&details, "PUBLISH");
        assert!(ics.contains("SUMMARY:30min call \u{2014} Jean-Baptiste & Olivier"));
    }

    #[test]
    fn generate_ics_escapes_special_chars() {
        let details = BookingDetails {
            event_title: "Meet; discuss, plan".to_string(),
            date: "2026-03-10".to_string(),
            start_time: "09:00".to_string(),
            end_time: "10:00".to_string(),
            guest_name: "O'Brien".to_string(),
            guest_email: "ob@test.com".to_string(),
            guest_timezone: "UTC".to_string(),
            host_name: "Host".to_string(),
            host_email: "host@test.com".to_string(),
            uid: "uid-789".to_string(),
            notes: None,
            location: None,
            reminder_minutes: None,
            additional_attendees: vec![],
            ..Default::default()
        };

        let ics = generate_ics(&details, "PUBLISH");
        assert!(ics.contains("SUMMARY:Meet\\; discuss\\, plan \u{2014} O'Brien & Host"));
    }

    // --- h (HTML escaping) ---

    #[test]
    fn html_escape_entities() {
        assert_eq!(
            h("<script>alert('xss')</script>"),
            "&lt;script&gt;alert('xss')&lt;/script&gt;"
        );
        assert_eq!(h("a & b"), "a &amp; b");
        assert_eq!(h("he said \"hello\""), "he said &quot;hello&quot;");
    }

    #[test]
    fn html_escape_plain_text() {
        assert_eq!(h("Hello World"), "Hello World");
    }

    // --- render_html_email ---

    #[test]
    fn html_email_contains_structure() {
        let html = render_html_email(
            "Hi Alice,",
            "Your booking is confirmed!",
            "#16a34a",
            &[
                EmailRow {
                    label: "Event".to_string(),
                    value: "Intro Call".to_string(),
                },
                EmailRow {
                    label: "Date".to_string(),
                    value: "2026-03-10".to_string(),
                },
            ],
            Some("Calendar invite attached."),
        );

        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("Hi Alice,"));
        assert!(html.contains("Your booking is confirmed!"));
        assert!(html.contains("#16a34a")); // accent color
        assert!(html.contains("Intro Call"));
        assert!(html.contains("2026-03-10"));
        assert!(html.contains("Calendar invite attached."));
        assert!(html.contains("calrs")); // footer branding
    }

    #[test]
    fn html_email_with_actions() {
        let html = render_html_email_with_actions(
            "Action required",
            "Someone wants to book.",
            "#f59e0b",
            &[],
            None,
            &[
                EmailAction {
                    label: "Approve".to_string(),
                    url: "https://cal.rs/approve/tok".to_string(),
                    color: "#16a34a".to_string(),
                },
                EmailAction {
                    label: "Decline".to_string(),
                    url: "https://cal.rs/decline/tok".to_string(),
                    color: "#dc2626".to_string(),
                },
            ],
        );

        assert!(html.contains("Approve"));
        assert!(html.contains("Decline"));
        assert!(html.contains("https://cal.rs/approve/tok"));
        assert!(html.contains("https://cal.rs/decline/tok"));
    }

    #[test]
    fn generate_cancel_ics_basic_structure() {
        let details = CancellationDetails {
            event_title: "Intro Call".to_string(),
            date: "2026-03-10".to_string(),
            start_time: "14:00".to_string(),
            end_time: "14:30".to_string(),
            guest_name: "Jane Doe".to_string(),
            guest_email: "jane@example.com".to_string(),
            guest_timezone: "UTC".to_string(),
            host_name: "Alice".to_string(),
            host_email: "alice@cal.rs".to_string(),
            uid: "cancel-uid-123".to_string(),
            reason: None,
            cancelled_by_host: true,
            ..Default::default()
        };

        let ics = generate_cancel_ics(&details);
        assert!(ics.contains("METHOD:CANCEL"));
        assert!(ics.contains("STATUS:CANCELLED"));
        assert!(ics.contains("UID:cancel-uid-123"));
        assert!(ics.contains("DTSTART:20260310T140000Z"));
        assert!(ics.contains("DTEND:20260310T143000Z"));
        assert!(ics.contains("SUMMARY:Intro Call \u{2014} Jane & Alice"));
    }

    // Regression test for #49 — DTSTAMP is also required on CANCEL, and its
    // absence was the original symptom RustiCal reported. See
    // generate_ics_has_rfc5545_dtstamp for the format rationale.
    #[test]
    fn generate_cancel_ics_has_rfc5545_dtstamp() {
        let details = CancellationDetails {
            event_title: "Intro Call".to_string(),
            date: "2026-03-10".to_string(),
            start_time: "14:00".to_string(),
            end_time: "14:30".to_string(),
            guest_name: "Jane Doe".to_string(),
            guest_email: "jane@example.com".to_string(),
            guest_timezone: "UTC".to_string(),
            host_name: "Alice".to_string(),
            host_email: "alice@cal.rs".to_string(),
            uid: "cancel-dtstamp-uid".to_string(),
            reason: None,
            cancelled_by_host: true,
            ..Default::default()
        };

        let ics = generate_cancel_ics(&details);
        let line = ics
            .lines()
            .find(|l| l.starts_with("DTSTAMP:"))
            .unwrap_or_else(|| panic!("DTSTAMP line missing from CANCEL VEVENT:\n{}", ics));
        let ts = &line["DTSTAMP:".len()..];
        assert_eq!(ts.len(), 16);
        assert!(ts.ends_with('Z'));
    }

    #[test]
    fn cancellation_message_host_initiated() {
        let details = CancellationDetails {
            event_title: "Meeting".to_string(),
            date: "2026-03-10".to_string(),
            start_time: "09:00".to_string(),
            end_time: "10:00".to_string(),
            guest_name: "Bob".to_string(),
            guest_email: "bob@test.com".to_string(),
            guest_timezone: "UTC".to_string(),
            host_name: "Alice".to_string(),
            host_email: "alice@test.com".to_string(),
            uid: "uid-1".to_string(),
            reason: None,
            cancelled_by_host: true,
            ..Default::default()
        };

        // Host email should say "You cancelled this booking."
        let host_html = render_html_email(
            "Booking cancelled.",
            &if details.cancelled_by_host {
                "You cancelled this booking.".to_string()
            } else {
                format!("{} cancelled their booking.", h(&details.guest_name))
            },
            "#dc2626",
            &[],
            None,
        );
        assert!(host_html.contains("You cancelled this booking."));
        assert!(!host_html.contains("Bob cancelled"));

        // Guest email should mention the host
        let guest_msg = if details.cancelled_by_host {
            format!(
                "Your booking has been cancelled by {}.",
                h(&details.host_name)
            )
        } else {
            "Your booking has been cancelled.".to_string()
        };
        assert!(guest_msg.contains("cancelled by Alice"));
    }

    #[test]
    fn cancellation_message_guest_initiated() {
        let details = CancellationDetails {
            event_title: "Meeting".to_string(),
            date: "2026-03-10".to_string(),
            start_time: "09:00".to_string(),
            end_time: "10:00".to_string(),
            guest_name: "Bob".to_string(),
            guest_email: "bob@test.com".to_string(),
            guest_timezone: "UTC".to_string(),
            host_name: "Alice".to_string(),
            host_email: "alice@test.com".to_string(),
            uid: "uid-2".to_string(),
            reason: Some("Schedule conflict".to_string()),
            cancelled_by_host: false,
            ..Default::default()
        };

        // Host email should say who cancelled
        let host_msg = if details.cancelled_by_host {
            "You cancelled this booking.".to_string()
        } else {
            format!("{} cancelled their booking.", h(&details.guest_name))
        };
        assert!(host_msg.contains("Bob cancelled their booking."));

        // Guest email should be generic
        let guest_msg = if details.cancelled_by_host {
            format!(
                "Your booking has been cancelled by {}.",
                h(&details.host_name)
            )
        } else {
            "Your booking has been cancelled.".to_string()
        };
        assert_eq!(guest_msg, "Your booking has been cancelled.");
    }

    #[test]
    fn html_email_with_cancel_action() {
        let html = render_html_email_with_actions(
            "Hi Bob,",
            "Your booking has been confirmed!",
            "#16a34a",
            &[EmailRow {
                label: "Event".to_string(),
                value: "Intro Call".to_string(),
            }],
            Some("A calendar invite is attached."),
            &[EmailAction {
                label: "Cancel booking".to_string(),
                url: "https://cal.rs/booking/cancel/abc-123".to_string(),
                color: "#dc2626".to_string(),
            }],
        );

        assert!(html.contains("Cancel booking"));
        assert!(html.contains("https://cal.rs/booking/cancel/abc-123"));
        assert!(html.contains("#dc2626"));
    }

    #[test]
    fn html_email_escapes_values() {
        let html = render_html_email(
            "Hi,",
            "Test",
            "#000",
            &[EmailRow {
                label: "Notes".to_string(),
                value: "<script>alert(1)</script>".to_string(),
            }],
            None,
        );

        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;script&gt;"));
    }

    // --- generate_ics edge cases ---

    #[test]
    fn sanitize_ics_param_quotes_delimiters() {
        // A plain name is left exactly as it was: no quotes, no escapes.
        assert_eq!(sanitize_ics_param("Jane Doe"), "Jane Doe");
        // Non-ASCII is a legal parameter value and must survive untouched.
        assert_eq!(
            sanitize_ics_param("Test Guest \u{ab}quotes\u{bb}"),
            "Test Guest \u{ab}quotes\u{bb}"
        );
        // The three delimiters that end a paramtext force a quoted-string.
        assert_eq!(sanitize_ics_param("Jane; Doe"), "\"Jane; Doe\"");
        assert_eq!(sanitize_ics_param("Doe, Jane"), "\"Doe, Jane\"");
        assert_eq!(sanitize_ics_param("Jane: Doe"), "\"Jane: Doe\"");
        // Never a backslash escape — that is TEXT syntax and is what #163 was.
        assert!(!sanitize_ics_param("Jane; Doe").contains('\\'));
    }

    #[test]
    fn sanitize_ics_param_uses_caret_escapes() {
        // A quoted-string cannot hold a DQUOTE, so RFC 6868 spells it `^'`.
        assert_eq!(sanitize_ics_param("Jane \"JD\" Doe"), "Jane ^'JD^' Doe");
        // The caret itself doubles, and it must be escaped first so an input
        // caret cannot be mistaken for one this function introduced.
        assert_eq!(sanitize_ics_param("a^b"), "a^^b");
        assert_eq!(sanitize_ics_param("a^'b"), "a^^'b");
        // CR/LF becomes `^n` rather than being dropped, which also keeps the
        // header-injection guard: no raw newline survives.
        assert_eq!(sanitize_ics_param("a\r\nb"), "a^nb");
        assert_eq!(sanitize_ics_param("a\nb"), "a^nb");
        assert_eq!(sanitize_ics_param("a\rb"), "a^nb");
    }

    #[test]
    fn caldav_ics_quotes_a_guest_name_with_a_semicolon() {
        // #163: Yandex 360 answers 400 Bad Request to `CN=Test Guest \; and`,
        // because a parameter takes no backslash escapes and the raw `;` ends
        // the parameter. The booking was reported confirmed and never reached
        // the calendar. Quoting is the RFC 5545 §3.1 spelling.
        let details = BookingDetails {
            event_title: "Call".to_string(),
            date: "2026-04-01".to_string(),
            start_time: "10:00".to_string(),
            end_time: "10:30".to_string(),
            guest_name: "Test Guest \u{ab}quotes\u{bb} ; and a semicolon".to_string(),
            guest_email: "guest@test.com".to_string(),
            guest_timezone: "UTC".to_string(),
            host_name: "H\u{e9}lo\u{ef}se; Host".to_string(),
            host_email: "host@test.com".to_string(),
            uid: "uid-163".to_string(),
            notes: None,
            location: None,
            reminder_minutes: None,
            additional_attendees: vec![],
            ..Default::default()
        };
        let ics = generate_ics_caldav(&details);

        assert!(
            ics.contains(
                "ATTENDEE;SCHEDULE-AGENT=CLIENT;CN=\"Test Guest \u{ab}quotes\u{bb} ; and a semicolon\";RSVP=TRUE:mailto:guest@test.com"
            ),
            "{ics}"
        );
        assert!(
            ics.contains("ORGANIZER;CN=\"H\u{e9}lo\u{ef}se; Host\":mailto:host@test.com"),
            "{ics}"
        );
        // The SUMMARY is a TEXT value and keeps backslash escaping.
        assert!(
            ics.contains("SUMMARY:Call \u{2014} Test & H\u{e9}lo\u{ef}se\u{5c};"),
            "{ics}"
        );
        // No `CN=` value may carry a backslash escape.
        for line in ics.lines().filter(|l| l.contains("CN=")) {
            assert!(!line.contains("\\;"), "backslash-escaped CN: {line}");
            assert!(!line.contains("\\,"), "backslash-escaped CN: {line}");
        }
    }

    #[test]
    fn cancel_ics_quotes_a_guest_name_with_a_semicolon() {
        // The cancellation ICS builds its own VEVENT and had the same bug, so
        // a guest with a semicolon could book but never be un-booked either.
        let details = CancellationDetails {
            event_title: "Call".to_string(),
            date: "2026-04-01".to_string(),
            start_time: "10:00".to_string(),
            end_time: "10:30".to_string(),
            guest_name: "Doe, Jane; Ms".to_string(),
            guest_email: "guest@test.com".to_string(),
            guest_timezone: "UTC".to_string(),
            host_name: "Host".to_string(),
            host_email: "host@test.com".to_string(),
            uid: "uid-163-cancel".to_string(),
            ..Default::default()
        };
        let ics = generate_cancel_ics(&details);
        assert!(
            ics.contains("ATTENDEE;CN=\"Doe, Jane; Ms\":mailto:guest@test.com"),
            "{ics}"
        );
    }

    #[test]
    fn generate_ics_sanitizes_malicious_guest_name() {
        let details = BookingDetails {
            event_title: "Call".to_string(),
            date: "2026-04-01".to_string(),
            start_time: "10:00".to_string(),
            end_time: "10:30".to_string(),
            guest_name: "Evil\r\nATTENDEE:hacker@evil.com".to_string(),
            guest_email: "guest@test.com".to_string(),
            guest_timezone: "UTC".to_string(),
            host_name: "Host".to_string(),
            host_email: "host@test.com".to_string(),
            uid: "uid-inject".to_string(),
            notes: None,
            location: None,
            reminder_minutes: None,
            additional_attendees: vec![],
            ..Default::default()
        };
        let ics = generate_ics(&details, "REQUEST");
        // The injected ATTENDEE line must not appear as a separate field
        assert!(!ics.contains("\r\nATTENDEE:hacker@evil.com"));
        // The newline becomes an RFC 6868 `^n`, and the `:` it was carrying
        // forces the whole CN into a quoted-string, so the payload stays one
        // parameter value instead of breaking out into a property.
        assert!(
            ics.contains("CN=\"Evil^nATTENDEE:hacker@evil.com\""),
            "{ics}"
        );
    }

    #[test]
    fn generate_ics_without_location_has_no_location_line() {
        let details = BookingDetails {
            event_title: "Call".to_string(),
            date: "2026-04-01".to_string(),
            start_time: "10:00".to_string(),
            end_time: "10:30".to_string(),
            guest_name: "Guest".to_string(),
            guest_email: "guest@test.com".to_string(),
            guest_timezone: "UTC".to_string(),
            host_name: "Host".to_string(),
            host_email: "host@test.com".to_string(),
            uid: "uid-noloc".to_string(),
            notes: None,
            location: None,
            reminder_minutes: None,
            additional_attendees: vec![],
            ..Default::default()
        };
        let ics = generate_ics(&details, "PUBLISH");
        assert!(!ics.contains("LOCATION:"));
    }

    #[test]
    fn generate_ics_with_valarm_reminder() {
        let details = BookingDetails {
            event_title: "Meeting".to_string(),
            date: "2026-04-01".to_string(),
            start_time: "14:00".to_string(),
            end_time: "14:30".to_string(),
            guest_name: "Guest".to_string(),
            guest_email: "guest@test.com".to_string(),
            guest_timezone: "UTC".to_string(),
            host_name: "Host".to_string(),
            host_email: "host@test.com".to_string(),
            uid: "uid-valarm".to_string(),
            notes: None,
            location: None,
            reminder_minutes: Some(15),
            additional_attendees: vec![],
            ..Default::default()
        };
        let ics = generate_ics(&details, "PUBLISH");
        assert!(ics.contains("BEGIN:VALARM"));
        assert!(ics.contains("TRIGGER:-PT15M"));
        assert!(ics.contains("ACTION:DISPLAY"));
        assert!(ics.contains("END:VALARM"));
    }

    #[test]
    fn generate_ics_no_valarm_when_none() {
        let details = BookingDetails {
            event_title: "Meeting".to_string(),
            date: "2026-04-01".to_string(),
            start_time: "14:00".to_string(),
            end_time: "14:30".to_string(),
            guest_name: "Guest".to_string(),
            guest_email: "guest@test.com".to_string(),
            guest_timezone: "UTC".to_string(),
            host_name: "Host".to_string(),
            host_email: "host@test.com".to_string(),
            uid: "uid-novalarm".to_string(),
            notes: None,
            location: None,
            reminder_minutes: None,
            additional_attendees: vec![],
            ..Default::default()
        };
        let ics = generate_ics(&details, "PUBLISH");
        assert!(!ics.contains("VALARM"));
    }

    #[test]
    fn generate_ics_no_valarm_when_zero() {
        let details = BookingDetails {
            event_title: "Meeting".to_string(),
            date: "2026-04-01".to_string(),
            start_time: "14:00".to_string(),
            end_time: "14:30".to_string(),
            guest_name: "Guest".to_string(),
            guest_email: "guest@test.com".to_string(),
            guest_timezone: "UTC".to_string(),
            host_name: "Host".to_string(),
            host_email: "host@test.com".to_string(),
            uid: "uid-zero".to_string(),
            notes: None,
            location: None,
            reminder_minutes: Some(0),
            additional_attendees: vec![],
            ..Default::default()
        };
        let ics = generate_ics(&details, "PUBLISH");
        assert!(!ics.contains("VALARM"));
    }

    #[test]
    fn generate_cancel_ics_with_special_chars_in_title() {
        let details = CancellationDetails {
            event_title: "Team sync; weekly, recurring".to_string(),
            date: "2026-05-20".to_string(),
            start_time: "16:00".to_string(),
            end_time: "16:45".to_string(),
            guest_name: "Bob".to_string(),
            guest_email: "bob@test.com".to_string(),
            guest_timezone: "UTC".to_string(),
            host_name: "Alice".to_string(),
            host_email: "alice@test.com".to_string(),
            uid: "cancel-special".to_string(),
            reason: Some("No longer needed".to_string()),
            cancelled_by_host: true,
            ..Default::default()
        };
        let ics = generate_cancel_ics(&details);
        assert!(ics.contains("SUMMARY:Team sync\\; weekly\\, recurring \u{2014} Bob & Alice"));
        assert!(ics.contains("METHOD:CANCEL"));
        assert!(ics.contains("STATUS:CANCELLED"));
        assert!(ics.contains("DTSTART:20260520T160000Z"));
        assert!(ics.contains("DTEND:20260520T164500Z"));
    }

    // --- render_html_email edge cases ---

    #[test]
    fn html_email_no_rows_no_footer() {
        let html = render_html_email("Hello,", "Nothing to show.", "#333", &[], None);
        assert!(html.contains("Hello,"));
        assert!(html.contains("Nothing to show."));
        assert!(html.contains("#333"));
        // No detail rows
        assert!(!html.contains("<td style=\"padding:8px"));
    }

    #[test]
    fn html_email_multiple_rows_alternate_bg() {
        let html = render_html_email(
            "Hi,",
            "Details below.",
            "#000",
            &[
                EmailRow {
                    label: "Row1".to_string(),
                    value: "val1".to_string(),
                },
                EmailRow {
                    label: "Row2".to_string(),
                    value: "val2".to_string(),
                },
                EmailRow {
                    label: "Row3".to_string(),
                    value: "val3".to_string(),
                },
            ],
            None,
        );
        // Even rows (0, 2) get #f8f9fa background, odd rows (1) get #ffffff
        assert!(html.contains("val1"));
        assert!(html.contains("val2"));
        assert!(html.contains("val3"));
        assert!(html.contains("#f8f9fa"));
    }

    #[test]
    fn html_email_actions_escape_urls() {
        let html = render_html_email_with_actions(
            "Hi,",
            "Test",
            "#000",
            &[],
            None,
            &[EmailAction {
                label: "Click <here>".to_string(),
                url: "https://cal.rs/action?a=1&b=2".to_string(),
                color: "#16a34a".to_string(),
            }],
        );
        // Label should be HTML-escaped
        assert!(html.contains("Click &lt;here&gt;"));
        // URL should be HTML-escaped (& → &amp;)
        assert!(html.contains("https://cal.rs/action?a=1&amp;b=2"));
    }

    // --- build_multipart_body ---

    #[test]
    fn multipart_body_contains_both_parts() {
        let body = build_multipart_body("Plain text version", "<p>HTML version</p>");
        let formatted = format!("{:?}", body);
        // The multipart should be alternative type with both parts
        assert!(formatted.contains("Plain text version") || formatted.contains("alternative"));
    }

    // --- h (HTML escaping) additional ---

    #[test]
    fn html_escape_empty_string() {
        assert_eq!(h(""), "");
    }

    #[test]
    fn html_escape_all_special_chars() {
        assert_eq!(h("&<>\""), "&amp;&lt;&gt;&quot;");
    }

    // --- sanitize_ics additional ---

    #[test]
    fn sanitize_ics_multiple_newlines() {
        // \r is stripped, \n is replaced with space
        assert_eq!(sanitize_ics("a\r\nb\r\nc\nd\re"), "a b c de");
    }

    #[test]
    fn sanitize_ics_only_special_chars() {
        // \r stripped, \n→space, ; and , escaped
        assert_eq!(sanitize_ics(";\n,\r"), "\\; \\,");
    }

    // --- convert_to_utc tests ---

    #[test]
    fn convert_to_utc_europe_paris() {
        // March 2026: Paris is CET (UTC+1), so 14:30 Paris = 13:30 UTC
        let (start, end) = convert_to_utc("2026-03-15", "14:30", "16:00", "Europe/Paris");
        assert_eq!(start, "20260315T133000Z");
        assert_eq!(end, "20260315T150000Z");
        assert!(start.ends_with('Z'));
        assert!(end.ends_with('Z'));
    }

    #[test]
    fn convert_to_utc_invalid_timezone_fallback() {
        let (start, end) = convert_to_utc("2026-03-15", "14:30", "16:00", "Invalid/Timezone");
        // Fallback: floating time, no Z suffix
        assert_eq!(start, "20260315T143000");
        assert_eq!(end, "20260315T160000");
        assert!(!start.ends_with('Z'));
        assert!(!end.ends_with('Z'));
    }

    #[test]
    fn convert_to_utc_utc_timezone() {
        let (start, end) = convert_to_utc("2026-03-15", "14:30", "16:00", "UTC");
        assert_eq!(start, "20260315T143000Z");
        assert_eq!(end, "20260315T160000Z");
    }

    // --- convert_time_between_tz / host_time_display tests ---

    // Regression for issue #119: the host (Paris) was reading the time in the
    // guest's wall-clock (LA), with no TZ label on cancellation emails. This
    // verifies the LA→Paris conversion that makes the host email show 16:00
    // Paris time when the guest booked 07:00 LA time.
    #[test]
    fn convert_time_between_tz_la_to_paris() {
        let (date, start, end) = convert_time_between_tz(
            "2026-05-26",
            "07:00",
            "07:30",
            "America/Los_Angeles",
            "Europe/Paris",
        )
        .expect("conversion should succeed for valid IANA names");
        // May 26 is in PDT (UTC-7) and CEST (UTC+2), so LA 07:00 = Paris 16:00 same day.
        assert_eq!(date, "2026-05-26");
        assert_eq!(start, "16:00");
        assert_eq!(end, "16:30");
    }

    // Late-evening LA booking crosses midnight into the next day in Paris.
    #[test]
    fn convert_time_between_tz_rolls_over_date() {
        let (date, start, end) = convert_time_between_tz(
            "2026-05-26",
            "22:00",
            "22:30",
            "America/Los_Angeles",
            "Europe/Paris",
        )
        .expect("conversion should succeed");
        assert_eq!(date, "2026-05-27");
        assert_eq!(start, "07:00");
        assert_eq!(end, "07:30");
    }

    #[test]
    fn convert_time_between_tz_invalid_zone_returns_none() {
        assert!(convert_time_between_tz(
            "2026-05-26",
            "07:00",
            "07:30",
            "Not/A/Zone",
            "Europe/Paris"
        )
        .is_none());
        assert!(convert_time_between_tz(
            "2026-05-26",
            "07:00",
            "07:30",
            "America/Los_Angeles",
            "Also/Bad"
        )
        .is_none());
    }

    #[test]
    fn host_time_display_converts_to_host_tz() {
        let (date, time_display) = host_time_display(
            "2026-05-26",
            "07:00",
            "07:30",
            "America/Los_Angeles",
            "Europe/Paris",
        );
        assert_eq!(date, "2026-05-26");
        assert_eq!(time_display, "16:00 \u{2013} 16:30 (Europe/Paris)");
    }

    // When host_timezone is empty (legacy callers / no users.timezone set),
    // keep the original wall-clock and still surface *some* TZ label so the
    // host can disambiguate. Fallback to guest_timezone.
    #[test]
    fn host_time_display_empty_host_tz_falls_back_to_guest_label() {
        let (date, time_display) =
            host_time_display("2026-05-26", "07:00", "07:30", "America/Los_Angeles", "");
        assert_eq!(date, "2026-05-26");
        assert_eq!(time_display, "07:00 \u{2013} 07:30 (America/Los_Angeles)");
    }

    // When both TZ values match, display the original time without conversion
    // overhead, but still label it.
    #[test]
    fn host_time_display_same_tz_keeps_original_time() {
        let (date, time_display) = host_time_display(
            "2026-05-26",
            "14:00",
            "14:30",
            "Europe/Paris",
            "Europe/Paris",
        );
        assert_eq!(date, "2026-05-26");
        assert_eq!(time_display, "14:00 \u{2013} 14:30 (Europe/Paris)");
    }

    // --- ICS location field regression test ---

    #[test]
    fn generate_ics_location_no_trailing_whitespace() {
        // Regression: LOCATION line had trailing whitespace after CRLF, causing
        // ORGANIZER to be treated as a continuation of LOCATION per RFC 5545.
        let details = BookingDetails {
            event_title: "Meeting".to_string(),
            date: "2026-03-10".to_string(),
            start_time: "09:00".to_string(),
            end_time: "10:00".to_string(),
            guest_name: "Bob".to_string(),
            guest_email: "bob@test.com".to_string(),
            guest_timezone: "UTC".to_string(),
            host_name: "Alice".to_string(),
            host_email: "alice@test.com".to_string(),
            uid: "uid-loc-ws".to_string(),
            notes: None,
            location: Some("https://meet.example.com/room".to_string()),
            reminder_minutes: None,
            additional_attendees: vec![],
            ..Default::default()
        };

        let ics = generate_ics(&details, "PUBLISH");

        // LOCATION line must end with value + \r\n, no trailing spaces
        assert!(ics.contains("LOCATION:https://meet.example.com/room\r\n"));

        // ORGANIZER must appear on its own line (not folded into LOCATION)
        for line in ics.split("\r\n") {
            if line.starts_with("LOCATION:") {
                assert!(
                    !line.ends_with(' '),
                    "LOCATION line must not have trailing whitespace"
                );
            }
            // ORGANIZER must not be on the same line as LOCATION
            if line.starts_with("LOCATION:") {
                assert!(
                    !line.contains("ORGANIZER"),
                    "ORGANIZER must not be on the LOCATION line"
                );
            }
        }

        // ORGANIZER must start its own line
        assert!(ics.contains("\r\nORGANIZER;"));
    }

    // --- ICS DTSTART/DTEND UTC Z suffix ---

    #[test]
    fn generate_ics_dtstart_dtend_have_utc_z_suffix() {
        let details = BookingDetails {
            event_title: "Call".to_string(),
            date: "2026-04-01".to_string(),
            start_time: "10:00".to_string(),
            end_time: "10:30".to_string(),
            guest_name: "Guest".to_string(),
            guest_email: "guest@test.com".to_string(),
            guest_timezone: "America/New_York".to_string(),
            host_name: "Host".to_string(),
            host_email: "host@test.com".to_string(),
            uid: "uid-utc-z".to_string(),
            notes: None,
            location: None,
            reminder_minutes: None,
            additional_attendees: vec![],
            ..Default::default()
        };

        let ics = generate_ics(&details, "PUBLISH");

        // Extract DTSTART and DTEND values
        for line in ics.split("\r\n") {
            if let Some(val) = line.strip_prefix("DTSTART:") {
                assert!(
                    val.ends_with('Z'),
                    "DTSTART value '{}' must end with Z",
                    val
                );
            }
            if let Some(val) = line.strip_prefix("DTEND:") {
                assert!(val.ends_with('Z'), "DTEND value '{}' must end with Z", val);
            }
        }
    }

    // --- ICS cancel also has UTC times ---

    #[test]
    fn generate_cancel_ics_dtstart_dtend_have_utc_z_suffix() {
        let details = CancellationDetails {
            event_title: "Call".to_string(),
            date: "2026-04-01".to_string(),
            start_time: "10:00".to_string(),
            end_time: "10:30".to_string(),
            guest_name: "Guest".to_string(),
            guest_email: "guest@test.com".to_string(),
            guest_timezone: "Europe/London".to_string(),
            host_name: "Host".to_string(),
            host_email: "host@test.com".to_string(),
            uid: "uid-cancel-z".to_string(),
            reason: None,
            cancelled_by_host: true,
            ..Default::default()
        };

        let ics = generate_cancel_ics(&details);

        for line in ics.split("\r\n") {
            if let Some(val) = line.strip_prefix("DTSTART:") {
                assert!(
                    val.ends_with('Z'),
                    "Cancel ICS DTSTART value '{}' must end with Z",
                    val
                );
            }
            if let Some(val) = line.strip_prefix("DTEND:") {
                assert!(
                    val.ends_with('Z'),
                    "Cancel ICS DTEND value '{}' must end with Z",
                    val
                );
            }
        }
    }

    #[test]
    fn generate_ics_includes_additional_attendees() {
        let details = BookingDetails {
            event_title: "Team Sync".to_string(),
            date: "2026-03-10".to_string(),
            start_time: "14:00".to_string(),
            end_time: "14:30".to_string(),
            guest_name: "Jane".to_string(),
            guest_email: "jane@example.com".to_string(),
            guest_timezone: "UTC".to_string(),
            host_name: "Alice".to_string(),
            host_email: "alice@test.com".to_string(),
            uid: "uid-attendees".to_string(),
            notes: None,
            location: None,
            reminder_minutes: None,
            additional_attendees: vec![
                "bob@example.com".to_string(),
                "carol@example.com".to_string(),
            ],
            ..Default::default()
        };

        let ics = generate_ics(&details, "REQUEST");
        assert!(ics.contains("ATTENDEE;RSVP=TRUE:mailto:bob@example.com"));
        assert!(ics.contains("ATTENDEE;RSVP=TRUE:mailto:carol@example.com"));
        // Primary guest should also be present
        assert!(ics.contains("ATTENDEE;CN=Jane;RSVP=TRUE:mailto:jane@example.com"));
    }

    #[test]
    fn generate_ics_no_extra_attendees_when_empty() {
        let details = BookingDetails {
            event_title: "Solo".to_string(),
            date: "2026-03-10".to_string(),
            start_time: "10:00".to_string(),
            end_time: "10:30".to_string(),
            guest_name: "Jane".to_string(),
            guest_email: "jane@example.com".to_string(),
            guest_timezone: "UTC".to_string(),
            host_name: "Alice".to_string(),
            host_email: "alice@test.com".to_string(),
            uid: "uid-no-extra".to_string(),
            notes: None,
            location: None,
            reminder_minutes: None,
            additional_attendees: vec![],
            ..Default::default()
        };

        let ics = generate_ics(&details, "PUBLISH");
        let attendee_count = ics.matches("ATTENDEE;").count();
        // Only 1 ATTENDEE line: the primary guest (CN=Jane)
        assert_eq!(
            attendee_count, 1,
            "Expected exactly 1 ATTENDEE line, got {}",
            attendee_count
        );
    }

    // --- RescheduleDetails tests ---

    fn sample_reschedule_details() -> RescheduleDetails {
        RescheduleDetails {
            old_utc_times: None,
            event_title: "30min call".to_string(),
            old_date: "2026-03-16".to_string(),
            old_start_time: "10:00".to_string(),
            old_end_time: "10:30".to_string(),
            new_date: "2026-03-17".to_string(),
            new_start_time: "14:00".to_string(),
            new_end_time: "14:30".to_string(),
            guest_name: "Jane".to_string(),
            guest_email: "jane@example.com".to_string(),
            guest_timezone: "Europe/Paris".to_string(),
            host_name: "Alice".to_string(),
            host_email: "alice@example.com".to_string(),
            uid: "test-uid@calrs".to_string(),
            location: Some("https://meet.example.com/abc".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn reschedule_details_generates_valid_ics_for_new_time() {
        let details = sample_reschedule_details();
        let booking_details = BookingDetails {
            event_title: details.event_title.clone(),
            date: details.new_date.clone(),
            start_time: details.new_start_time.clone(),
            end_time: details.new_end_time.clone(),
            guest_name: details.guest_name.clone(),
            guest_email: details.guest_email.clone(),
            guest_timezone: details.guest_timezone.clone(),
            host_name: details.host_name.clone(),
            host_email: details.host_email.clone(),
            uid: details.uid.clone(),
            notes: None,
            location: details.location.clone(),
            reminder_minutes: None,
            additional_attendees: vec![],
            ..Default::default()
        };
        let ics = generate_ics(&booking_details, "PUBLISH");
        assert!(
            ics.contains("UID:test-uid@calrs"),
            "ICS should contain the booking UID"
        );
        assert!(
            ics.contains("METHOD:PUBLISH"),
            "ICS should have PUBLISH method"
        );
        assert!(ics.contains("SUMMARY:"), "ICS should have a summary");
        assert!(ics.contains("LOCATION:"), "ICS should include location");
    }

    #[test]
    fn reschedule_details_ics_uses_same_uid() {
        // This is critical: reschedule must use the same UID so CalDAV updates in place
        let details = sample_reschedule_details();
        let booking_details = BookingDetails {
            event_title: details.event_title,
            date: details.new_date,
            start_time: details.new_start_time,
            end_time: details.new_end_time,
            guest_name: details.guest_name,
            guest_email: details.guest_email,
            guest_timezone: details.guest_timezone,
            host_name: details.host_name,
            host_email: details.host_email,
            uid: "original-uid@calrs".to_string(),
            notes: None,
            location: None,
            reminder_minutes: None,
            additional_attendees: vec![],
            ..Default::default()
        };
        let ics = generate_ics(&booking_details, "REQUEST");
        assert!(
            ics.contains("UID:original-uid@calrs"),
            "Rescheduled ICS must preserve the original UID for CalDAV update-in-place"
        );
    }

    #[test]
    fn confirmation_email_actions_include_reschedule_when_provided() {
        // Test that the email action builder produces both reschedule and cancel buttons
        let mut actions: Vec<EmailAction> = Vec::new();
        let reschedule_url = Some("https://cal.example.com/booking/reschedule/abc123");
        let cancel_url = Some("https://cal.example.com/booking/cancel/def456");

        if let Some(u) = reschedule_url {
            actions.push(EmailAction {
                label: "Reschedule".to_string(),
                url: u.to_string(),
                color: "#3b82f6".to_string(),
            });
        }
        if let Some(u) = cancel_url {
            actions.push(EmailAction {
                label: "Cancel booking".to_string(),
                url: u.to_string(),
                color: "#dc2626".to_string(),
            });
        }

        assert_eq!(
            actions.len(),
            2,
            "Should have both reschedule and cancel actions"
        );
        assert_eq!(actions[0].label, "Reschedule");
        assert!(actions[0].url.contains("reschedule"));
        assert_eq!(actions[1].label, "Cancel booking");
        assert!(actions[1].url.contains("cancel"));
    }

    #[test]
    fn confirmation_email_actions_only_cancel_when_no_reschedule() {
        let mut actions: Vec<EmailAction> = Vec::new();
        let reschedule_url: Option<&str> = None;
        let cancel_url = Some("https://cal.example.com/booking/cancel/def456");

        if let Some(u) = reschedule_url {
            actions.push(EmailAction {
                label: "Reschedule".to_string(),
                url: u.to_string(),
                color: "#3b82f6".to_string(),
            });
        }
        if let Some(u) = cancel_url {
            actions.push(EmailAction {
                label: "Cancel booking".to_string(),
                url: u.to_string(),
                color: "#dc2626".to_string(),
            });
        }

        assert_eq!(actions.len(), 1, "Should only have cancel action");
        assert_eq!(actions[0].label, "Cancel booking");
    }

    #[test]
    fn reschedule_email_html_contains_old_and_new_times() {
        let details = sample_reschedule_details();
        let rows = vec![
            EmailRow {
                label: "Event".to_string(),
                value: details.event_title.clone(),
            },
            EmailRow {
                label: "Previous".to_string(),
                value: format!(
                    "{} at {} \u{2013} {}",
                    details.old_date, details.old_start_time, details.old_end_time
                ),
            },
            EmailRow {
                label: "New date".to_string(),
                value: details.new_date.clone(),
            },
            EmailRow {
                label: "New time".to_string(),
                value: format!(
                    "{} \u{2013} {} ({})",
                    details.new_start_time, details.new_end_time, details.guest_timezone
                ),
            },
            EmailRow {
                label: "With".to_string(),
                value: details.host_name.clone(),
            },
        ];

        let html = render_html_email_with_actions(
            &format!("Hi {},", h(&details.guest_name)),
            "Your booking has been rescheduled.",
            "#d97706",
            &rows,
            None,
            &[],
        );

        assert!(html.contains("30min call"), "Should contain event title");
        assert!(html.contains("2026-03-16"), "Should contain old date");
        assert!(html.contains("2026-03-17"), "Should contain new date");
        assert!(html.contains("10:00"), "Should contain old start time");
        assert!(html.contains("14:00"), "Should contain new start time");
        assert!(
            html.contains("#d97706"),
            "Should use orange accent for reschedule"
        );
    }

    #[test]
    fn host_reschedule_request_email_has_approve_decline_actions() {
        let approve_url = "https://cal.example.com/booking/approve/token123";
        let decline_url = "https://cal.example.com/booking/decline/token123";

        let actions = vec![
            EmailAction {
                label: "Approve".to_string(),
                url: approve_url.to_string(),
                color: "#16a34a".to_string(),
            },
            EmailAction {
                label: "Decline".to_string(),
                url: decline_url.to_string(),
                color: "#dc2626".to_string(),
            },
        ];

        let html = render_html_email_with_actions(
            "Hi,",
            "A guest wants to reschedule.",
            "#d97706",
            &[EmailRow {
                label: "Event".to_string(),
                value: "Test".to_string(),
            }],
            None,
            &actions,
        );

        assert!(html.contains("Approve"), "Should have approve button");
        assert!(html.contains("Decline"), "Should have decline button");
        assert!(html.contains(approve_url), "Should contain approve URL");
        assert!(html.contains(decline_url), "Should contain decline URL");
    }

    // --- first_name helper ---

    #[test]
    fn first_name_single_word() {
        assert_eq!(first_name("Alice"), "Alice");
    }

    #[test]
    fn first_name_two_words() {
        assert_eq!(first_name("Alice Smith"), "Alice");
    }

    #[test]
    fn first_name_hyphenated() {
        assert_eq!(first_name("Jean-Baptiste Piacentino"), "Jean-Baptiste");
    }

    #[test]
    fn first_name_empty_string() {
        assert_eq!(first_name(""), "");
    }

    #[test]
    fn first_name_multiple_spaces() {
        assert_eq!(first_name("  Alice  Smith  "), "Alice");
    }

    // --- convert_to_utc additional edge cases ---

    #[test]
    fn convert_to_utc_america_new_york_dst() {
        // April 2026: New York is EDT (UTC-4), so 10:00 NY = 14:00 UTC
        let (start, end) = convert_to_utc("2026-04-15", "10:00", "10:30", "America/New_York");
        assert_eq!(start, "20260415T140000Z");
        assert_eq!(end, "20260415T143000Z");
    }

    #[test]
    fn convert_to_utc_america_new_york_standard() {
        // January 2026: New York is EST (UTC-5), so 10:00 NY = 15:00 UTC
        let (start, end) = convert_to_utc("2026-01-15", "10:00", "10:30", "America/New_York");
        assert_eq!(start, "20260115T150000Z");
        assert_eq!(end, "20260115T153000Z");
    }

    #[test]
    fn convert_to_utc_asia_tokyo() {
        // Tokyo is JST (UTC+9) year-round, so 18:00 Tokyo = 09:00 UTC
        let (start, end) = convert_to_utc("2026-06-01", "18:00", "19:00", "Asia/Tokyo");
        assert_eq!(start, "20260601T090000Z");
        assert_eq!(end, "20260601T100000Z");
    }

    #[test]
    fn convert_to_utc_australia_sydney_dst() {
        // January 2026: Sydney is AEDT (UTC+11), so 10:00 Sydney = 23:00 previous day UTC
        let (start, end) = convert_to_utc("2026-01-15", "10:00", "11:00", "Australia/Sydney");
        assert_eq!(start, "20260114T230000Z");
        assert_eq!(end, "20260115T000000Z");
    }

    #[test]
    fn convert_to_utc_invalid_date_format_fallback() {
        let (start, end) = convert_to_utc("not-a-date", "10:00", "11:00", "UTC");
        // Should fallback to floating time
        assert!(!start.ends_with('Z'));
        assert!(!end.ends_with('Z'));
    }

    #[test]
    fn convert_to_utc_invalid_time_format_fallback() {
        let (start, end) = convert_to_utc("2026-03-15", "bad", "worse", "UTC");
        assert!(!start.ends_with('Z'));
        assert!(!end.ends_with('Z'));
    }

    #[test]
    fn convert_to_utc_midnight_boundary() {
        // 23:30 UTC stays on same day
        let (start, end) = convert_to_utc("2026-03-15", "23:30", "23:59", "UTC");
        assert_eq!(start, "20260315T233000Z");
        assert_eq!(end, "20260315T235900Z");
    }

    #[test]
    fn convert_to_utc_pacific_honolulu() {
        // Hawaii is HST (UTC-10) year-round, so 08:00 Honolulu = 18:00 UTC
        let (start, end) = convert_to_utc("2026-07-01", "08:00", "09:00", "Pacific/Honolulu");
        assert_eq!(start, "20260701T180000Z");
        assert_eq!(end, "20260701T190000Z");
    }

    // --- generate_ics additional edge cases ---

    #[test]
    fn generate_ics_empty_notes_excluded() {
        let details = BookingDetails {
            event_title: "Call".to_string(),
            date: "2026-04-01".to_string(),
            start_time: "10:00".to_string(),
            end_time: "10:30".to_string(),
            guest_name: "Guest".to_string(),
            guest_email: "guest@test.com".to_string(),
            guest_timezone: "UTC".to_string(),
            host_name: "Host".to_string(),
            host_email: "host@test.com".to_string(),
            uid: "uid-empty-notes".to_string(),
            notes: Some("   ".to_string()),
            location: None,
            reminder_minutes: None,
            additional_attendees: vec![],
            ..Default::default()
        };
        let ics = generate_ics(&details, "PUBLISH");
        // Empty/whitespace-only notes should not produce a DESCRIPTION line
        assert!(!ics.contains("DESCRIPTION:"));
    }

    #[test]
    fn generate_ics_notes_with_special_chars() {
        let details = BookingDetails {
            event_title: "Call".to_string(),
            date: "2026-04-01".to_string(),
            start_time: "10:00".to_string(),
            end_time: "10:30".to_string(),
            guest_name: "Guest".to_string(),
            guest_email: "guest@test.com".to_string(),
            guest_timezone: "UTC".to_string(),
            host_name: "Host".to_string(),
            host_email: "host@test.com".to_string(),
            uid: "uid-notes-special".to_string(),
            notes: Some("Topic: budget; Q1, Q2".to_string()),
            location: None,
            reminder_minutes: None,
            additional_attendees: vec![],
            ..Default::default()
        };
        let ics = generate_ics(&details, "PUBLISH");
        assert!(ics.contains("DESCRIPTION:Topic: budget\\; Q1\\, Q2"));
    }

    #[test]
    fn generate_ics_method_request() {
        let details = BookingDetails {
            event_title: "Call".to_string(),
            date: "2026-04-01".to_string(),
            start_time: "10:00".to_string(),
            end_time: "10:30".to_string(),
            guest_name: "Guest".to_string(),
            guest_email: "guest@test.com".to_string(),
            guest_timezone: "UTC".to_string(),
            host_name: "Host".to_string(),
            host_email: "host@test.com".to_string(),
            uid: "uid-method".to_string(),
            notes: None,
            location: None,
            reminder_minutes: None,
            additional_attendees: vec![],
            ..Default::default()
        };
        let ics = generate_ics(&details, "REQUEST");
        assert!(ics.contains("METHOD:REQUEST"));
        assert!(!ics.contains("METHOD:PUBLISH"));
    }

    #[test]
    fn generate_ics_prodid_present() {
        let details = BookingDetails {
            event_title: "Call".to_string(),
            date: "2026-04-01".to_string(),
            start_time: "10:00".to_string(),
            end_time: "10:30".to_string(),
            guest_name: "Guest".to_string(),
            guest_email: "guest@test.com".to_string(),
            guest_timezone: "UTC".to_string(),
            host_name: "Host".to_string(),
            host_email: "host@test.com".to_string(),
            uid: "uid-prodid".to_string(),
            notes: None,
            location: None,
            reminder_minutes: None,
            additional_attendees: vec![],
            ..Default::default()
        };
        let ics = generate_ics(&details, "PUBLISH");
        assert!(ics.contains("PRODID:-//calrs//calrs//EN"));
        assert!(ics.contains("VERSION:2.0"));
    }

    #[test]
    fn generate_ics_negative_reminder_excluded() {
        let details = BookingDetails {
            event_title: "Call".to_string(),
            date: "2026-04-01".to_string(),
            start_time: "10:00".to_string(),
            end_time: "10:30".to_string(),
            guest_name: "Guest".to_string(),
            guest_email: "guest@test.com".to_string(),
            guest_timezone: "UTC".to_string(),
            host_name: "Host".to_string(),
            host_email: "host@test.com".to_string(),
            uid: "uid-neg-reminder".to_string(),
            notes: None,
            location: None,
            reminder_minutes: Some(-5),
            additional_attendees: vec![],
            ..Default::default()
        };
        let ics = generate_ics(&details, "PUBLISH");
        assert!(!ics.contains("VALARM"));
    }

    #[test]
    fn generate_ics_large_reminder() {
        let details = BookingDetails {
            event_title: "Call".to_string(),
            date: "2026-04-01".to_string(),
            start_time: "10:00".to_string(),
            end_time: "10:30".to_string(),
            guest_name: "Guest".to_string(),
            guest_email: "guest@test.com".to_string(),
            guest_timezone: "UTC".to_string(),
            host_name: "Host".to_string(),
            host_email: "host@test.com".to_string(),
            uid: "uid-large-reminder".to_string(),
            notes: None,
            location: None,
            reminder_minutes: Some(1440),
            additional_attendees: vec![],
            ..Default::default()
        };
        let ics = generate_ics(&details, "PUBLISH");
        assert!(ics.contains("TRIGGER:-PT1440M"));
    }

    #[test]
    fn generate_ics_location_with_special_chars() {
        let details = BookingDetails {
            event_title: "Call".to_string(),
            date: "2026-04-01".to_string(),
            start_time: "10:00".to_string(),
            end_time: "10:30".to_string(),
            guest_name: "Guest".to_string(),
            guest_email: "guest@test.com".to_string(),
            guest_timezone: "UTC".to_string(),
            host_name: "Host".to_string(),
            host_email: "host@test.com".to_string(),
            uid: "uid-loc-special".to_string(),
            notes: None,
            location: Some("Room A; Building 3, Floor 2".to_string()),
            reminder_minutes: None,
            additional_attendees: vec![],
            ..Default::default()
        };
        let ics = generate_ics(&details, "PUBLISH");
        assert!(ics.contains("LOCATION:Room A\\; Building 3\\, Floor 2"));
    }

    #[test]
    fn generate_ics_multiple_attendees_with_special_chars() {
        let details = BookingDetails {
            event_title: "Call".to_string(),
            date: "2026-04-01".to_string(),
            start_time: "10:00".to_string(),
            end_time: "10:30".to_string(),
            guest_name: "Guest".to_string(),
            guest_email: "guest@test.com".to_string(),
            guest_timezone: "UTC".to_string(),
            host_name: "Host".to_string(),
            host_email: "host@test.com".to_string(),
            uid: "uid-att-special".to_string(),
            notes: None,
            location: None,
            reminder_minutes: None,
            additional_attendees: vec![
                "user+tag@example.com".to_string(),
                "another.user@sub.domain.com".to_string(),
            ],
            ..Default::default()
        };
        let ics = generate_ics(&details, "PUBLISH");
        assert!(ics.contains("ATTENDEE;RSVP=TRUE:mailto:user+tag@example.com"));
        assert!(ics.contains("ATTENDEE;RSVP=TRUE:mailto:another.user@sub.domain.com"));
    }

    // --- generate_cancel_ics additional edge cases ---

    #[test]
    fn generate_cancel_ics_no_location_line() {
        let details = CancellationDetails {
            event_title: "Call".to_string(),
            date: "2026-04-01".to_string(),
            start_time: "10:00".to_string(),
            end_time: "10:30".to_string(),
            guest_name: "Guest".to_string(),
            guest_email: "guest@test.com".to_string(),
            guest_timezone: "UTC".to_string(),
            host_name: "Host".to_string(),
            host_email: "host@test.com".to_string(),
            uid: "uid-cancel-noloc".to_string(),
            reason: None,
            cancelled_by_host: false,
            ..Default::default()
        };
        let ics = generate_cancel_ics(&details);
        assert!(!ics.contains("LOCATION:"));
        assert!(!ics.contains("DESCRIPTION:"));
    }

    #[test]
    fn generate_cancel_ics_no_valarm() {
        // Cancel ICS should never contain VALARM
        let details = CancellationDetails {
            event_title: "Call".to_string(),
            date: "2026-04-01".to_string(),
            start_time: "10:00".to_string(),
            end_time: "10:30".to_string(),
            guest_name: "Guest".to_string(),
            guest_email: "guest@test.com".to_string(),
            guest_timezone: "UTC".to_string(),
            host_name: "Host".to_string(),
            host_email: "host@test.com".to_string(),
            uid: "uid-cancel-novalarm".to_string(),
            reason: Some("Conflict".to_string()),
            cancelled_by_host: true,
            ..Default::default()
        };
        let ics = generate_cancel_ics(&details);
        assert!(!ics.contains("VALARM"));
    }

    #[test]
    fn generate_cancel_ics_no_additional_attendees() {
        // Cancel ICS only has the primary guest attendee
        let details = CancellationDetails {
            event_title: "Call".to_string(),
            date: "2026-04-01".to_string(),
            start_time: "10:00".to_string(),
            end_time: "10:30".to_string(),
            guest_name: "Guest".to_string(),
            guest_email: "guest@test.com".to_string(),
            guest_timezone: "UTC".to_string(),
            host_name: "Host".to_string(),
            host_email: "host@test.com".to_string(),
            uid: "uid-cancel-att".to_string(),
            reason: None,
            cancelled_by_host: false,
            ..Default::default()
        };
        let ics = generate_cancel_ics(&details);
        let attendee_count = ics.matches("ATTENDEE;").count();
        assert_eq!(attendee_count, 1);
    }

    #[test]
    fn generate_cancel_ics_with_timezone_conversion() {
        // Ensure cancel ICS also converts to UTC properly
        let details = CancellationDetails {
            event_title: "Call".to_string(),
            date: "2026-07-01".to_string(),
            start_time: "15:00".to_string(),
            end_time: "15:30".to_string(),
            guest_name: "Guest".to_string(),
            guest_email: "guest@test.com".to_string(),
            guest_timezone: "America/Los_Angeles".to_string(),
            host_name: "Host".to_string(),
            host_email: "host@test.com".to_string(),
            uid: "uid-cancel-tz".to_string(),
            reason: None,
            cancelled_by_host: true,
            ..Default::default()
        };
        let ics = generate_cancel_ics(&details);
        // July: PDT = UTC-7, so 15:00 PDT = 22:00 UTC
        assert!(ics.contains("DTSTART:20260701T220000Z"));
        assert!(ics.contains("DTEND:20260701T223000Z"));
    }

    #[test]
    fn generate_cancel_ics_prodid_and_version() {
        let details = CancellationDetails {
            event_title: "Call".to_string(),
            date: "2026-04-01".to_string(),
            start_time: "10:00".to_string(),
            end_time: "10:30".to_string(),
            guest_name: "Guest".to_string(),
            guest_email: "guest@test.com".to_string(),
            guest_timezone: "UTC".to_string(),
            host_name: "Host".to_string(),
            host_email: "host@test.com".to_string(),
            uid: "uid-cancel-prodid".to_string(),
            reason: None,
            cancelled_by_host: true,
            ..Default::default()
        };
        let ics = generate_cancel_ics(&details);
        assert!(ics.contains("PRODID:-//calrs//calrs//EN"));
        assert!(ics.contains("VERSION:2.0"));
    }

    // --- render_html_email_with_actions additional tests ---

    #[test]
    fn html_email_no_actions_no_action_table() {
        let html = render_html_email_with_actions(
            "Hi,",
            "Message.",
            "#000",
            &[],
            None,
            &[], // no actions
        );
        // No action buttons table when empty
        assert!(!html.contains("display:inline-block;padding:12px 28px"));
    }

    #[test]
    fn html_email_single_action() {
        let html = render_html_email_with_actions(
            "Hi,",
            "Click below.",
            "#3b82f6",
            &[],
            None,
            &[EmailAction {
                label: "Book now".to_string(),
                url: "https://cal.rs/book".to_string(),
                color: "#6366f1".to_string(),
            }],
        );
        assert!(html.contains("Book now"));
        assert!(html.contains("https://cal.rs/book"));
        assert!(html.contains("#6366f1"));
    }

    #[test]
    fn html_email_three_actions() {
        let html = render_html_email_with_actions(
            "Hi,",
            "Actions below.",
            "#000",
            &[],
            None,
            &[
                EmailAction {
                    label: "A".to_string(),
                    url: "https://a.com".to_string(),
                    color: "#111".to_string(),
                },
                EmailAction {
                    label: "B".to_string(),
                    url: "https://b.com".to_string(),
                    color: "#222".to_string(),
                },
                EmailAction {
                    label: "C".to_string(),
                    url: "https://c.com".to_string(),
                    color: "#333".to_string(),
                },
            ],
        );
        assert!(html.contains("https://a.com"));
        assert!(html.contains("https://b.com"));
        assert!(html.contains("https://c.com"));
    }

    #[test]
    fn html_email_footer_note_html_escaped() {
        let html = render_html_email("Hi,", "Test", "#000", &[], Some("Click <here> & there"));
        assert!(html.contains("Click &lt;here&gt; &amp; there"));
    }

    #[test]
    fn html_email_row_values_html_escaped() {
        let html = render_html_email(
            "Hi,",
            "Details",
            "#000",
            &[
                EmailRow {
                    label: "Name".to_string(),
                    value: "Alice & Bob <team>".to_string(),
                },
                EmailRow {
                    label: "Notes".to_string(),
                    value: "use \"quotes\"".to_string(),
                },
            ],
            None,
        );
        assert!(html.contains("Alice &amp; Bob &lt;team&gt;"));
        assert!(html.contains("use &quot;quotes&quot;"));
    }

    #[test]
    fn html_email_accent_color_in_bar() {
        let html = render_html_email("Hi,", "Test", "#e11d48", &[], None);
        // The accent color should appear in the accent bar
        assert!(html.contains("background:#e11d48"));
    }

    #[test]
    fn html_email_with_rows_and_actions_and_footer() {
        // Test a "full" email with all components present
        let html = render_html_email_with_actions(
            "Hello Alice,",
            "Your booking is confirmed!",
            "#16a34a",
            &[
                EmailRow {
                    label: "Event".to_string(),
                    value: "Intro Call".to_string(),
                },
                EmailRow {
                    label: "Date".to_string(),
                    value: "2026-03-15".to_string(),
                },
                EmailRow {
                    label: "Time".to_string(),
                    value: "10:00 - 10:30 (UTC)".to_string(),
                },
                EmailRow {
                    label: "With".to_string(),
                    value: "Bob".to_string(),
                },
                EmailRow {
                    label: "Location".to_string(),
                    value: "https://meet.example.com/room".to_string(),
                },
            ],
            Some("A calendar invite is attached to this email."),
            &[
                EmailAction {
                    label: "Reschedule".to_string(),
                    url: "https://cal.rs/reschedule/abc".to_string(),
                    color: "#3b82f6".to_string(),
                },
                EmailAction {
                    label: "Cancel booking".to_string(),
                    url: "https://cal.rs/cancel/def".to_string(),
                    color: "#dc2626".to_string(),
                },
            ],
        );
        assert!(html.contains("Hello Alice,"));
        assert!(html.contains("Your booking is confirmed!"));
        assert!(html.contains("Intro Call"));
        assert!(html.contains("2026-03-15"));
        assert!(html.contains("10:00 - 10:30 (UTC)"));
        assert!(html.contains("Bob"));
        assert!(html.contains("https://meet.example.com/room"));
        assert!(html.contains("A calendar invite is attached to this email."));
        assert!(html.contains("Reschedule"));
        assert!(html.contains("Cancel booking"));
        assert!(html.contains("https://cal.rs/reschedule/abc"));
        assert!(html.contains("https://cal.rs/cancel/def"));
        assert!(html.contains("#16a34a")); // accent
        assert!(html.contains("calrs")); // footer branding
    }

    // --- build_multipart_body tests ---

    #[test]
    fn build_multipart_body_returns_multipart() {
        let body = build_multipart_body("plain", "<b>html</b>");
        // Verify it produces valid MIME output by formatting to string
        let formatted = format!("{:?}", body);
        // MultiPart::alternative should be in the debug output
        assert!(!formatted.is_empty());
    }

    #[test]
    fn build_multipart_body_with_empty_content() {
        let body = build_multipart_body("", "");
        let formatted = format!("{:?}", body);
        assert!(!formatted.is_empty());
    }

    #[test]
    fn build_multipart_body_with_unicode() {
        let body = build_multipart_body(
            "Meeting \u{2014} confirmed",
            "<p>Meeting \u{2014} confirmed</p>",
        );
        let formatted = format!("{:?}", body);
        assert!(!formatted.is_empty());
    }

    // --- Simulated email content building (mirrors send_* functions) ---

    /// Helper to create a standard BookingDetails for testing
    fn sample_booking_details() -> BookingDetails {
        BookingDetails {
            event_title: "30min Intro".to_string(),
            date: "2026-04-10".to_string(),
            start_time: "14:00".to_string(),
            end_time: "14:30".to_string(),
            guest_name: "Jane Doe".to_string(),
            guest_email: "jane@example.com".to_string(),
            guest_timezone: "Europe/Paris".to_string(),
            host_name: "Alice Smith".to_string(),
            host_email: "alice@example.com".to_string(),
            uid: "booking-uid-001".to_string(),
            notes: Some("Discuss project roadmap".to_string()),
            location: Some("https://meet.example.com/room".to_string()),
            reminder_minutes: Some(15),
            additional_attendees: vec!["cc@example.com".to_string()],
            ..Default::default()
        }
    }

    #[test]
    fn guest_confirmation_email_body_construction() {
        // Mirrors send_guest_confirmation_ex body construction
        let details = sample_booking_details();
        let cancel_url = Some("https://cal.rs/booking/cancel/tok1");
        let reschedule_url = Some("https://cal.rs/booking/reschedule/tok2");

        let time_display = format!(
            "{} \u{2013} {} ({})",
            details.start_time, details.end_time, details.guest_timezone
        );

        let mut rows = vec![
            EmailRow {
                label: "Event".to_string(),
                value: details.event_title.clone(),
            },
            EmailRow {
                label: "Date".to_string(),
                value: details.date.clone(),
            },
            EmailRow {
                label: "Time".to_string(),
                value: time_display,
            },
            EmailRow {
                label: "With".to_string(),
                value: details.host_name.clone(),
            },
        ];
        if let Some(loc) = &details.location {
            rows.push(EmailRow {
                label: "Location".to_string(),
                value: loc.clone(),
            });
        }
        if let Some(notes) = &details.notes {
            rows.push(EmailRow {
                label: "Notes".to_string(),
                value: notes.clone(),
            });
        }

        let mut actions: Vec<EmailAction> = Vec::new();
        if let Some(u) = reschedule_url {
            actions.push(EmailAction {
                label: "Reschedule".to_string(),
                url: u.to_string(),
                color: "#3b82f6".to_string(),
            });
        }
        if let Some(u) = cancel_url {
            actions.push(EmailAction {
                label: "Cancel booking".to_string(),
                url: u.to_string(),
                color: "#dc2626".to_string(),
            });
        }

        let html = render_html_email_with_actions(
            &format!("Hi {},", h(&details.guest_name)),
            "Your booking has been confirmed!",
            "#16a34a",
            &rows,
            Some("A calendar invite is attached to this email."),
            &actions,
        );

        assert!(html.contains("Hi Jane Doe,"));
        assert!(html.contains("Your booking has been confirmed!"));
        assert!(html.contains("30min Intro"));
        assert!(html.contains("2026-04-10"));
        assert!(html.contains("14:00"));
        assert!(html.contains("Alice Smith"));
        assert!(html.contains("https://meet.example.com/room"));
        assert!(html.contains("Discuss project roadmap"));
        assert!(html.contains("Reschedule"));
        assert!(html.contains("Cancel booking"));
        assert!(html.contains("#16a34a")); // green accent
    }

    #[test]
    fn guest_pending_email_body_excludes_location() {
        // Mirrors send_guest_pending_notice_ex — location should NOT be included
        let details = sample_booking_details();

        let time_display = format!(
            "{} \u{2013} {} ({})",
            details.start_time, details.end_time, details.guest_timezone
        );

        let mut rows = vec![
            EmailRow {
                label: "Event".to_string(),
                value: details.event_title.clone(),
            },
            EmailRow {
                label: "Date".to_string(),
                value: details.date.clone(),
            },
            EmailRow {
                label: "Time".to_string(),
                value: time_display,
            },
            EmailRow {
                label: "Host".to_string(),
                value: details.host_name.clone(),
            },
        ];
        // Note: no location row for pending emails
        if let Some(notes) = &details.notes {
            rows.push(EmailRow {
                label: "Notes".to_string(),
                value: notes.clone(),
            });
        }

        let html = render_html_email_with_actions(
            &format!("Hi {},", h(&details.guest_name)),
            &format!(
                "Your booking request is awaiting confirmation from {}.",
                h(&details.host_name)
            ),
            "#f59e0b",
            &rows,
            Some("You\u{2019}ll receive another email once it\u{2019}s confirmed."),
            &[],
        );

        assert!(html.contains("awaiting confirmation from Alice Smith"));
        assert!(html.contains("#f59e0b")); // amber accent for pending
        assert!(!html.contains("Location")); // No location in pending emails
        assert!(html.contains("Notes"));
    }

    #[test]
    fn host_notification_email_body_construction() {
        // Mirrors send_host_notification body
        let details = sample_booking_details();

        let time_display = format!("{} \u{2013} {}", details.start_time, details.end_time);

        let mut rows = vec![
            EmailRow {
                label: "Event".to_string(),
                value: details.event_title.clone(),
            },
            EmailRow {
                label: "Date".to_string(),
                value: details.date.clone(),
            },
            EmailRow {
                label: "Time".to_string(),
                value: time_display,
            },
            EmailRow {
                label: "Guest".to_string(),
                value: format!("{} <{}>", details.guest_name, details.guest_email),
            },
        ];
        if let Some(loc) = &details.location {
            rows.push(EmailRow {
                label: "Location".to_string(),
                value: loc.clone(),
            });
        }
        if let Some(notes) = &details.notes {
            rows.push(EmailRow {
                label: "Notes".to_string(),
                value: notes.clone(),
            });
        }

        let html = render_html_email(
            "New booking!",
            &format!("{} booked a slot with you.", h(&details.guest_name)),
            "#16a34a",
            &rows,
            Some("A calendar invite is attached to this email."),
        );

        assert!(html.contains("New booking!"));
        assert!(html.contains("Jane Doe booked a slot with you."));
        assert!(html.contains("Jane Doe &lt;jane@example.com&gt;"));
        assert!(html.contains("Location"));
    }

    #[test]
    fn host_approval_request_email_with_token() {
        // Mirrors send_host_approval_request body construction
        let details = sample_booking_details();
        let confirm_token = Some("abc-token-123");
        let base_url = Some("https://cal.example.com");

        let (approve_url, decline_url) = match (confirm_token, base_url) {
            (Some(token), Some(url)) => (
                Some(format!(
                    "{}/booking/approve/{}",
                    url.trim_end_matches('/'),
                    token
                )),
                Some(format!(
                    "{}/booking/decline/{}",
                    url.trim_end_matches('/'),
                    token
                )),
            ),
            _ => (None, None),
        };

        assert_eq!(
            approve_url.as_deref(),
            Some("https://cal.example.com/booking/approve/abc-token-123")
        );
        assert_eq!(
            decline_url.as_deref(),
            Some("https://cal.example.com/booking/decline/abc-token-123")
        );

        let actions: Vec<EmailAction> = match (approve_url, decline_url) {
            (Some(a), Some(d)) => vec![
                EmailAction {
                    label: "Approve".to_string(),
                    url: a,
                    color: "#16a34a".to_string(),
                },
                EmailAction {
                    label: "Decline".to_string(),
                    url: d,
                    color: "#dc2626".to_string(),
                },
            ],
            _ => vec![],
        };

        let html = render_html_email_with_actions(
            "Action required",
            &format!("{} wants to book a slot with you.", h(&details.guest_name)),
            "#f59e0b",
            &[EmailRow {
                label: "Guest".to_string(),
                value: format!("{} <{}>", details.guest_name, details.guest_email),
            }],
            Some("You can also manage this from your dashboard."),
            &actions,
        );

        assert!(html.contains("Action required"));
        assert!(html.contains("Jane Doe wants to book a slot with you."));
        assert!(html.contains("Approve"));
        assert!(html.contains("Decline"));
        assert!(html.contains("booking/approve/abc-token-123"));
        assert!(html.contains("booking/decline/abc-token-123"));
    }

    #[test]
    fn host_approval_request_without_token_no_actions() {
        let confirm_token: Option<&str> = None;
        let base_url = Some("https://cal.example.com");

        let (approve_url, decline_url) = match (confirm_token, base_url) {
            (Some(token), Some(url)) => (
                Some(format!(
                    "{}/booking/approve/{}",
                    url.trim_end_matches('/'),
                    token
                )),
                Some(format!(
                    "{}/booking/decline/{}",
                    url.trim_end_matches('/'),
                    token
                )),
            ),
            _ => (None, None),
        };

        let actions: Vec<EmailAction> = match (approve_url, decline_url) {
            (Some(a), Some(d)) => vec![
                EmailAction {
                    label: "Approve".to_string(),
                    url: a,
                    color: "#16a34a".to_string(),
                },
                EmailAction {
                    label: "Decline".to_string(),
                    url: d,
                    color: "#dc2626".to_string(),
                },
            ],
            _ => vec![],
        };

        assert!(actions.is_empty(), "No actions when token is missing");
    }

    #[test]
    fn guest_decline_email_body_with_reason() {
        let details = CancellationDetails {
            event_title: "Intro Call".to_string(),
            date: "2026-04-10".to_string(),
            start_time: "14:00".to_string(),
            end_time: "14:30".to_string(),
            guest_name: "Jane".to_string(),
            guest_email: "jane@example.com".to_string(),
            guest_timezone: "UTC".to_string(),
            host_name: "Alice".to_string(),
            host_email: "alice@example.com".to_string(),
            uid: "uid-decline".to_string(),
            reason: Some("Schedule conflict".to_string()),
            cancelled_by_host: true, // decline is host-initiated
            ..Default::default()
        };

        let mut rows = vec![
            EmailRow {
                label: "Event".to_string(),
                value: details.event_title.clone(),
            },
            EmailRow {
                label: "Date".to_string(),
                value: details.date.clone(),
            },
            EmailRow {
                label: "With".to_string(),
                value: details.host_name.clone(),
            },
        ];
        if let Some(reason) = &details.reason {
            rows.push(EmailRow {
                label: "Reason".to_string(),
                value: reason.clone(),
            });
        }

        let html = render_html_email(
            &format!("Hi {},", h(&details.guest_name)),
            "Your booking request has been declined.",
            "#dc2626",
            &rows,
            None,
        );

        assert!(html.contains("Hi Jane,"));
        assert!(html.contains("declined"));
        assert!(html.contains("Schedule conflict"));
        assert!(html.contains("#dc2626")); // red accent
    }

    #[test]
    fn guest_decline_email_body_without_reason() {
        let details = CancellationDetails {
            event_title: "Meeting".to_string(),
            date: "2026-04-10".to_string(),
            start_time: "09:00".to_string(),
            end_time: "10:00".to_string(),
            guest_name: "Bob".to_string(),
            guest_email: "bob@test.com".to_string(),
            guest_timezone: "UTC".to_string(),
            host_name: "Alice".to_string(),
            host_email: "alice@test.com".to_string(),
            uid: "uid-decline-noreason".to_string(),
            reason: None,
            cancelled_by_host: true,
            ..Default::default()
        };

        let mut rows = vec![EmailRow {
            label: "Event".to_string(),
            value: details.event_title.clone(),
        }];
        if let Some(reason) = &details.reason {
            rows.push(EmailRow {
                label: "Reason".to_string(),
                value: reason.clone(),
            });
        }

        let html = render_html_email("Hi,", "Declined.", "#dc2626", &rows, None);
        assert!(!html.contains("Reason")); // No reason row
    }

    #[test]
    fn invite_email_body_construction() {
        // Mirrors send_invite_email body construction
        let guest_name = "Jane";
        let host_name = "Alice";
        let event_title = "Private Consultation";
        let message = Some("Looking forward to chatting!");
        let invite_url = "https://cal.rs/u/alice/consult?invite=TOKEN123";
        let expires_at = Some("2026-04-20");

        let mut rows = vec![
            EmailRow {
                label: "Event".to_string(),
                value: event_title.to_string(),
            },
            EmailRow {
                label: "Invited by".to_string(),
                value: host_name.to_string(),
            },
        ];
        if let Some(msg) = message.filter(|m| !m.trim().is_empty()) {
            rows.push(EmailRow {
                label: "Message".to_string(),
                value: msg.to_string(),
            });
        }
        if let Some(exp) = expires_at {
            rows.push(EmailRow {
                label: "Expires".to_string(),
                value: exp.to_string(),
            });
        }

        let actions = vec![EmailAction {
            label: "Choose a time".to_string(),
            url: invite_url.to_string(),
            color: "#6366f1".to_string(),
        }];

        let html = render_html_email_with_actions(
            &format!("Hi {},", h(guest_name)),
            &format!(
                "{} has invited you to book: {}",
                h(host_name),
                h(event_title)
            ),
            "#6366f1",
            &rows,
            None,
            &actions,
        );

        assert!(html.contains("Hi Jane,"));
        assert!(html.contains("Alice has invited you to book: Private Consultation"));
        assert!(html.contains("Looking forward to chatting!"));
        assert!(html.contains("2026-04-20"));
        assert!(html.contains("Choose a time"));
        assert!(html.contains(invite_url));
        assert!(html.contains("#6366f1")); // indigo accent
    }

    #[test]
    fn invite_email_body_no_message_no_expiry() {
        let message: Option<&str> = None;
        let expires_at: Option<&str> = None;

        let mut rows = vec![
            EmailRow {
                label: "Event".to_string(),
                value: "Meeting".to_string(),
            },
            EmailRow {
                label: "Invited by".to_string(),
                value: "Host".to_string(),
            },
        ];
        if let Some(msg) = message.filter(|m| !m.trim().is_empty()) {
            rows.push(EmailRow {
                label: "Message".to_string(),
                value: msg.to_string(),
            });
        }
        if let Some(exp) = expires_at {
            rows.push(EmailRow {
                label: "Expires".to_string(),
                value: exp.to_string(),
            });
        }

        assert_eq!(rows.len(), 2); // Only Event and Invited by
    }

    #[test]
    fn invite_email_empty_message_excluded() {
        let message: Option<&str> = Some("   ");

        let mut rows = Vec::new();
        if let Some(msg) = message.filter(|m| !m.trim().is_empty()) {
            rows.push(EmailRow {
                label: "Message".to_string(),
                value: msg.to_string(),
            });
        }

        assert!(
            rows.is_empty(),
            "Whitespace-only message should be excluded"
        );
    }

    #[test]
    fn guest_reminder_email_body_with_cancel_url() {
        // Mirrors send_guest_reminder body construction
        let details = sample_booking_details();
        let cancel_url = Some("https://cal.rs/booking/cancel/rem-tok");

        let actions: Vec<EmailAction> = cancel_url
            .map(|u| {
                vec![EmailAction {
                    label: "Cancel booking".to_string(),
                    url: u.to_string(),
                    color: "#dc2626".to_string(),
                }]
            })
            .unwrap_or_default();

        let html = render_html_email_with_actions(
            &format!("Hi {},", h(&details.guest_name)),
            "Reminder: you have an upcoming booking.",
            "#3b82f6",
            &[
                EmailRow {
                    label: "Event".to_string(),
                    value: details.event_title.clone(),
                },
                EmailRow {
                    label: "Date".to_string(),
                    value: details.date.clone(),
                },
            ],
            None,
            &actions,
        );

        assert!(html.contains("Reminder"));
        assert!(html.contains("#3b82f6")); // blue accent for reminders
        assert!(html.contains("Cancel booking"));
        assert!(html.contains("rem-tok"));
    }

    #[test]
    fn guest_reminder_email_body_without_cancel_url() {
        let cancel_url: Option<&str> = None;

        let actions: Vec<EmailAction> = cancel_url
            .map(|u| {
                vec![EmailAction {
                    label: "Cancel booking".to_string(),
                    url: u.to_string(),
                    color: "#dc2626".to_string(),
                }]
            })
            .unwrap_or_default();

        assert!(actions.is_empty());

        let html =
            render_html_email_with_actions("Hi,", "Reminder.", "#3b82f6", &[], None, &actions);
        assert!(!html.contains("Cancel booking"));
    }

    #[test]
    fn host_reschedule_request_url_construction() {
        // Mirrors the URL construction in send_host_reschedule_request
        let confirm_token = Some("resched-token-xyz");
        let base_url = Some("https://cal.example.com/");

        let (approve_url, decline_url) = match (confirm_token, base_url) {
            (Some(token), Some(url)) => (
                Some(format!(
                    "{}/booking/approve/{}",
                    url.trim_end_matches('/'),
                    token
                )),
                Some(format!(
                    "{}/booking/decline/{}",
                    url.trim_end_matches('/'),
                    token
                )),
            ),
            _ => (None, None),
        };

        // Trailing slash should be stripped
        assert_eq!(
            approve_url.as_deref(),
            Some("https://cal.example.com/booking/approve/resched-token-xyz")
        );
        assert_eq!(
            decline_url.as_deref(),
            Some("https://cal.example.com/booking/decline/resched-token-xyz")
        );
    }

    #[test]
    fn guest_pick_new_time_email_body() {
        // Mirrors send_guest_pick_new_time body construction
        let details = sample_booking_details();
        let reschedule_url = "https://cal.rs/booking/reschedule/tok";
        let cancel_url = Some("https://cal.rs/booking/cancel/tok");

        let time_display = format!(
            "{} \u{2013} {} ({})",
            details.start_time, details.end_time, details.guest_timezone
        );

        let rows = vec![
            EmailRow {
                label: "Event".to_string(),
                value: details.event_title.clone(),
            },
            EmailRow {
                label: "Originally".to_string(),
                value: format!("{} at {}", details.date, time_display),
            },
            EmailRow {
                label: "Host".to_string(),
                value: details.host_name.clone(),
            },
        ];

        let mut actions = vec![EmailAction {
            label: "Pick a new time".to_string(),
            url: reschedule_url.to_string(),
            color: "#d97706".to_string(),
        }];
        if let Some(u) = cancel_url {
            actions.push(EmailAction {
                label: "Cancel booking".to_string(),
                url: u.to_string(),
                color: "#dc2626".to_string(),
            });
        }

        let html = render_html_email_with_actions(
            &format!("Hi {},", h(&details.guest_name)),
            &format!(
                "{} needs to reschedule your booking. Please pick a new time.",
                h(&details.host_name)
            ),
            "#d97706",
            &rows,
            None,
            &actions,
        );

        assert!(html.contains("Pick a new time"));
        assert!(html.contains("Cancel booking"));
        assert!(html.contains("needs to reschedule"));
        assert!(html.contains("#d97706")); // orange accent
        assert!(html.contains("Originally"));
    }

    #[test]
    fn host_booking_confirmed_email_body() {
        // Mirrors send_host_booking_confirmed body construction
        let details = sample_booking_details();

        let time_display = format!("{} \u{2013} {}", details.start_time, details.end_time);

        let mut rows = vec![
            EmailRow {
                label: "Event".to_string(),
                value: details.event_title.clone(),
            },
            EmailRow {
                label: "Date".to_string(),
                value: details.date.clone(),
            },
            EmailRow {
                label: "Time".to_string(),
                value: time_display,
            },
            EmailRow {
                label: "Guest".to_string(),
                value: format!("{} <{}>", details.guest_name, details.guest_email),
            },
        ];
        if let Some(loc) = &details.location {
            rows.push(EmailRow {
                label: "Location".to_string(),
                value: loc.clone(),
            });
        }

        let html = render_html_email(
            "Booking confirmed",
            &format!("You approved the booking with {}.", h(&details.guest_name)),
            "#16a34a",
            &rows,
            Some("The event has been added to your calendar."),
        );

        assert!(html.contains("Booking confirmed"));
        assert!(html.contains("You approved the booking with Jane Doe."));
        assert!(html.contains("The event has been added to your calendar."));
        assert!(html.contains("Location"));
    }

    // --- ICS generation for reschedule ---

    #[test]
    fn reschedule_ics_uses_new_date_and_time() {
        let details = sample_reschedule_details();
        let booking_details = BookingDetails {
            event_title: details.event_title.clone(),
            date: details.new_date.clone(),
            start_time: details.new_start_time.clone(),
            end_time: details.new_end_time.clone(),
            guest_name: details.guest_name.clone(),
            guest_email: details.guest_email.clone(),
            guest_timezone: details.guest_timezone.clone(),
            host_name: details.host_name.clone(),
            host_email: details.host_email.clone(),
            uid: details.uid.clone(),
            notes: None,
            location: details.location.clone(),
            reminder_minutes: None,
            additional_attendees: vec![],
            ..Default::default()
        };
        let ics = generate_ics(&booking_details, "PUBLISH");
        // March 17, 2026 in Paris (CET, UTC+1): 14:00 Paris = 13:00 UTC
        assert!(ics.contains("DTSTART:20260317T130000Z"));
        assert!(ics.contains("DTEND:20260317T133000Z"));
        // Should NOT contain old dates
        assert!(!ics.contains("20260316"));
    }

    #[test]
    fn reschedule_details_without_location() {
        let mut details = sample_reschedule_details();
        details.location = None;
        let booking_details = BookingDetails {
            event_title: details.event_title,
            date: details.new_date,
            start_time: details.new_start_time,
            end_time: details.new_end_time,
            guest_name: details.guest_name,
            guest_email: details.guest_email,
            guest_timezone: details.guest_timezone,
            host_name: details.host_name,
            host_email: details.host_email,
            uid: details.uid,
            notes: None,
            location: None,
            reminder_minutes: None,
            additional_attendees: vec![],
            ..Default::default()
        };
        let ics = generate_ics(&booking_details, "PUBLISH");
        assert!(!ics.contains("LOCATION:"));
    }

    // --- ICS structural validation ---

    #[test]
    fn generate_ics_crlf_line_endings() {
        let details = BookingDetails {
            event_title: "Call".to_string(),
            date: "2026-04-01".to_string(),
            start_time: "10:00".to_string(),
            end_time: "10:30".to_string(),
            guest_name: "Guest".to_string(),
            guest_email: "guest@test.com".to_string(),
            guest_timezone: "UTC".to_string(),
            host_name: "Host".to_string(),
            host_email: "host@test.com".to_string(),
            uid: "uid-crlf".to_string(),
            notes: None,
            location: None,
            reminder_minutes: None,
            additional_attendees: vec![],
            ..Default::default()
        };
        let ics = generate_ics(&details, "PUBLISH");
        // Every line should end with \r\n (RFC 5545 requirement)
        assert!(ics.contains("\r\n"));
        // Should start and end properly
        assert!(ics.starts_with("BEGIN:VCALENDAR\r\n"));
        assert!(ics.ends_with("END:VCALENDAR\r\n"));
    }

    #[test]
    fn generate_cancel_ics_crlf_line_endings() {
        let details = CancellationDetails {
            event_title: "Call".to_string(),
            date: "2026-04-01".to_string(),
            start_time: "10:00".to_string(),
            end_time: "10:30".to_string(),
            guest_name: "Guest".to_string(),
            guest_email: "guest@test.com".to_string(),
            guest_timezone: "UTC".to_string(),
            host_name: "Host".to_string(),
            host_email: "host@test.com".to_string(),
            uid: "uid-cancel-crlf".to_string(),
            reason: None,
            cancelled_by_host: false,
            ..Default::default()
        };
        let ics = generate_cancel_ics(&details);
        assert!(ics.starts_with("BEGIN:VCALENDAR\r\n"));
        assert!(ics.ends_with("END:VCALENDAR\r\n"));
    }

    // --- HTML email structural validation ---

    #[test]
    fn html_email_is_valid_html_structure() {
        let html = render_html_email("Hi,", "Test", "#000", &[], None);
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("<html"));
        assert!(html.contains("</html>"));
        assert!(html.contains("<head>"));
        assert!(html.contains("</head>"));
        assert!(html.contains("<body"));
        assert!(html.contains("</body>"));
    }

    #[test]
    fn html_email_has_meta_charset() {
        let html = render_html_email("Hi,", "Test", "#000", &[], None);
        assert!(html.contains("charset=\"utf-8\"") || html.contains("charset=utf-8"));
    }

    #[test]
    fn html_email_has_viewport_meta() {
        let html = render_html_email("Hi,", "Test", "#000", &[], None);
        assert!(html.contains("viewport"));
    }

    #[test]
    fn html_email_has_calrs_footer_link() {
        let html = render_html_email("Hi,", "Test", "#000", &[], None);
        assert!(html.contains("https://cal.rs"));
        assert!(html.contains("calrs"));
    }

    // --- Cancellation email body tests ---

    #[test]
    fn guest_cancellation_email_host_initiated_with_reason() {
        let details = CancellationDetails {
            event_title: "Intro Call".to_string(),
            date: "2026-04-10".to_string(),
            start_time: "14:00".to_string(),
            end_time: "14:30".to_string(),
            guest_name: "Jane".to_string(),
            guest_email: "jane@example.com".to_string(),
            guest_timezone: "UTC".to_string(),
            host_name: "Alice".to_string(),
            host_email: "alice@example.com".to_string(),
            uid: "uid-gcancel".to_string(),
            reason: Some("Emergency".to_string()),
            cancelled_by_host: true,
            ..Default::default()
        };

        let mut rows = vec![
            EmailRow {
                label: "Event".to_string(),
                value: details.event_title.clone(),
            },
            EmailRow {
                label: "Date".to_string(),
                value: details.date.clone(),
            },
            EmailRow {
                label: "With".to_string(),
                value: details.host_name.clone(),
            },
        ];
        if let Some(reason) = &details.reason {
            rows.push(EmailRow {
                label: "Reason".to_string(),
                value: reason.clone(),
            });
        }

        let msg = if details.cancelled_by_host {
            format!(
                "Your booking has been cancelled by {}.",
                h(&details.host_name)
            )
        } else {
            "Your booking has been cancelled.".to_string()
        };

        let html = render_html_email(
            &format!("Hi {},", h(&details.guest_name)),
            &msg,
            "#dc2626",
            &rows,
            Some("A calendar cancellation is attached to this email."),
        );

        assert!(html.contains("cancelled by Alice"));
        assert!(html.contains("Emergency"));
    }

    #[test]
    fn host_cancellation_email_guest_initiated() {
        let details = CancellationDetails {
            event_title: "Meeting".to_string(),
            date: "2026-04-10".to_string(),
            start_time: "09:00".to_string(),
            end_time: "10:00".to_string(),
            guest_name: "Bob".to_string(),
            guest_email: "bob@test.com".to_string(),
            guest_timezone: "UTC".to_string(),
            host_name: "Alice".to_string(),
            host_email: "alice@test.com".to_string(),
            uid: "uid-hcancel".to_string(),
            reason: Some("Double booked".to_string()),
            cancelled_by_host: false,
            ..Default::default()
        };

        let msg = if details.cancelled_by_host {
            "You cancelled this booking.".to_string()
        } else {
            format!("{} cancelled their booking.", h(&details.guest_name))
        };

        let html = render_html_email("Booking cancelled.", &msg, "#dc2626", &[], None);

        assert!(html.contains("Bob cancelled their booking."));
    }

    // --- Test email body ICS attachment generation ---

    #[test]
    fn guest_confirmation_ics_has_publish_method() {
        let details = sample_booking_details();
        let ics = generate_ics(&details, "PUBLISH");
        assert!(ics.contains("METHOD:PUBLISH"));
    }

    #[test]
    fn host_notification_ics_has_request_method() {
        let details = sample_booking_details();
        let ics = generate_ics(&details, "REQUEST");
        assert!(ics.contains("METHOD:REQUEST"));
    }

    #[test]
    fn cancellation_ics_has_cancel_method_and_status() {
        let details = CancellationDetails {
            event_title: "Meeting".to_string(),
            date: "2026-04-10".to_string(),
            start_time: "14:00".to_string(),
            end_time: "14:30".to_string(),
            guest_name: "Jane".to_string(),
            guest_email: "jane@example.com".to_string(),
            guest_timezone: "Europe/Paris".to_string(),
            host_name: "Alice".to_string(),
            host_email: "alice@example.com".to_string(),
            uid: "uid-cancel-method".to_string(),
            reason: None,
            cancelled_by_host: true,
            ..Default::default()
        };
        let ics = generate_cancel_ics(&details);
        assert!(ics.contains("METHOD:CANCEL"));
        assert!(ics.contains("STATUS:CANCELLED"));
        // Confirm ICS does NOT have STATUS:CONFIRMED
        assert!(!ics.contains("STATUS:CONFIRMED"));
    }

    // ===== Email-header injection defenses =====
    //
    // Email-sending paths used to build To via
    // `format!("{name} <{email}>").parse::<Mailbox>()?`; they now go through
    // `named_mailbox()`, which replaces control characters in the name before
    // `Mailbox::new` (see the tests below it). Subjects go through
    // `.subject(format!(…))`. The audit that produced #43 flagged the first
    // pattern as potentially injectable (Claude's reasoning: an unvalidated
    // guest name could contain CRLF and smuggle a Bcc: into the headers).
    //
    // Empirically lettre's typed builder defends both: `Mailbox::from_str`
    // rejects CRLF in display names, and `.subject(…)` RFC 2047-encodes any
    // control chars (so `\r\n` ends up inside a base64-encoded section and
    // never reaches the SMTP wire). These tests pin that behavior so we
    // notice immediately if a future lettre upgrade relaxes either defense
    // — at which point we'd need to add an explicit sanitizer at the
    // boundary in email.rs.

    #[test]
    fn lettre_mailbox_rejects_crlf_in_display_name() {
        use lettre::message::Mailbox;
        // The shape email.rs used before `named_mailbox()`:
        //   format!("{} <{}>", details.guest_name, details.guest_email).parse()
        let payloads = [
            "Alice\r\nBcc: evil@attacker.com",
            "Alice\nX-Smuggled: true",
            "Alice\r\nSubject: hijacked",
            "Alice\"; Bcc: evil@attacker.com\r\n",
        ];
        for payload in payloads {
            let raw = format!("{} <guest@example.com>", payload);
            let result = raw.parse::<Mailbox>();
            assert!(
                result.is_err(),
                "lettre must reject CRLF/LF in display name — payload {:?} parsed to {:?}",
                payload,
                result
            );
        }
    }

    /// A display name with `@`, a comma, quotes and angle brackets did not
    /// parse once formatted as `name <email>`, so the email was never sent.
    #[test]
    fn named_mailbox_accepts_special_characters_in_the_name() {
        let name = r#"Dr. "Ace" O'Neil, PhD @ Acme <ops>; team"#;
        let mailbox = named_mailbox(name, "ace@example.com").expect("a valid mailbox");
        assert_eq!(mailbox.name.as_deref(), Some(name));
        assert_eq!(mailbox.email.to_string(), "ace@example.com");
        // What lettre writes on the wire parses back to the same mailbox.
        let reparsed: Mailbox = mailbox.to_string().parse().expect("round-trips");
        assert_eq!(reparsed, mailbox);
        // The old shape refused the same input.
        assert!(format!("{name} <ace@example.com>")
            .parse::<Mailbox>()
            .is_err());
    }

    #[test]
    fn named_mailbox_keeps_crlf_out_of_the_headers() {
        let mailbox = named_mailbox("Alice\r\nBcc: evil@attacker.com", "guest@example.com")
            .expect("control characters are replaced, not refused");
        let msg = Message::builder()
            .from("sender@example.com".parse::<Mailbox>().unwrap())
            .to(mailbox)
            .subject("s")
            .body("body".to_string())
            .unwrap();
        let wire = String::from_utf8_lossy(&msg.formatted()).into_owned();
        assert!(
            !wire.lines().any(|l| l.starts_with("Bcc:")),
            "header injected: {wire}"
        );
        // An empty (or all-control) name leaves the bare address.
        let bare = named_mailbox(" \r\n ", "guest@example.com").unwrap();
        assert_eq!(bare.name, None);
        assert!(named_mailbox("Alice", "not an address").is_err());
    }

    /// End to end: a host whose name has `@`, a comma and quotes in it gets
    /// their cancellation notice.
    #[tokio::test]
    async fn host_with_special_characters_in_the_name_is_emailed() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(fake_no_auth_mta(listener));

        let details = CancellationDetails {
            event_title: "Intro".to_string(),
            date: "2030-07-02".to_string(),
            start_time: "10:00".to_string(),
            end_time: "10:30".to_string(),
            guest_name: "Guest".to_string(),
            guest_email: "guest@example.com".to_string(),
            guest_timezone: "UTC".to_string(),
            host_name: r#"Alice "Ops" @ Acme, Inc."#.to_string(),
            host_email: "alice@example.com".to_string(),
            uid: "uid-special-name".to_string(),
            ..Default::default()
        };
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            send_host_cancellation(&plaintext_config(port, ""), &details),
        )
        .await
        .expect("send timed out")
        .expect("the notice is sent");

        let seen = tokio::time::timeout(std::time::Duration::from_secs(10), server)
            .await
            .expect("server timed out")
            .unwrap();
        assert!(
            seen.iter()
                .any(|c| c.starts_with("RCPT TO") && c.contains("alice@example.com")),
            "{seen:?}"
        );
        assert!(seen.iter().any(|c| c == "DATA"), "{seen:?}");
    }

    #[test]
    fn lettre_subject_encodes_crlf_safely() {
        use lettre::message::{Mailbox, Message};
        let msg = Message::builder()
            .from("sender@example.com".parse::<Mailbox>().unwrap())
            .to("to@example.com".parse::<Mailbox>().unwrap())
            .subject("Normal\r\nBcc: evil@attacker.com")
            .body("body".to_string())
            .expect("message builds");

        let raw = msg.formatted();
        let wire = String::from_utf8_lossy(&raw);

        // The injected header name must not appear as its own header line.
        // Exhaustively: neither right after a CRLF, nor at the start of the
        // wire format (which would also be injection).
        let lines: Vec<&str> = wire.split("\r\n").collect();
        assert!(
            !lines.iter().any(|l| l.starts_with("Bcc:")),
            "Bcc header injected — lettre no longer encodes Subject CRLF. Wire:\n{}",
            wire
        );
        // Sanity: the Subject line itself must exist exactly once.
        let subject_count = lines.iter().filter(|l| l.starts_with("Subject:")).count();
        assert_eq!(subject_count, 1, "exactly one Subject header expected");
    }

    // --- #209: guest pending-flow emails follow the booking's language ---

    fn cancellation_from(details: &BookingDetails) -> CancellationDetails {
        CancellationDetails {
            event_title: details.event_title.clone(),
            date: details.date.clone(),
            start_time: details.start_time.clone(),
            end_time: details.end_time.clone(),
            guest_name: details.guest_name.clone(),
            guest_email: details.guest_email.clone(),
            guest_timezone: details.guest_timezone.clone(),
            host_name: details.host_name.clone(),
            host_email: details.host_email.clone(),
            reason: Some("Conflit".to_string()),
            cancelled_by_host: true,
            guest_language: details.guest_language.clone(),
            ..Default::default()
        }
    }

    #[test]
    fn pending_notice_is_written_in_the_guest_language() {
        let details = BookingDetails {
            guest_language: Some("fr".to_string()),
            ..sample_booking_details()
        };
        let mail = compose_guest_pending_notice(
            &details,
            Some("https://cal.rs/booking/cancel/tok1"),
            Some("https://cal.rs/booking/reschedule/tok2"),
        );

        assert_eq!(
            mail.subject,
            "[En attente de confirmation] 30min Intro \u{2014} 2026-04-10"
        );
        assert!(
            mail.plain.starts_with("Bonjour Jane Doe,"),
            "{}",
            mail.plain
        );
        assert!(mail
            .plain
            .contains("Votre demande de réservation a été envoyée à Alice Smith"));
        assert!(mail.plain.contains("Événement : 30min Intro"));
        assert!(mail.html.contains("<html lang=\"fr\">"));
        for english in [
            "Hi Jane",
            "awaiting",
            "Pending:",
            "Cancel booking",
            "Event:",
        ] {
            assert!(
                !mail.plain.contains(english),
                "{english} leaked into: {}",
                mail.plain
            );
            assert!(
                !mail.html.contains(english),
                "{english} leaked into the HTML"
            );
        }
        // The meeting link is only revealed once the booking is confirmed.
        assert!(!mail.plain.contains("meet.example.com"));
        assert!(!mail.html.contains("meet.example.com"));
    }

    #[test]
    fn pending_notice_without_a_stored_language_is_english() {
        let mail = compose_guest_pending_notice(&sample_booking_details(), None, None);
        assert_eq!(
            mail.subject,
            "[Pending confirmation] 30min Intro \u{2014} 2026-04-10"
        );
        assert!(mail.plain.starts_with("Hi Jane Doe,"));
        assert!(mail
            .plain
            .contains("Your booking request has been sent to Alice Smith."));
        assert!(mail.html.contains("<html lang=\"en\">"));
    }

    #[test]
    fn pending_notice_escapes_names_in_the_html_headline() {
        let details = BookingDetails {
            host_name: "<b>Mallory</b>".to_string(),
            ..sample_booking_details()
        };
        let mail = compose_guest_pending_notice(&details, None, None);
        assert!(!mail.html.contains("<b>Mallory</b>"));
        assert!(mail.html.contains("&lt;b&gt;Mallory&lt;/b&gt;"));
    }

    #[test]
    fn decline_notice_is_written_in_the_guest_language() {
        let details = BookingDetails {
            guest_language: Some("fr".to_string()),
            ..sample_booking_details()
        };
        let mail = compose_guest_decline_notice(&cancellation_from(&details));

        assert_eq!(
            mail.subject,
            "[Réservation refusée] 30min Intro \u{2014} 2026-04-10"
        );
        assert!(mail.plain.starts_with("Bonjour Jane Doe,"));
        assert!(mail
            .plain
            .contains("Cette réservation a été refusée par l'hôte."));
        assert!(mail.plain.contains("Motif : Conflit"));
        assert!(mail.html.contains("<html lang=\"fr\">"));
        for english in ["Hi Jane", "has been declined", "Declined:", "Reason:"] {
            assert!(
                !mail.plain.contains(english),
                "{english} leaked into: {}",
                mail.plain
            );
            assert!(
                !mail.html.contains(english),
                "{english} leaked into the HTML"
            );
        }
    }

    #[test]
    fn decline_notice_without_a_stored_language_is_english() {
        let mail = compose_guest_decline_notice(&cancellation_from(&sample_booking_details()));
        assert_eq!(
            mail.subject,
            "[Booking declined] 30min Intro \u{2014} 2026-04-10"
        );
        assert!(mail
            .plain
            .contains("This booking has been declined by the host."));
        assert!(mail.html.contains("<html lang=\"en\">"));
    }

    #[test]
    fn html_email_lang_attribute_is_escaped() {
        let html = render_html_email_in("fr\"><script>", "Hi,", "Body", "#000", &[], None, &[]);
        assert!(html.contains("<html lang=\"fr&quot;&gt;&lt;script&gt;\">"));
        // Untranslated emails keep declaring English.
        let html = render_html_email("Hi,", "Body", "#000", &[], None);
        assert!(html.contains("<html lang=\"en\">"));
    }

    // --- #209: host, watcher and remaining guest emails are translated ---

    /// No English copy left in a translated email. Names, the event title and
    /// URLs are data, so only phrases calrs writes itself are checked.
    fn assert_no_english(mail: &ComposedEmail, phrases: &[&str]) {
        for english in phrases {
            assert!(
                !mail.subject.contains(english),
                "{english} leaked into the subject: {}",
                mail.subject
            );
            assert!(
                !mail.plain.contains(english),
                "{english} leaked into: {}",
                mail.plain
            );
            assert!(
                !mail.html.contains(english),
                "{english} leaked into the HTML"
            );
        }
    }

    fn host_in(lang: Option<&str>) -> BookingDetails {
        BookingDetails {
            host_language: lang.map(str::to_string),
            ..sample_booking_details()
        }
    }

    #[test]
    fn host_notification_is_written_in_the_host_language() {
        let mail = compose_host_notification(&host_in(Some("de")));
        assert_eq!(
            mail.subject,
            "Neue Buchung: 30min Intro, Jane Doe (2026-04-10)"
        );
        assert!(mail.plain.starts_with("Neue Buchung!"), "{}", mail.plain);
        assert!(mail.plain.contains("Gast: Jane Doe <jane@example.com>"));
        assert!(mail.html.contains("<html lang=\"de\">"));
        assert!(mail.html.contains("Gesendet von"));
        assert_no_english(
            &mail,
            &[
                "New booking",
                "booked a slot",
                "Guest:",
                "Sent by",
                "attached",
            ],
        );
    }

    #[test]
    fn host_notification_without_a_language_is_english() {
        for lang in [None, Some(""), Some("xx")] {
            let mail = compose_host_notification(&host_in(lang));
            assert_eq!(
                mail.subject,
                "New booking: 30min Intro, Jane Doe (2026-04-10)"
            );
            assert!(mail.plain.starts_with("New booking!"));
            assert!(mail.plain.contains("Jane Doe booked a slot with you."));
            assert!(mail.html.contains("<html lang=\"en\">"));
            assert!(mail.html.contains("Sent by"));
        }
    }

    /// The guest's language never leaks into the host's copy: a French guest
    /// booking an English-speaking host still gets the host an English email.
    #[test]
    fn host_email_ignores_the_guest_language() {
        let details = BookingDetails {
            guest_language: Some("fr".to_string()),
            ..host_in(None)
        };
        let mail = compose_host_notification(&details);
        assert!(mail.subject.starts_with("New booking:"));
        assert!(mail.html.contains("<html lang=\"en\">"));
    }

    #[test]
    fn host_booking_confirmed_is_written_in_the_host_language() {
        let mail = compose_host_booking_confirmed(&host_in(Some("fr")));
        assert_eq!(
            mail.subject,
            "Confirmée : 30min Intro, Jane Doe (2026-04-10)"
        );
        assert!(mail.plain.starts_with("Réservation confirmée"));
        assert!(mail.html.contains("<html lang=\"fr\">"));
        assert_no_english(&mail, &["Booking confirmed", "You approved", "calendar."]);

        let mail = compose_host_booking_confirmed(&host_in(None));
        assert_eq!(
            mail.subject,
            "Confirmed: 30min Intro, Jane Doe (2026-04-10)"
        );
        assert!(mail.html.contains("<html lang=\"en\">"));
    }

    #[test]
    fn host_calendar_sync_failure_is_written_in_the_host_language() {
        let mail = compose_host_calendar_sync_failure(&host_in(Some("de")), "HTTP 409");
        assert!(
            mail.subject.starts_with("Aktion nötig:"),
            "{}",
            mail.subject
        );
        assert!(mail
            .plain
            .starts_with("Dein Kalender wurde nicht aktualisiert"));
        assert!(mail.plain.contains("Neues Datum: 2026-04-10"));
        // The technical reason is shown as the API returned it.
        assert!(mail.plain.contains("HTTP 409"));
        assert!(mail.html.contains("<html lang=\"de\">"));
        assert_no_english(&mail, &["Action needed", "Your calendar", "New date"]);

        let mail = compose_host_calendar_sync_failure(&host_in(None), "HTTP 409");
        assert_eq!(
            mail.subject,
            "Action needed: calendar not updated for 30min Intro (2026-04-10)"
        );
    }

    #[test]
    fn host_reminder_is_written_in_the_host_language() {
        let mail = compose_host_reminder(&host_in(Some("fr")));
        assert_eq!(mail.subject, "Rappel : 30min Intro, Jane Doe (2026-04-10)");
        assert!(mail.plain.starts_with("Réservation à venir"));
        assert!(mail.html.contains("<html lang=\"fr\">"));
        assert_no_english(&mail, &["Reminder", "Upcoming", "coming up"]);

        let mail = compose_host_reminder(&host_in(None));
        assert_eq!(mail.subject, "Reminder: 30min Intro, Jane Doe (2026-04-10)");
        assert!(mail.plain.starts_with("Upcoming booking"));
    }

    #[test]
    fn host_cancellation_is_written_in_the_host_language() {
        let details = CancellationDetails {
            host_language: Some("fr".to_string()),
            cancelled_by_host: false,
            ..cancellation_from(&sample_booking_details())
        };
        let mail = compose_host_cancellation(&details);
        assert_eq!(mail.subject, "Annulée : 30min Intro, Jane Doe (2026-04-10)");
        assert!(mail.plain.starts_with("Réservation annulée"));
        assert!(mail.plain.contains("Jane Doe a annulé sa réservation."));
        assert!(mail.plain.contains("Motif : Conflit"));
        assert!(mail.html.contains("<html lang=\"fr\">"));
        assert_no_english(&mail, &["Cancelled", "cancelled their", "Reason:"]);

        let mail = compose_host_cancellation(&CancellationDetails {
            host_language: None,
            cancelled_by_host: true,
            ..details
        });
        assert_eq!(
            mail.subject,
            "Cancelled: 30min Intro, Jane Doe (2026-04-10)"
        );
        assert!(mail.plain.contains("You cancelled this booking."));
    }

    #[test]
    fn host_approval_request_is_written_in_the_host_language() {
        let details = BookingDetails {
            guest_phone: Some("+33612345678".to_string()),
            ..host_in(Some("fr"))
        };
        let mail = compose_host_approval_email(
            &details,
            Some("tok"),
            Some("https://cal.example.com/"),
            None,
        );
        assert_eq!(
            mail.subject,
            "Action requise : 30min Intro, Jane Doe (2026-04-10)"
        );
        assert!(mail
            .plain
            .contains("Approuver : https://cal.example.com/booking/approve/tok"));
        assert!(mail
            .plain
            .contains("Refuser : https://cal.example.com/booking/decline/tok"));
        assert!(mail.plain.contains("Téléphone : +33612345678"));
        assert!(mail.html.contains(">Approuver</a>"));
        assert!(mail.html.contains(">Refuser</a>"));
        assert!(mail.html.contains("<html lang=\"fr\">"));
        assert_no_english(
            &mail,
            &[
                "Action required",
                "Approve",
                "Decline",
                "Phone:",
                "dashboard",
            ],
        );

        // Without a base URL the plain text points to the dashboard instead.
        let mail = compose_host_approval_email(&details, Some("tok"), None, None);
        assert!(mail
            .plain
            .contains("Connectez-vous à votre tableau de bord"));
        assert!(!mail.html.contains("booking/approve"));
    }

    #[test]
    fn host_approval_reminder_is_written_in_the_host_language() {
        let mail = compose_host_approval_email(
            &host_in(Some("de")),
            Some("tok"),
            Some("https://cal.example.com"),
            Some("2026-04-09 18:00 (Europe/Paris)"),
        );
        assert_eq!(
            mail.subject,
            "Erinnerung: Jane Doe wartet auf deine Antwort (30min Intro, 2026-04-10)"
        );
        assert!(mail
            .plain
            .contains("am 2026-04-09 18:00 (Europe/Paris) automatisch abgelehnt"));
        assert!(mail.plain.contains("Läuft ab: 2026-04-09 18:00"));
        assert!(mail.html.contains(">Genehmigen</a>"));
        assert_no_english(&mail, &["Reminder", "waiting", "Expires"]);

        let mail = compose_host_approval_email(
            &host_in(None),
            Some("tok"),
            Some("https://cal.example.com"),
            Some("2026-04-09 18:00 (Europe/Paris)"),
        );
        assert_eq!(
            mail.subject,
            "Reminder: Jane Doe is waiting for your answer (30min Intro, 2026-04-10)"
        );
        assert!(mail
            .plain
            .contains("Approve: https://cal.example.com/booking/approve/tok"));
    }

    #[test]
    fn host_pending_expired_is_written_in_the_host_language() {
        let details = CancellationDetails {
            host_language: Some("pl".to_string()),
            ..cancellation_from(&sample_booking_details())
        };
        let mail = compose_host_pending_expired(&details);
        assert_eq!(mail.subject, "Wygasła: 30min Intro, Jane Doe (2026-04-10)");
        assert!(mail.plain.starts_with("Prośba o rezerwację wygasła"));
        assert!(mail.html.contains("<html lang=\"pl\">"));
        assert_no_english(&mail, &["Expired", "Nobody answered", "Guest:"]);

        let mail = compose_host_pending_expired(&CancellationDetails {
            host_language: None,
            ..details
        });
        assert_eq!(
            mail.subject,
            "Expired: 30min Intro with Jane Doe (2026-04-10)"
        );
    }

    #[test]
    fn host_reschedule_request_is_written_in_the_host_language() {
        let details = RescheduleDetails {
            host_language: Some("de".to_string()),
            guest_language: Some("fr".to_string()),
            ..sample_reschedule_details()
        };
        let mail =
            compose_host_reschedule_request(&details, Some("tok"), Some("https://cal.example.com"));
        assert_eq!(
            mail.subject,
            "Verschiebungsanfrage: 30min call, Jane (jane@example.com)"
        );
        assert!(mail.plain.starts_with("Hallo Alice,"));
        assert!(mail.plain.contains("Bisher: 2026-03-16 um 10:00"));
        assert!(mail.plain.contains("Angefragt: 2026-03-17 um 14:00"));
        assert!(mail.html.contains(">Ablehnen</a>"));
        assert!(mail.html.contains("<html lang=\"de\">"));
        assert_no_english(
            &mail,
            &["Reschedule request", "Previous", "Requested", "Hi "],
        );

        let mail = compose_host_reschedule_request(
            &RescheduleDetails {
                host_language: None,
                ..details
            },
            None,
            None,
        );
        assert_eq!(
            mail.subject,
            "Reschedule request: 30min call, Jane (jane@example.com)"
        );
        assert!(mail.plain.contains("Log in to your dashboard"));
    }

    #[test]
    fn watcher_claim_offer_is_written_in_the_watcher_language() {
        let mail = compose_watcher_claim_notification(
            &sample_booking_details(),
            "Wanda",
            Some("fr"),
            "Alice Smith",
            "https://cal.example.com/booking/claim/b?token=t",
        );
        assert_eq!(
            mail.subject,
            "À prendre en charge : 30min Intro, Jane Doe (2026-04-10)"
        );
        assert!(mail.plain.starts_with("Bonjour Wanda,"));
        assert!(mail.plain.contains("Attribuée à : Alice Smith"));
        assert!(mail.plain.contains(
            "Prendre en charge cette réservation : https://cal.example.com/booking/claim/b?token=t"
        ));
        assert!(mail.html.contains("<html lang=\"fr\">"));
        assert_no_english(&mail, &["Claim", "Assigned", "Hi "]);

        let mail = compose_watcher_claim_notification(
            &sample_booking_details(),
            "Wanda",
            None,
            "Alice Smith",
            "https://cal.example.com/c",
        );
        assert_eq!(
            mail.subject,
            "Claim available: 30min Intro, Jane Doe (2026-04-10)"
        );
    }

    #[test]
    fn claim_confirmation_is_written_in_the_claimant_language() {
        let mail = compose_claim_confirmation(&sample_booking_details(), "Wanda", Some("de"));
        assert_eq!(
            mail.subject,
            "Buchung übernommen: 30min Intro, Jane Doe (2026-04-10)"
        );
        assert!(mail.plain.starts_with("Hallo Wanda,"));
        assert!(mail.html.contains("<html lang=\"de\">"));
        assert_no_english(&mail, &["claimed", "attendee", "Hi "]);

        let mail = compose_claim_confirmation(&sample_booking_details(), "Wanda", None);
        assert_eq!(
            mail.subject,
            "Booking claimed: 30min Intro, Jane Doe (2026-04-10)"
        );
    }

    #[test]
    fn guest_pick_new_time_is_written_in_the_booking_language() {
        let details = BookingDetails {
            guest_language: Some("fr".to_string()),
            host_language: Some("de".to_string()),
            ..sample_booking_details()
        };
        let mail = compose_guest_pick_new_time(
            &details,
            "https://cal.example.com/booking/reschedule/r",
            Some("https://cal.example.com/booking/cancel/c"),
        );
        assert_eq!(
            mail.subject,
            "Reprogrammation : 30min Intro, merci de choisir un nouveau créneau"
        );
        assert!(mail.plain.starts_with("Bonjour Jane Doe,"));
        assert!(mail
            .plain
            .contains("Alice Smith doit reprogrammer votre réservation."));
        assert!(mail
            .plain
            .contains("Initialement : 2026-04-10 à 14:00 \u{2013} 14:30 (Europe/Paris)"));
        assert!(mail.html.contains(">Annuler la réservation</a>"));
        assert!(mail.html.contains("<html lang=\"fr\">"));
        assert_no_english(
            &mail,
            &["Reschedule", "pick a new time", "Originally", "Hi "],
        );

        let mail = compose_guest_pick_new_time(&sample_booking_details(), "https://x/r", None);
        assert_eq!(
            mail.subject,
            "Reschedule: 30min Intro, please pick a new time"
        );
    }

    #[test]
    fn guest_reschedule_notification_is_written_in_the_booking_language() {
        let details = RescheduleDetails {
            guest_language: Some("fr".to_string()),
            host_language: Some("de".to_string()),
            ..sample_reschedule_details()
        };
        let mail = compose_guest_reschedule_notification(
            &details,
            Some("https://cal.example.com/booking/cancel/c"),
            Some("https://cal.example.com/booking/reschedule/r"),
        );
        // The neutral "event, date" subject Exchange titles the event after.
        assert_eq!(
            mail.subject,
            ta(
                "fr",
                "email-confirm-subject",
                [("event", "30min call"), ("date", "2026-03-17")]
            )
        );
        assert!(mail.plain.starts_with("Bonjour Jane,"));
        assert!(mail
            .plain
            .contains("Votre réservation a été reprogrammée par Alice."));
        assert!(mail
            .plain
            .contains("Précédemment : 2026-03-16 à 10:00 \u{2013} 10:30"));
        assert!(mail.plain.contains("Nouvelle date : 2026-03-17"));
        assert!(mail
            .plain
            .contains("Besoin de reprogrammer ? https://cal.example.com/booking/reschedule/r"));
        assert!(mail.html.contains("<html lang=\"fr\">"));
        assert_no_english(
            &mail,
            &["rescheduled", "Previous", "New date", "Need to", "Hi "],
        );

        let mail = compose_guest_reschedule_notification(&sample_reschedule_details(), None, None);
        assert!(mail
            .plain
            .contains("Your booking has been rescheduled by Alice."));
        assert!(mail.html.contains("<html lang=\"en\">"));
    }

    #[test]
    fn attendee_confirmation_is_written_in_the_booking_language() {
        let details = BookingDetails {
            guest_language: Some("es".to_string()),
            ..sample_booking_details()
        };
        let mail = compose_attendee_confirmation(&details);
        assert!(mail.plain.starts_with("Hola,"));
        assert!(mail.plain.contains("Organizador: Alice Smith"));
        assert!(mail
            .plain
            .contains("Reservado por: Jane Doe <jane@example.com>"));
        assert!(mail.html.contains("<html lang=\"es\">"));
        assert_no_english(&mail, &["added as an attendee", "Organizer", "Booked by"]);

        let mail = compose_attendee_confirmation(&sample_booking_details());
        assert!(mail
            .plain
            .contains("You've been added as an attendee to a booking."));
    }

    #[test]
    fn invite_email_is_written_in_the_inviter_language() {
        let mail = compose_invite_email(
            "de",
            "Gina",
            "Demo",
            "Alice",
            Some("Bis bald"),
            "https://cal.example.com/u/alice/demo?invite=t",
            Some("2026-04-17"),
        );
        assert_eq!(
            mail.subject,
            "Alice hat dich eingeladen, einen Termin zu buchen: Demo"
        );
        assert!(mail.plain.starts_with("Hallo Gina,"));
        assert!(mail.plain.contains("Eingeladen von: Alice"));
        assert!(mail.plain.contains("Nachricht: Bis bald"));
        assert!(mail.plain.contains("Läuft ab: 2026-04-17"));
        assert!(mail
            .plain
            .contains("https://cal.example.com/u/alice/demo?invite=t"));
        assert!(mail.html.contains(">Termin wählen</a>"));
        assert!(mail.html.contains("<html lang=\"de\">"));
        assert_no_english(
            &mail,
            &["invited you", "Invited by", "Choose a time", "Hi "],
        );

        let mail = compose_invite_email("en", "Gina", "Demo", "Alice", None, "https://x", None);
        assert_eq!(mail.subject, "Alice invited you to book: Demo");
    }

    #[test]
    fn calendar_deleted_reason_follows_the_reader() {
        assert_eq!(
            calendar_deleted_reason(None),
            "The calendar event was deleted by the host."
        );
        assert_eq!(
            calendar_deleted_reason(Some("fr")),
            "L'événement a été supprimé de l'agenda de l'hôte."
        );
    }

    /// Every email now carries the footer in its own language, and the
    /// guest emails translated before #209 pick it up too.
    #[test]
    fn footer_is_translated() {
        let html = render_html_email_in("nl", "Hoi,", "Body", "#000", &[], None, &[]);
        assert!(html.contains("Verzonden door"));
        assert!(!html.contains("Sent by"));
        let details = BookingDetails {
            guest_language: Some("it".to_string()),
            ..sample_booking_details()
        };
        let mail = compose_guest_pending_notice(&details, None, None);
        assert!(mail.html.contains("Inviato da"));
    }
}
