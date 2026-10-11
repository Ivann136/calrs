//! Tests for the email module. Shared fixtures live here; each child
//! module covers one area and reaches them, and every item of `email`,
//! through `use super::*`.

use lettre::Address;

use super::*;

mod transport;

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
    assert!(caldav
        .contains("ATTENDEE;SCHEDULE-AGENT=CLIENT;CN=Jane Doe;RSVP=TRUE:mailto:jane@example.com"));
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
    assert!(
        convert_time_between_tz("2026-05-26", "07:00", "07:30", "Not/A/Zone", "Europe/Paris")
            .is_none()
    );
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

    let html = render_html_email_with_actions("Hi,", "Reminder.", "#3b82f6", &[], None, &actions);
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
