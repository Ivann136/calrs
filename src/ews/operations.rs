//! High-level EWS operations: list calendar folders, fetch / create / delete
//! calendar items, run an incremental sync.
//!
//! Each function builds a SOAP body, posts it via [`super::soap::post_soap`],
//! and parses the response with helpers from [`super::parse`]. Operations are
//! kept narrow on purpose — calrs only exercises a small slice of the EWS
//! surface.

use anyhow::{bail, Context, Result};

use super::parse::{
    parse_calendar_items_response, parse_create_item_response, parse_find_folder_response,
    parse_get_item_response, parse_sync_folder_items_response, EwsCalendarFolder, EwsCalendarItem,
    EwsSyncDelta,
};
use super::soap::{escape, post_soap};

/// Issue a `GetFolder` against `inbox` to confirm that the credentials are
/// valid and the endpoint speaks EWS. The folder is purely a convenience pick
/// — every Exchange mailbox has it.
pub async fn check_connection(endpoint: &str, username: &str, password: &str) -> Result<bool> {
    let body = r#"    <m:GetFolder>
      <m:FolderShape>
        <t:BaseShape>IdOnly</t:BaseShape>
      </m:FolderShape>
      <m:FolderIds>
        <t:DistinguishedFolderId Id="inbox" />
      </m:FolderIds>
    </m:GetFolder>
"#;
    let resp = post_soap(endpoint, username, password, body, false).await?;
    // post_soap already raises on SOAP faults; we only need to confirm the
    // response carries a real folder reference (or, as a softer fallback, the
    // standard Success class) before declaring the endpoint EWS-compatible.
    if resp.contains("FolderId") || resp.contains("ResponseClass=\"Success\"") {
        Ok(true)
    } else {
        bail!("EWS GetFolder returned no FolderId — server may not be EWS-compatible")
    }
}

/// Enumerate the user's calendar folders by walking down from
/// `msgfolderroot`. We restrict to `IPF.Appointment` containers.
pub async fn list_calendar_folders(
    endpoint: &str,
    username: &str,
    password: &str,
) -> Result<Vec<EwsCalendarFolder>> {
    let body = r#"    <m:FindFolder Traversal="Deep">
      <m:FolderShape>
        <t:BaseShape>Default</t:BaseShape>
        <t:AdditionalProperties>
          <t:FieldURI FieldURI="folder:FolderClass" />
          <t:FieldURI FieldURI="folder:DisplayName" />
        </t:AdditionalProperties>
      </m:FolderShape>
      <m:Restriction>
        <t:IsEqualTo>
          <t:FieldURI FieldURI="folder:FolderClass" />
          <t:FieldURIOrConstant>
            <t:Constant Value="IPF.Appointment" />
          </t:FieldURIOrConstant>
        </t:IsEqualTo>
      </m:Restriction>
      <m:ParentFolderIds>
        <t:DistinguishedFolderId Id="msgfolderroot" />
      </m:ParentFolderIds>
    </m:FindFolder>
"#;
    let resp = post_soap(endpoint, username, password, body, false).await?;
    parse_find_folder_response(&resp)
}

/// Fetch every calendar item in a folder. Uses paging
/// (`IndexedPageItemView`) with a max page size to avoid OOM on busy
/// mailboxes.
pub async fn list_items(
    endpoint: &str,
    username: &str,
    password: &str,
    folder_id: &str,
) -> Result<Vec<EwsCalendarItem>> {
    list_items_window(endpoint, username, password, folder_id, None, None).await
}

/// Fetch calendar items overlapping `[start, end)`. Both bounds are RFC 3339
/// UTC strings (e.g. `2026-05-06T00:00:00Z`). EWS exposes this as a
/// `CalendarView` query, which expands recurring series into their
/// occurrences in the window — handy for booking slot computation.
pub async fn list_items_in_window(
    endpoint: &str,
    username: &str,
    password: &str,
    folder_id: &str,
    start_utc: &str,
    end_utc: &str,
) -> Result<Vec<EwsCalendarItem>> {
    list_items_window(
        endpoint,
        username,
        password,
        folder_id,
        Some(start_utc),
        Some(end_utc),
    )
    .await
}

const PAGE_SIZE: u32 = 200;

async fn list_items_window(
    endpoint: &str,
    username: &str,
    password: &str,
    folder_id: &str,
    start_utc: Option<&str>,
    end_utc: Option<&str>,
) -> Result<Vec<EwsCalendarItem>> {
    let mut all = Vec::new();
    let mut offset: u32 = 0;
    loop {
        let view = if let (Some(s), Some(e)) = (start_utc, end_utc) {
            // CalendarView expands recurrences; no offset paging is needed
            // because EWS returns up to 1000 items in one shot for a window.
            format!(
                r#"<m:CalendarView MaxEntriesReturned="1000" StartDate="{s}" EndDate="{e}" />"#,
                s = escape(s),
                e = escape(e),
            )
        } else {
            format!(
                r#"<m:IndexedPageItemView MaxEntriesReturned="{PAGE_SIZE}" Offset="{offset}" BasePoint="Beginning" />"#,
            )
        };

        let body = format!(
            r#"    <m:FindItem Traversal="Shallow">
      <m:ItemShape>
        <t:BaseShape>IdOnly</t:BaseShape>
        <t:AdditionalProperties>
          <t:FieldURI FieldURI="item:Subject" />
          <t:FieldURI FieldURI="calendar:Start" />
          <t:FieldURI FieldURI="calendar:End" />
          <t:FieldURI FieldURI="calendar:Location" />
          <t:FieldURI FieldURI="calendar:UID" />
          <t:FieldURI FieldURI="calendar:LegacyFreeBusyStatus" />
          <t:FieldURI FieldURI="calendar:IsAllDayEvent" />
          <t:FieldURI FieldURI="calendar:IsCancelled" />
          <t:FieldURI FieldURI="calendar:Recurrence" />
          <t:FieldURI FieldURI="calendar:CalendarItemType" />
        </t:AdditionalProperties>
      </m:ItemShape>
      {view}
      <m:ParentFolderIds>
        <t:FolderId Id="{folder}" />
      </m:ParentFolderIds>
    </m:FindItem>
"#,
            folder = escape(folder_id),
        );
        let resp = post_soap(endpoint, username, password, &body, true).await?;
        let mut page = parse_calendar_items_response(&resp)?;

        let included = page.included_count;
        let total = page.total;
        all.append(&mut page.items);

        // CalendarView returns everything in one shot.
        if start_utc.is_some() {
            break;
        }
        if included == 0 {
            break;
        }
        offset += included as u32;
        if let Some(t) = total {
            if offset >= t as u32 {
                break;
            }
        } else if (included as u32) < PAGE_SIZE {
            break;
        }
    }
    tracing::debug!(folder = %folder_id, count = all.len(), "EWS FindItem complete");
    Ok(all)
}

/// Fetch the MIME (RFC 5322 + iCalendar) representation of one or more items.
/// Returns the items in the same order, dropping any that the server failed
/// to retrieve.
pub async fn get_items_mime(
    endpoint: &str,
    username: &str,
    password: &str,
    item_ids: &[&str],
) -> Result<Vec<(String, String)>> {
    if item_ids.is_empty() {
        return Ok(Vec::new());
    }
    let mut id_xml = String::new();
    for id in item_ids {
        id_xml.push_str(&format!(
            r#"        <t:ItemId Id="{}" />
"#,
            escape(id)
        ));
    }
    let body = format!(
        r#"    <m:GetItem>
      <m:ItemShape>
        <t:BaseShape>IdOnly</t:BaseShape>
        <t:IncludeMimeContent>true</t:IncludeMimeContent>
        <t:AdditionalProperties>
          <t:FieldURI FieldURI="calendar:UID" />
        </t:AdditionalProperties>
      </m:ItemShape>
      <m:ItemIds>
{id_xml}      </m:ItemIds>
    </m:GetItem>
"#,
    );
    let resp = post_soap(endpoint, username, password, &body, true).await?;
    parse_get_item_response(&resp)
}

/// Create a calendar item from an iCalendar payload. Exchange will store the
/// MIME blob and surface the event natively via OWA / Outlook.
///
/// `SendMeetingInvitations="SendToNone"` keeps the call non-disruptive — calrs
/// drives invitations through SMTP separately and does not want EWS to fire
/// off duplicate invites on every booking.
pub async fn create_item_from_ics(
    endpoint: &str,
    username: &str,
    password: &str,
    folder_id: &str,
    ics: &str,
) -> Result<String> {
    use base64::Engine;
    let mime = base64::engine::general_purpose::STANDARD.encode(ics.as_bytes());

    let body = format!(
        r#"    <m:CreateItem MessageDisposition="SaveOnly" SendMeetingInvitations="SendToNone">
      <m:SavedItemFolderId>
        <t:FolderId Id="{folder}" />
      </m:SavedItemFolderId>
      <m:Items>
        <t:CalendarItem>
          <t:MimeContent CharacterSet="UTF-8">{mime}</t:MimeContent>
        </t:CalendarItem>
      </m:Items>
    </m:CreateItem>
"#,
        folder = escape(folder_id),
    );
    let resp = post_soap(endpoint, username, password, &body, true).await?;
    let item_id = parse_create_item_response(&resp)?;
    Ok(item_id)
}

/// Find calendar items that match a specific iCalendar UID. EWS exposes
/// `calendar:UID` as a searchable field; the result is usually 0 or 1 item.
///
/// Some Exchange versions refuse `calendar:UID` inside a `Restriction` with
/// `ErrorUnsupportedPathForQuery` (#179). On that fault, and only on the
/// query-shape faults listed in [`is_unsupported_restriction_fault`], the
/// lookup falls back to [`find_items_by_uid_in_calendar_view`]. Auth and
/// transport errors, and any other fault, propagate unchanged.
pub async fn find_items_by_uid(
    endpoint: &str,
    username: &str,
    password: &str,
    folder_id: &str,
    uid: &str,
) -> Result<Vec<String>> {
    let body = format!(
        r#"    <m:FindItem Traversal="Shallow">
      <m:ItemShape>
        <t:BaseShape>IdOnly</t:BaseShape>
      </m:ItemShape>
      <m:Restriction>
        <t:IsEqualTo>
          <t:FieldURI FieldURI="calendar:UID" />
          <t:FieldURIOrConstant>
            <t:Constant Value="{uid}" />
          </t:FieldURIOrConstant>
        </t:IsEqualTo>
      </m:Restriction>
      <m:ParentFolderIds>
        <t:FolderId Id="{folder}" />
      </m:ParentFolderIds>
    </m:FindItem>
"#,
        uid = escape(uid),
        folder = escape(folder_id),
    );
    let resp = match post_soap(endpoint, username, password, &body, false).await {
        Ok(resp) => resp,
        Err(e) if is_unsupported_restriction_fault(&e.to_string()) => {
            tracing::info!(
                uid = %uid,
                error = %e,
                "EWS refused the calendar:UID restriction, scanning a CalendarView instead"
            );
            return find_items_by_uid_in_calendar_view(
                endpoint, username, password, folder_id, uid,
            )
            .await;
        }
        Err(e) => return Err(e),
    };
    let parsed = parse_calendar_items_response(&resp)?;
    Ok(parsed.items.into_iter().map(|i| i.item_id).collect())
}

/// SOAP fault codes that mean "this server cannot run the restricted
/// FindItem", as opposed to "this request is not allowed" or "this folder is
/// gone". Only these trigger the CalendarView fallback.
const UNSUPPORTED_RESTRICTION_FAULTS: &[&str] = &[
    "ErrorUnsupportedPathForQuery",
    "ErrorUnsupportedQueryFilter",
    "ErrorInvalidRestriction",
];

/// Whether an error raised by [`post_soap`] is a SOAP fault whose code says
/// the restriction itself is unsupported. `post_soap` formats faults as
/// `EWS SOAP fault: <Code>: <MessageText>`; 401s and transport failures carry
/// a different message and never match.
fn is_unsupported_restriction_fault(message: &str) -> bool {
    let Some(fault) = message.strip_prefix(super::soap::SOAP_FAULT_PREFIX) else {
        return false;
    };
    let code = fault.split(':').next().unwrap_or("").trim();
    UNSUPPORTED_RESTRICTION_FAULTS.contains(&code)
}

/// How far back and forward the fallback scan looks. The booking horizon is
/// capped at 365 days, so a calrs-written item lives inside this window.
const UID_SCAN_PAST_DAYS: i64 = 30;
const UID_SCAN_FUTURE_DAYS: i64 = 400;
/// Width of one CalendarView request. A CalendarView returns at most 1000
/// entries, so the window is split to keep each request well under that on a
/// busy calendar.
const UID_SCAN_CHUNK_DAYS: i64 = 60;
/// Exchange truncates a CalendarView at this many entries, silently.
const CALENDAR_VIEW_CAP: usize = 1000;
/// A window at the cap is halved and both halves scanned again, down to this
/// width. A window this narrow still at the cap is reported as an error, since
/// an empty result would read as "the event is gone".
const UID_SCAN_MIN_WINDOW_HOURS: i64 = 24;

/// Fallback for [`find_items_by_uid`]: walk the folder with CalendarView
/// requests that carry `calendar:UID`, and filter by UID in memory.
async fn find_items_by_uid_in_calendar_view(
    endpoint: &str,
    username: &str,
    password: &str,
    folder_id: &str,
    uid: &str,
) -> Result<Vec<String>> {
    let now = chrono::Utc::now();
    let start = now - chrono::Duration::days(UID_SCAN_PAST_DAYS);
    let end = now + chrono::Duration::days(UID_SCAN_FUTURE_DAYS);
    scan_windows_for_uid(
        start,
        end,
        uid,
        CALENDAR_VIEW_CAP,
        chrono::Duration::hours(UID_SCAN_MIN_WINDOW_HOURS),
        |s, e| async move {
            list_items_in_window(
                endpoint,
                username,
                password,
                folder_id,
                &s.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                &e.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            )
            .await
        },
    )
    .await
}

/// Scan `[start, end)` in [`UID_SCAN_CHUNK_DAYS`] chunks, oldest first, and
/// stop at the first window holding `uid`, since calrs writes each booking as
/// a single item. A window that comes back with `cap` entries or more may have
/// been truncated by the server, so it is split in half and both halves are
/// scanned (oldest first) instead, recursively. A window no wider than
/// `min_window` that is still at the cap is an error: returning an empty
/// result there would let a caller conclude the item does not exist.
async fn scan_windows_for_uid<F, Fut>(
    start: chrono::DateTime<chrono::Utc>,
    end: chrono::DateTime<chrono::Utc>,
    uid: &str,
    cap: usize,
    min_window: chrono::Duration,
    mut fetch: F,
) -> Result<Vec<String>>
where
    F: FnMut(chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<EwsCalendarItem>>>,
{
    // Windows still to scan, the next one on top of the stack.
    let mut chunks = Vec::new();
    let mut chunk_start = start;
    while chunk_start < end {
        let chunk_end = (chunk_start + chrono::Duration::days(UID_SCAN_CHUNK_DAYS)).min(end);
        chunks.push((chunk_start, chunk_end));
        chunk_start = chunk_end;
    }
    chunks.reverse();

    while let Some((s, e)) = chunks.pop() {
        let items = fetch(s, e).await?;
        // A match is a match even in a truncated window.
        let found = item_ids_with_uid(&items, uid);
        if !found.is_empty() {
            return Ok(found);
        }
        if items.len() >= cap {
            if e - s <= min_window {
                bail!(
                    "EWS CalendarView from {s} to {e} returned {} entries, the server cap; \
                     the UID scan cannot tell whether the item exists",
                    items.len()
                );
            }
            let mid = s + (e - s) / 2;
            tracing::debug!(%s, %e, "EWS CalendarView hit its entry cap, splitting the window");
            chunks.push((mid, e));
            chunks.push((s, mid));
        }
    }
    Ok(Vec::new())
}

/// Item ids whose `calendar:UID` equals `uid`, deduplicated in order. A
/// CalendarView lists each occurrence of a recurring series separately, and
/// overlapping requests can return the same single item twice.
fn item_ids_with_uid(items: &[EwsCalendarItem], uid: &str) -> Vec<String> {
    let escaped = escape(uid);
    let mut ids: Vec<String> = Vec::new();
    for item in items {
        let matches = item
            .uid
            .as_deref()
            .is_some_and(|u| u == uid || u == escaped);
        if matches && !ids.contains(&item.item_id) {
            ids.push(item.item_id.clone());
        }
    }
    ids
}

/// Permanently delete an item by id. We use `HardDelete` because the
/// alternative (`MoveToDeletedItems`) would leave a tombstone in Trash that
/// can confuse free/busy on shared calendars.
pub async fn delete_item(
    endpoint: &str,
    username: &str,
    password: &str,
    item_id: &str,
) -> Result<()> {
    let body = format!(
        r#"    <m:DeleteItem DeleteType="HardDelete" SendMeetingCancellations="SendToNone">
      <m:ItemIds>
        <t:ItemId Id="{id}" />
      </m:ItemIds>
    </m:DeleteItem>
"#,
        id = escape(item_id),
    );
    let _ = post_soap(endpoint, username, password, &body, false).await?;
    Ok(())
}

/// Run a delta sync (`SyncFolderItems`).
///
/// `sync_state` is the opaque cursor returned by the previous call (or
/// `None` for the initial sync). We request `MaxChangesReturned=512` and
/// loop until the server reports `IncludesLastItemInRange=true`, with a
/// hard cap of `MAX_SYNC_PAGES` iterations as insurance against a server
/// that never sets the terminator (200 pages × 512 changes = 102 400
/// items, far above any realistic mailbox).
pub async fn sync_folder_items(
    endpoint: &str,
    username: &str,
    password: &str,
    folder_id: &str,
    sync_state: Option<&str>,
) -> Result<EwsSyncDelta> {
    const MAX_SYNC_PAGES: usize = 200;
    let mut state = sync_state.map(str::to_string);
    let mut all = EwsSyncDelta::default();
    for _ in 0..MAX_SYNC_PAGES {
        let state_xml = state
            .as_deref()
            .map(|s| format!("      <m:SyncState>{}</m:SyncState>\n", escape(s)))
            .unwrap_or_default();
        let body = format!(
            r#"    <m:SyncFolderItems>
      <m:ItemShape>
        <t:BaseShape>IdOnly</t:BaseShape>
        <t:AdditionalProperties>
          <t:FieldURI FieldURI="calendar:UID" />
        </t:AdditionalProperties>
      </m:ItemShape>
      <m:SyncFolderId>
        <t:FolderId Id="{folder}" />
      </m:SyncFolderId>
{state_xml}      <m:MaxChangesReturned>512</m:MaxChangesReturned>
      <m:SyncScope>NormalItems</m:SyncScope>
    </m:SyncFolderItems>
"#,
            folder = escape(folder_id),
        );
        let resp = post_soap(endpoint, username, password, &body, true).await?;
        let page = parse_sync_folder_items_response(&resp)
            .context("failed to parse SyncFolderItems response")?;

        all.added_or_changed.extend(page.added_or_changed);
        all.deleted_uids.extend(page.deleted_uids);
        all.deleted_item_ids.extend(page.deleted_item_ids);
        all.new_sync_state = page.new_sync_state;
        state = all.new_sync_state.clone();

        if page.includes_last {
            return Ok(all);
        }
    }
    // Hit the safety cap without seeing IncludesLastItemInRange=true: either
    // the server is broken or the mailbox is genuinely enormous. Return what
    // we have plus the latest cursor so the next sync can resume.
    tracing::warn!(
        folder_id = %folder_id,
        pages = MAX_SYNC_PAGES,
        "SyncFolderItems hit the safety cap without IncludesLastItemInRange=true; \
         returning partial result, next sync will resume from cursor"
    );
    Ok(all)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ews::soap::{extract_soap_fault, SOAP_FAULT_PREFIX};

    /// The response from #179, trimmed to the parts `post_soap` reads.
    const UNSUPPORTED_PATH_RESPONSE: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <m:FindItemResponse xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
      <m:ResponseMessages>
        <m:FindItemResponseMessage ResponseClass="Error">
          <m:MessageText>Die Eigenschaft darf nicht mit diesem Einschränkungstyp verwendet werden.</m:MessageText>
          <m:ResponseCode>ErrorUnsupportedPathForQuery</m:ResponseCode>
          <m:DescriptiveLinkKey>0</m:DescriptiveLinkKey>
        </m:FindItemResponseMessage>
      </m:ResponseMessages>
    </m:FindItemResponse>
  </s:Body>
</s:Envelope>"#;

    #[test]
    fn unsupported_path_fault_triggers_the_fallback() {
        let fault = extract_soap_fault(UNSUPPORTED_PATH_RESPONSE).expect("a fault");
        let message = format!("{SOAP_FAULT_PREFIX}{fault}");
        assert!(is_unsupported_restriction_fault(&message), "{message}");
    }

    #[test]
    fn other_errors_do_not_trigger_the_fallback() {
        for message in [
            "EWS authentication failed (401). Check username/password.",
            "EWS request to https://ex.example.com/EWS/Exchange.asmx failed",
            "EWS SOAP fault: ErrorAccessDenied: Access is denied.",
            "EWS SOAP fault: ErrorFolderNotFound",
            "ErrorUnsupportedPathForQuery without the fault prefix",
        ] {
            assert!(!is_unsupported_restriction_fault(message), "{message}");
        }
        assert!(is_unsupported_restriction_fault(
            "EWS SOAP fault: ErrorInvalidRestriction"
        ));
    }

    fn item(id: &str, uid: Option<&str>) -> EwsCalendarItem {
        EwsCalendarItem {
            item_id: id.to_string(),
            change_key: None,
            uid: uid.map(str::to_string),
            subject: None,
            start: None,
            end: None,
            location: None,
            is_all_day: false,
            is_cancelled: false,
            free_busy_status: None,
            has_recurrence: false,
        }
    }

    #[test]
    fn calendar_view_items_are_filtered_by_uid_and_deduplicated() {
        let items = vec![
            item("A", Some("other@calrs")),
            item("B", Some("73c8e55c@calrs")),
            item("C", None),
            item("B", Some("73c8e55c@calrs")),
            item("D", Some("73c8e55c@calrs")),
        ];
        assert_eq!(item_ids_with_uid(&items, "73c8e55c@calrs"), ["B", "D"]);
        assert!(item_ids_with_uid(&items, "missing@calrs").is_empty());
    }

    /// A fake CalendarView over items placed at fixed instants: returns the
    /// items inside `[s, e)`, truncated to `cap` like Exchange does, and
    /// records every window requested.
    fn fake_view(
        items: Vec<(chrono::DateTime<chrono::Utc>, EwsCalendarItem)>,
        cap: usize,
        calls: &std::cell::RefCell<
            Vec<(chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)>,
        >,
        s: chrono::DateTime<chrono::Utc>,
        e: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<EwsCalendarItem>> {
        calls.borrow_mut().push((s, e));
        Ok(items
            .into_iter()
            .filter(|(at, _)| *at >= s && *at < e)
            .map(|(_, i)| i)
            .take(cap)
            .collect())
    }

    #[tokio::test]
    async fn uid_scan_splits_a_truncated_window_until_it_finds_the_item() {
        use chrono::TimeZone;
        let start = chrono::Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let end = start + chrono::Duration::days(60);
        // Twelve busy items, six in each half, push the chunk past the cap
        // of 10, so the target near its end is truncated away. Each half on
        // its own stays under the cap.
        let mut items: Vec<_> = (0..12)
            .map(|n| {
                let at = start + chrono::Duration::days(n % 6 + 31 * (n / 6));
                (at, item(&format!("busy{n}"), Some("other@calrs")))
            })
            .collect();
        items.push((
            start + chrono::Duration::days(50),
            item("TARGET", Some("wanted@calrs")),
        ));
        let calls = std::cell::RefCell::new(Vec::new());
        let found = scan_windows_for_uid(
            start,
            end,
            "wanted@calrs",
            10,
            chrono::Duration::days(1),
            |s, e| {
                let r = fake_view(items.clone(), 10, &calls, s, e);
                async move { r }
            },
        )
        .await
        .unwrap();
        assert_eq!(found, ["TARGET"]);
        let calls = calls.into_inner();
        assert_eq!(calls[0], (start, end), "the whole chunk is tried first");
        assert_eq!(
            calls[1],
            (start, start + chrono::Duration::days(30)),
            "then its older half"
        );
        assert_eq!(calls[2], (start + chrono::Duration::days(30), end));
    }

    #[tokio::test]
    async fn uid_scan_errors_instead_of_reporting_not_found_when_still_truncated() {
        use chrono::TimeZone;
        let start = chrono::Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let end = start + chrono::Duration::days(60);
        // Ten items inside the same minute: no split can get below the cap.
        let items: Vec<_> = (0..10)
            .map(|n| {
                let at = start + chrono::Duration::seconds(n);
                (at, item(&format!("busy{n}"), Some("other@calrs")))
            })
            .collect();
        let calls = std::cell::RefCell::new(Vec::new());
        let result = scan_windows_for_uid(
            start,
            end,
            "wanted@calrs",
            10,
            chrono::Duration::days(1),
            |s, e| {
                let r = fake_view(items.clone(), 10, &calls, s, e);
                async move { r }
            },
        )
        .await;
        let err = result.expect_err("a truncated minimum window must not read as not found");
        assert!(err.to_string().contains("cap"), "{err}");
        let last = *calls.borrow().last().unwrap();
        assert!(last.1 - last.0 <= chrono::Duration::days(1));
    }

    #[tokio::test]
    async fn uid_scan_returns_empty_when_no_window_is_truncated() {
        use chrono::TimeZone;
        let start = chrono::Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let end = start + chrono::Duration::days(130);
        let items = vec![(start, item("A", Some("other@calrs")))];
        let calls = std::cell::RefCell::new(Vec::new());
        let found = scan_windows_for_uid(
            start,
            end,
            "wanted@calrs",
            10,
            chrono::Duration::days(1),
            |s, e| {
                let r = fake_view(items.clone(), 10, &calls, s, e);
                async move { r }
            },
        )
        .await
        .unwrap();
        assert!(found.is_empty());
        // 130 days in 60-day chunks, oldest first, no splitting.
        assert_eq!(calls.borrow().len(), 3);
        assert_eq!(calls.borrow()[2].1, end);
    }

    #[test]
    fn calendar_view_response_is_filtered_through_the_shared_parser() {
        let xml = r#"<m:FindItemResponse><m:ResponseMessages><m:FindItemResponseMessage ResponseClass="Success"><m:ResponseCode>NoError</m:ResponseCode><m:RootFolder TotalItemsInView="2" IncludesLastItemInRange="true"><t:Items>
<t:CalendarItem><t:ItemId Id="AAA" ChangeKey="x"/><t:UID>keep@calrs</t:UID></t:CalendarItem>
<t:CalendarItem><t:ItemId Id="BBB" ChangeKey="y"/><t:UID>drop@calrs</t:UID></t:CalendarItem>
</t:Items></m:RootFolder></m:FindItemResponseMessage></m:ResponseMessages></m:FindItemResponse>"#;
        let page = parse_calendar_items_response(xml).unwrap();
        assert_eq!(item_ids_with_uid(&page.items, "keep@calrs"), ["AAA"]);
    }
}
