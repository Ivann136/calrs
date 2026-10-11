-- Calendar source sync failures (#162).
--
-- Availability keeps being served from the last good sync when a source
-- fails; these columns record the failure so the owner can see it on the
-- calendar sources page and be emailed once when it persists. All cleared
-- by the next successful sync.
--
-- last_sync_error     message of the last failed sync, NULL when fine
-- last_sync_error_at  when it failed ('YYYY-MM-DD HH:MM:SS' UTC); on-demand
--                     and background syncs back off from it
-- sync_failing_since  first failure of the current run of failures
-- sync_failure_count  failed syncs in a row
-- sync_alerted_at     when the owner was emailed about this run
ALTER TABLE caldav_sources ADD COLUMN last_sync_error TEXT;
ALTER TABLE caldav_sources ADD COLUMN last_sync_error_at TEXT;
ALTER TABLE caldav_sources ADD COLUMN sync_failing_since TEXT;
ALTER TABLE caldav_sources ADD COLUMN sync_failure_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE caldav_sources ADD COLUMN sync_alerted_at TEXT;
