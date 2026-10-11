-- Calendar write-back failures (#162).
--
-- A confirmed booking whose event could not be written to (or read back
-- from) the host's calendar keeps its status: calrs's own bookings table
-- already blocks the slot and the guest has the invitation. These columns
-- record the failure so the background loop can retry it and the host can
-- see it, and are cleared when a write-back succeeds.
--
-- writeback_error           summary of the last failure, NULL when fine
-- writeback_attempts        failed attempts in a row
-- writeback_next_attempt_at UTC 'YYYY-MM-DD HH:MM:SS' of the next retry,
--                           NULL when none is scheduled (fine, or retries
--                           exhausted)
-- writeback_alerted_at      when the host was emailed about it, so they are
--                           told once
ALTER TABLE bookings ADD COLUMN writeback_error TEXT;
ALTER TABLE bookings ADD COLUMN writeback_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE bookings ADD COLUMN writeback_next_attempt_at TEXT;
ALTER TABLE bookings ADD COLUMN writeback_alerted_at TEXT;

CREATE INDEX IF NOT EXISTS idx_bookings_writeback_retry
    ON bookings(writeback_next_attempt_at)
    WHERE writeback_next_attempt_at IS NOT NULL;
