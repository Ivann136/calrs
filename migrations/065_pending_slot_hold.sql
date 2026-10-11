-- Pending requests (event types with requires_confirmation) hold their slot
-- and expire if the host does not answer (#234).
--
-- pending_blocks_slot: a pending booking blocks its host's time like a
-- confirmed one. On by default, including for existing event types.
-- pending_expiry_hours: NULL means a request never expires. Existing event
-- types keep that behaviour; new ones are created with 24 by the web form.
ALTER TABLE event_types ADD COLUMN pending_blocks_slot INTEGER NOT NULL DEFAULT 1;
ALTER TABLE event_types ADD COLUMN pending_expiry_hours INTEGER;

-- Deadline after which an unanswered request is declined (UTC, RFC3339 with
-- a trailing Z). NULL means never: requests that already exist are not
-- expired on upgrade.
ALTER TABLE bookings ADD COLUMN pending_expires_at TEXT;
-- When the current pending window started (creation, or a reschedule back to
-- pending): anchors the halfway host nudge.
ALTER TABLE bookings ADD COLUMN pending_since TEXT;
-- When the one host nudge for a pending request went out.
ALTER TABLE bookings ADD COLUMN pending_reminder_sent_at TEXT;

CREATE INDEX IF NOT EXISTS idx_bookings_pending_expiry
    ON bookings (pending_expires_at) WHERE status = 'pending';
