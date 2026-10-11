-- The organizer a multi-host booking was created with (#161).
--
-- Collective team bookings and dynamic group bookings have no single host:
-- their calendar ORGANIZER, and the name and Reply-To on guest emails, come
-- from the roster (first member's address, every name joined). Recomputing
-- that roster later lets a membership, weight or name change move the
-- organizer under an existing event, which Google CalDAV refuses with
-- 403 Forbidden. These columns freeze what the booking was created with.
--
-- organizer_user_id  user whose address is the organizer; only used to pick
--                    the language of host-side emails. No foreign key: the
--                    snapshot must outlive the user.
-- organizer_name     ORGANIZER CN and guest email display name (joined roster)
-- organizer_email    ORGANIZER address and guest email Reply-To
--
-- All NULL for single-host bookings (personal, round-robin), which resolve
-- through a stable user id, and for bookings made before this migration,
-- which keep recomputing from the current roster. No backfill: the roster a
-- booking was created with is not recorded anywhere, and freezing today's
-- roster could pin a value the calendar event never carried.
ALTER TABLE bookings ADD COLUMN organizer_user_id TEXT;
ALTER TABLE bookings ADD COLUMN organizer_name TEXT;
ALTER TABLE bookings ADD COLUMN organizer_email TEXT;
