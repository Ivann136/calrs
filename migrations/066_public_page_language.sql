-- Language of a host's public pages under /u/{username}.
--
-- 'visitor': the visitor's browser language, like team and legacy pages.
-- 'host': the host's saved language preference (users.language), the
-- behaviour introduced in #76; falls back to the visitor's language when the
-- host has none saved.
--
-- Everyone starts on 'visitor', existing users included.
ALTER TABLE users ADD COLUMN public_page_language TEXT NOT NULL DEFAULT 'visitor';
