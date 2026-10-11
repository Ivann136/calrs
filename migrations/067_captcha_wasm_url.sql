-- Optional URL of the Cap solver's WASM binary (#164). When set, the booking
-- form sets window.CAP_CUSTOM_WASM_URL so the widget loads the solver from it
-- instead of cdn.jsdelivr.net, which makes a self-hosted Cap fully self-hosted.
-- NULL keeps the widget's own default.
ALTER TABLE auth_config ADD COLUMN captcha_wasm_url TEXT;
