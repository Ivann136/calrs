//! Theme CSS derivation and the static assets served from the binary.

use super::*;

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
    let utils = include_str!("../../../assets/intl-tel-input/utils.js");
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
