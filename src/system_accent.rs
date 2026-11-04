//! Reads the desktop's accent colour so the app matches the rest of the system.
//!
//! Linux uses the XDG settings portal, which covers every desktop that implements it, and follows
//! changes live. Windows reads the same registry value the shell uses. Everywhere else, and when
//! a desktop doesn't report one, there is no accent and the app stays monochrome.

use eframe::egui::{self, Color32};
use std::sync::atomic::{AtomicU32, Ordering};

/// 0 means no accent, otherwise 0x01RRGGBB.
static ACCENT: AtomicU32 = AtomicU32::new(0);

/// The current system accent, if the desktop reports one.
pub fn get() -> Option<Color32> {
    match ACCENT.load(Ordering::Relaxed) {
        0 => None,
        v => Some(Color32::from_rgb((v >> 16) as u8, (v >> 8) as u8, v as u8)),
    }
}

fn set(rgb: Option<[u8; 3]>, ctx: &egui::Context) {
    let v = rgb.map_or(0, |[r, g, b]| 0x0100_0000 | u32::from(r) << 16 | u32::from(g) << 8 | u32::from(b));
    if ACCENT.swap(v, Ordering::Relaxed) != v {
        ctx.request_repaint();
    }
}

/// Starts following the system accent on a background thread.
pub fn start(ctx: &egui::Context) {
    let ctx = ctx.clone();
    let _ = std::thread::Builder::new().name("system-accent".into()).spawn(move || follow(&ctx));
}

/// Moves `accent` towards white or black until it reads well on the theme's background.
pub fn readable(accent: Color32, dark: bool) -> Color32 {
    let (bg, target) = if dark { (Color32::from_gray(0x1c), 255.0) } else { (Color32::from_gray(0xf8), 0.0) };
    let mix = |c: u8, t: f32| (f32::from(c) + (target - f32::from(c)) * t).round() as u8;
    for step in 0..=20 {
        let t = step as f32 / 20.0;
        let c = Color32::from_rgb(mix(accent.r(), t), mix(accent.g(), t), mix(accent.b(), t));
        if contrast(c, bg) >= 4.5 {
            return c;
        }
    }
    if dark { Color32::WHITE } else { Color32::BLACK }
}

fn luminance(c: Color32) -> f32 {
    let f = |v: u8| {
        let v = f32::from(v) / 255.0;
        if v <= 0.03928 { v / 12.92 } else { ((v + 0.055) / 1.055).powf(2.4) }
    };
    0.2126 * f(c.r()) + 0.7152 * f(c.g()) + 0.0722 * f(c.b())
}

fn contrast(a: Color32, b: Color32) -> f32 {
    let (a, b) = (luminance(a), luminance(b));
    (a.max(b) + 0.05) / (a.min(b) + 0.05)
}

/// The portal gives sRGB as 0-1 floats. Anything out of range means "no accent set".
#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
fn from_portal(rgb: [f64; 3]) -> Option<[u8; 3]> {
    rgb.iter().all(|v| (0.0..=1.0).contains(v)).then(|| rgb.map(|v| (v * 255.0).round() as u8))
}

#[cfg(target_os = "linux")]
fn follow(ctx: &egui::Context) {
    use zbus::blocking::{Connection, Proxy};
    use zbus::zvariant::Value;

    const NAMESPACE: &str = "org.freedesktop.appearance";
    const KEY: &str = "accent-color";

    fn parse(v: &Value<'_>) -> Option<[f64; 3]> {
        match v {
            Value::Value(inner) => parse(inner),
            Value::Structure(s) => match s.fields() {
                [Value::F64(r), Value::F64(g), Value::F64(b)] => Some([*r, *g, *b]),
                _ => None,
            },
            _ => None,
        }
    }

    let run = || -> zbus::Result<()> {
        let conn = Connection::session()?;
        let proxy = Proxy::new(
            &conn,
            "org.freedesktop.portal.Desktop",
            "/org/freedesktop/portal/desktop",
            "org.freedesktop.portal.Settings",
        )?;
        // Subscribe first, so a change can't slip through between reading and listening.
        let changes = proxy.receive_signal("SettingChanged")?;
        let reply = proxy.call_method("ReadOne", &(NAMESPACE, KEY))?;
        let body = reply.body();
        set(parse(&body.deserialize::<Value<'_>>()?).and_then(from_portal), ctx);
        for msg in changes {
            let body = msg.body();
            if let Ok((ns, key, value)) = body.deserialize::<(String, String, Value<'_>)>() {
                if ns == NAMESPACE && key == KEY {
                    set(parse(&value).and_then(from_portal), ctx);
                }
            }
        }
        Ok(())
    };
    // No portal, or a desktop without this setting, simply means monochrome.
    let _ = run();
}

#[cfg(windows)]
fn follow(ctx: &egui::Context) {
    use winreg::RegKey;
    use winreg::enums::HKEY_CURRENT_USER;

    loop {
        let value: Option<u32> = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey("SOFTWARE\\Microsoft\\Windows\\DWM")
            .and_then(|key| key.get_value("AccentColor"))
            .ok();
        // Stored as 0xAABBGGRR.
        set(value.map(|v| [v as u8, (v >> 8) as u8, (v >> 16) as u8]), ctx);
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
fn follow(_ctx: &egui::Context) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portal_values_convert_to_srgb() {
        assert_eq!(from_portal([0.239, 0.682, 0.914]), Some([61, 174, 233]));
    }

    #[test]
    fn out_of_range_means_no_accent() {
        assert_eq!(from_portal([-1.0, -1.0, -1.0]), None);
        assert_eq!(from_portal([0.5, 1.5, 0.5]), None);
    }

    #[test]
    fn readable_always_has_enough_contrast() {
        for accent in [Color32::YELLOW, Color32::from_rgb(0, 0, 80), Color32::WHITE, Color32::BLACK, Color32::from_rgb(0x3d, 0xae, 0xe9)] {
            assert!(contrast(readable(accent, true), Color32::from_gray(0x1c)) >= 4.5, "{accent:?} on dark");
            assert!(contrast(readable(accent, false), Color32::from_gray(0xf8)) >= 4.5, "{accent:?} on light");
        }
    }

    #[test]
    fn readable_leaves_a_good_accent_alone() {
        let blue = Color32::from_rgb(0x3d, 0xae, 0xe9);
        assert_eq!(readable(blue, true), blue);
    }
}
