//! Look and feel: neutral greys plus the system accent, or monochrome without one. egui follows
//! the system light/dark setting by default; the user can override it from the top bar.
//! Severity and memory category colours live with their data and stay fixed: they carry meaning.

use crate::system_accent;
use eframe::egui::{self, Color32, CornerRadius, Stroke, Theme};

#[derive(Clone, Copy)]
pub struct Palette {
    pub bg: Color32,
    pub card: Color32,
    pub card_stroke: Color32,
    pub text: Color32,
    pub weak: Color32,
    pub accent: Color32,
    pub track: Color32,
}

pub const DARK: Palette = Palette {
    bg: Color32::from_gray(0x17),
    card: Color32::from_gray(0x20),
    card_stroke: Color32::from_gray(0x30),
    text: Color32::from_gray(0xe8),
    weak: Color32::from_gray(0xa0),
    accent: Color32::from_gray(0xe6),
    track: Color32::from_gray(0x2e),
};

pub const LIGHT: Palette = Palette {
    bg: Color32::from_gray(0xf4),
    card: Color32::WHITE,
    card_stroke: Color32::from_gray(0xe2),
    text: Color32::from_gray(0x22),
    weak: Color32::from_gray(0x68),
    accent: Color32::from_gray(0x1f),
    track: Color32::from_gray(0xeb),
};

/// The base palette with the system accent in place, if the desktop reports one.
fn with_accent(base: Palette, dark: bool) -> Palette {
    match system_accent::get() {
        Some(c) => Palette { accent: system_accent::readable(c, dark), ..base },
        None => base,
    }
}

pub fn palette(ui: &egui::Ui) -> Palette {
    if ui.visuals().dark_mode {
        with_accent(DARK, true)
    } else {
        with_accent(LIGHT, false)
    }
}

/// Restyles the widgets if the system accent has changed since the last frame.
pub fn refresh(ctx: &egui::Context, last: &mut Option<Color32>) {
    let now = system_accent::get();
    if now != *last {
        *last = now;
        apply(ctx);
    }
}

pub fn apply(ctx: &egui::Context) {
    ctx.all_styles_mut(|style| {
        for (ts, font) in style.text_styles.iter_mut() {
            font.size = match ts {
                egui::TextStyle::Heading => 20.0,
                egui::TextStyle::Small => 11.5,
                egui::TextStyle::Monospace => 13.5,
                _ => 14.0,
            };
        }
        style.spacing.item_spacing = egui::vec2(8.0, 6.0);
        style.spacing.button_padding = egui::vec2(10.0, 5.0);
        style.spacing.interact_size.y = 26.0;
    });
    for (theme, p) in [(Theme::Dark, with_accent(DARK, true)), (Theme::Light, with_accent(LIGHT, false))] {
        ctx.style_mut_of(theme, |style| {
            let v = &mut style.visuals;
            v.panel_fill = p.bg;
            v.window_fill = p.card;
            v.extreme_bg_color = if theme == Theme::Dark { Color32::from_gray(0x12) } else { Color32::WHITE };
            v.faint_bg_color = if theme == Theme::Dark { Color32::from_gray(0x26) } else { Color32::from_gray(0xf7) };
            v.override_text_color = Some(p.text);
            v.weak_text_color = Some(p.weak);
            v.hyperlink_color = p.accent;
            v.selection.bg_fill = p.accent.gamma_multiply(if theme == Theme::Dark { 0.45 } else { 0.25 });
            v.selection.stroke = Stroke::new(1.0, p.accent);
            v.window_stroke = Stroke::new(1.0, p.card_stroke);
            v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, p.card_stroke);
            let r = CornerRadius::same(6);
            for w in [&mut v.widgets.noninteractive, &mut v.widgets.inactive, &mut v.widgets.hovered, &mut v.widgets.active, &mut v.widgets.open] {
                w.corner_radius = r;
            }
            v.widgets.inactive.weak_bg_fill = p.track;
            v.widgets.inactive.bg_stroke = Stroke::new(1.0, p.card_stroke);
            v.widgets.inactive.bg_fill = p.track;
            v.widgets.hovered.weak_bg_fill = p.accent.gamma_multiply(0.25);
            v.widgets.hovered.bg_stroke = Stroke::new(1.0, p.accent.gamma_multiply(0.7));
            v.widgets.active.weak_bg_fill = p.accent.gamma_multiply(0.4);
            v.window_corner_radius = CornerRadius::same(10);
            v.menu_corner_radius = CornerRadius::same(8);
        });
    }
}

/// A rounded card with the theme's surface color.
pub fn card<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> egui::InnerResponse<R> {
    let p = palette(ui);
    egui::Frame::new()
        .fill(p.card)
        .stroke(Stroke::new(1.0, p.card_stroke))
        .corner_radius(10.0)
        .inner_margin(egui::Margin::same(14))
        .show(ui, add)
}

/// Black or white, whichever reads better on `bg`.
pub fn text_on(bg: Color32) -> Color32 {
    let l = 0.2126 * bg.r() as f32 + 0.7152 * bg.g() as f32 + 0.0722 * bg.b() as f32;
    if l > 150.0 {
        Color32::from_black_alpha(220)
    } else {
        Color32::WHITE
    }
}
