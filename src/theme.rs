//! Look and feel: one palette per theme. egui follows the Windows light/dark setting by
//! default; the user can override it from the top bar.

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
    bg: Color32::from_rgb(0x14, 0x16, 0x1b),
    card: Color32::from_rgb(0x1d, 0x20, 0x27),
    card_stroke: Color32::from_rgb(0x2b, 0x30, 0x3a),
    text: Color32::from_rgb(0xe6, 0xe8, 0xec),
    weak: Color32::from_rgb(0x96, 0x9f, 0xad),
    accent: Color32::from_rgb(0x5b, 0x9b, 0xff),
    track: Color32::from_rgb(0x2a, 0x2e, 0x37),
};

pub const LIGHT: Palette = Palette {
    bg: Color32::from_rgb(0xf3, 0xf4, 0xf7),
    card: Color32::WHITE,
    card_stroke: Color32::from_rgb(0xdf, 0xe2, 0xe8),
    text: Color32::from_rgb(0x1f, 0x23, 0x28),
    weak: Color32::from_rgb(0x5f, 0x68, 0x73),
    accent: Color32::from_rgb(0x25, 0x63, 0xeb),
    track: Color32::from_rgb(0xe8, 0xeb, 0xf0),
};

pub fn palette(ui: &egui::Ui) -> Palette {
    if ui.visuals().dark_mode {
        DARK
    } else {
        LIGHT
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
    for (theme, p) in [(Theme::Dark, DARK), (Theme::Light, LIGHT)] {
        ctx.style_mut_of(theme, |style| {
            let v = &mut style.visuals;
            v.panel_fill = p.bg;
            v.window_fill = p.card;
            v.extreme_bg_color = if theme == Theme::Dark { Color32::from_rgb(0x10, 0x12, 0x16) } else { Color32::WHITE };
            v.faint_bg_color = if theme == Theme::Dark { Color32::from_rgb(0x22, 0x26, 0x2e) } else { Color32::from_rgb(0xf6, 0xf7, 0xf9) };
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
