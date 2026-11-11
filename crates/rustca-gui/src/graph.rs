//! 簽發關係圖：以方框與連線畫出「誰簽發了誰」。

use std::collections::HashMap;

use eframe::egui::{
    self, epaint::CornerRadius, text::LayoutJob, Color32, FontId, Pos2, Rect, Sense, Stroke,
    StrokeKind, TextFormat, Vec2,
};
use rustca_core::{now_ts, IssuanceTree};

use crate::widgets::{status_color, BLUE, GREEN, RED};

const BOX_W: f32 = 330.0;
const BOX_H: f32 = 46.0;
const ROW_H: f32 = 58.0;
const INDENT: f32 = 34.0;
const MARGIN: f32 = 8.0;

/// 憑證位置：sha256 → 「檔案 / 別名」清單。
pub type Locations = HashMap<String, Vec<String>>;

#[derive(Default)]
pub struct TreeResponse {
    pub clicked: Option<usize>,
    pub double_clicked: Option<usize>,
}

/// 畫出關係圖；`menu` 為節點的右鍵選單內容。
pub fn tree_ui(
    ui: &mut egui::Ui,
    tree: &IssuanceTree,
    selected: usize,
    locations: &Locations,
    warn_days: i64,
    scroll_to: Option<usize>,
    menu: &mut dyn FnMut(&mut egui::Ui, usize),
) -> TreeResponse {
    let now = now_ts();
    let max_depth = tree.nodes.iter().map(|n| n.depth).max().unwrap_or(0);
    let size = Vec2::new(
        MARGIN * 2.0 + max_depth as f32 * INDENT + BOX_W,
        MARGIN * 2.0 + tree.nodes.len() as f32 * ROW_H - (ROW_H - BOX_H),
    );
    let (area, _) = ui.allocate_exact_size(size, Sense::hover());
    let painter = ui.painter_at(area.expand(2.0));
    let visuals = ui.visuals().clone();
    let rect_of = |i: usize| {
        let n = &tree.nodes[i];
        Rect::from_min_size(
            area.min + Vec2::new(MARGIN + n.depth as f32 * INDENT, MARGIN + i as f32 * ROW_H),
            Vec2::new(BOX_W, BOX_H),
        )
    };

    // 連線：父方框左下 → 往下 → 往右接到子方框
    for (i, n) in tree.nodes.iter().enumerate() {
        let Some(p) = n.parent else { continue };
        let pr = rect_of(p);
        let cr = rect_of(i);
        let x = pr.left() + INDENT * 0.5;
        let y = cr.center().y;
        let color = match n.signature_ok {
            Some(true) => GREEN.gamma_multiply(0.8),
            Some(false) => RED,
            None => visuals.weak_text_color(),
        };
        let width = if n.on_path { 2.5_f32 } else { 1.5 };
        let stroke = Stroke::new(width, color);
        painter.line_segment([Pos2::new(x, pr.bottom()), Pos2::new(x, y)], stroke);
        painter.line_segment([Pos2::new(x, y), Pos2::new(cr.left(), y)], stroke);
        // 箭頭：簽發方向
        let tip = Pos2::new(cr.left(), y);
        painter.line_segment([tip, tip + Vec2::new(-6.0, -4.0)], stroke);
        painter.line_segment([tip, tip + Vec2::new(-6.0, 4.0)], stroke);
        if n.signature_ok == Some(false) {
            painter.text(
                Pos2::new(x + 4.0, y - 2.0),
                egui::Align2::LEFT_BOTTOM,
                "✘",
                FontId::proportional(12.0),
                RED,
            );
        }
    }

    let mut out = TreeResponse::default();
    for (i, n) in tree.nodes.iter().enumerate() {
        let r = rect_of(i);
        let resp = ui.interact(r, ui.id().with(("tree_node", i)), Sense::click());
        if scroll_to == Some(i) {
            ui.scroll_to_rect(r, Some(egui::Align::Center));
        }
        let status = n.cert.status_at(now, warn_days);
        let fill = if i == selected {
            visuals.selection.bg_fill.gamma_multiply(0.55)
        } else if resp.hovered() {
            visuals.widgets.hovered.weak_bg_fill
        } else {
            visuals.extreme_bg_color
        };
        let border = if n.is_target {
            Stroke::new(2.5_f32, visuals.selection.stroke.color)
        } else if n.on_path {
            Stroke::new(1.5_f32, BLUE)
        } else {
            Stroke::new(1.0_f32, visuals.widgets.noninteractive.bg_stroke.color)
        };
        let radius = CornerRadius::same(6);
        painter.rect(r, radius, fill, border, StrokeKind::Inside);
        // 左側色條：有效期限狀態
        painter.rect_filled(
            Rect::from_min_size(r.min, Vec2::new(5.0, r.height())),
            CornerRadius {
                nw: 6,
                sw: 6,
                ne: 0,
                se: 0,
            },
            status_color(status),
        );

        let text_x = r.left() + 12.0;
        let w = r.width() - 18.0;
        let title = one_line(
            n.cert.display_name(),
            FontId::proportional(14.0),
            visuals.strong_text_color(),
            w,
        );
        painter.galley(
            Pos2::new(text_x, r.top() + 5.0),
            ui.fonts(|f| f.layout_job(title)),
            Color32::PLACEHOLDER,
        );

        let where_ = locations
            .get(&n.cert.sha256)
            .map(|v| {
                // 優先顯示以它為終端憑證的條目，其餘只計數
                let main = v.iter().find(|l| !l.contains("（鏈第")).unwrap_or(&v[0]);
                if v.len() > 1 {
                    format!("{main}（另有 {} 處引用）", v.len() - 1)
                } else {
                    main.clone()
                }
            })
            .unwrap_or_else(|| "（只在憑證鏈中）".into());
        let sub = format!(
            "{} · 到期 {} · {}",
            n.cert.role(),
            rustca_core::format_ts(n.cert.not_after)
                .chars()
                .take(10)
                .collect::<String>(),
            where_
        );
        let sub = one_line(
            sub,
            FontId::proportional(12.0),
            visuals.weak_text_color(),
            w,
        );
        painter.galley(
            Pos2::new(text_x, r.top() + 25.0),
            ui.fonts(|f| f.layout_job(sub)),
            Color32::PLACEHOLDER,
        );
        if n.is_target {
            painter.text(
                r.right_top() + Vec2::new(-6.0, 4.0),
                egui::Align2::RIGHT_TOP,
                "◀ 目前",
                FontId::proportional(11.0),
                visuals.selection.stroke.color,
            );
        }

        let resp = resp.on_hover_ui(|ui| {
            ui.label(format!("主體：{}", n.cert.subject));
            ui.label(format!("簽發者：{}", n.cert.issuer));
            ui.label(format!("狀態：{}", status.label()));
            ui.label(match n.signature_ok {
                Some(true) => "簽章：✔ 可用上層公鑰驗證",
                Some(false) => "簽章：✘ 無法用上層公鑰驗證",
                None => "簽章：無法判斷",
            });
            if let Some(v) = locations.get(&n.cert.sha256) {
                ui.label(format!("位置：{}", v.join("、")));
            }
            ui.weak("點兩下跳到所在條目；右鍵可管理");
        });
        if resp.clicked() || resp.secondary_clicked() {
            out.clicked = Some(i);
        }
        if resp.double_clicked() {
            out.double_clicked = Some(i);
        }
        resp.context_menu(|ui| menu(ui, i));
    }
    out
}

fn one_line(text: String, font: FontId, color: Color32, width: f32) -> LayoutJob {
    let mut job = LayoutJob::single_section(text, TextFormat::simple(font, color));
    job.wrap.max_width = width;
    job.wrap.max_rows = 1;
    job.wrap.break_anywhere = true;
    job
}
