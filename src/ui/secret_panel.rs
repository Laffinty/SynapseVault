//! 密码库面板 UI
//!
//! 提供密码列表的展示、搜索、过滤、以及操作按钮。

use crate::app::SynapseVaultApp;
use crate::secret::entry::SecretMeta;
use chrono::{DateTime, Utc};
use egui::{Color32, Context, Ui};
use egui_extras::{Column, TableBuilder};

/// 密码库面板渲染
pub fn render_secret_panel(app: &mut SynapseVaultApp, ctx: &Context, ui: &mut Ui) {
    ui.heading("🔑 密码库");
    ui.add_space(8.0);

    // 搜索和过滤栏
    ui.horizontal(|ui| {
        ui.label("🔍 搜索:");
        ui.text_edit_singleline(&mut app.secret_search_query);
        if ui.button("清除").clicked() {
            app.secret_search_query.clear();
        }
    });

    ui.add_space(8.0);

    // 密码列表
    let secrets = if app.secret_search_query.is_empty() {
        app.secret_metas
            .values()
            .flatten()
            .cloned()
            .collect::<Vec<_>>()
    } else {
        // 简单搜索：在所有组的密码中搜索
        let query = app.secret_search_query.to_lowercase();
        app.secret_metas
            .values()
            .flatten()
            .filter(|meta| {
                meta.title.to_lowercase().contains(&query)
                    || meta.username.to_lowercase().contains(&query)
                    || meta
                        .tags
                        .iter()
                        .any(|t: &String| t.to_lowercase().contains(&query))
                    || meta.environment.to_lowercase().contains(&query)
            })
            .cloned()
            .collect::<Vec<_>>()
    };

    if secrets.is_empty() {
        ui.add_space(20.0);
        ui.centered_and_justified(|ui| {
            if app.secret_metas.is_empty() {
                ui.label("暂无密码条目。点击上方按钮添加新密码。");
            } else {
                ui.label("未找到匹配的密码条目。");
            }
        });
    } else {
        let total = secrets.len();
        let per_page = app.secrets_per_page;
        let total_pages = total.div_ceil(per_page);
        if app.secret_page >= total_pages {
            app.secret_page = total_pages.saturating_sub(1);
        }
        let page = app.secret_page;
        let start = page * per_page;
        let end = (start + per_page).min(total);
        let page_secrets: Vec<SecretMeta> = secrets[start..end].to_vec();
        app.total_secrets_count = total;

        render_secret_table(app, ctx, ui, &page_secrets);

        // 分页控件
        if total_pages > 1 {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui.button("◀ 上一页").clicked() && page > 0 {
                    app.secret_page -= 1;
                }
                ui.label(format!("第 {} / {} 页  (共 {} 条)", page + 1, total_pages, total));
                if ui.button("下一页 ▶").clicked() && page + 1 < total_pages {
                    app.secret_page += 1;
                }
            });
        }
    }
}

fn render_secret_table(
    app: &mut SynapseVaultApp,
    _ctx: &Context,
    ui: &mut Ui,
    secrets: &[SecretMeta],
) {
    let now = Utc::now();
    let text_height = egui::TextStyle::Body.resolve(ui.style()).size;
    let default_bg = ui.visuals().widgets.inactive.bg_fill;

    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(
            Column::initial(180.0)
                .at_least(120.0)
                .clip(true)
                .resizable(true),
        )
        .column(
            Column::initial(120.0)
                .at_least(80.0)
                .clip(true)
                .resizable(true),
        )
        .column(
            Column::initial(100.0)
                .at_least(60.0)
                .clip(true)
                .resizable(true),
        )
        .column(
            Column::initial(120.0)
                .at_least(80.0)
                .clip(true)
                .resizable(true),
        )
        .column(Column::initial(80.0).at_least(60.0).resizable(true))
        .column(Column::initial(120.0).at_least(80.0).resizable(true))
        .header(20.0, |mut header| {
            header.col(|ui| {
                ui.strong("标题");
            });
            header.col(|ui| {
                ui.strong("用户名");
            });
            header.col(|ui| {
                ui.strong("环境");
            });
            header.col(|ui| {
                ui.strong("标签");
            });
            header.col(|ui| {
                ui.strong("状态");
            });
            header.col(|ui| {
                ui.strong("操作");
            });
        })
        .body(|body| {
            body.rows(text_height, secrets.len(), |mut row| {
                let secret = &secrets[row.index()];
                let expired = is_expired(secret, now);
                let expiring_soon = !expired && is_expiring_soon(secret, now);

                let row_color = if expired {
                    Color32::from_rgb(80, 20, 20) // 暗红色背景表示已过期
                } else if expiring_soon {
                    Color32::from_rgb(80, 60, 10) // 暗黄色背景表示即将过期
                } else {
                    default_bg
                };

                // 标题
                row.col(|ui| {
                    let rect = ui.max_rect();
                    ui.painter().rect_filled(rect, 0.0, row_color);

                    let title_text = if expired {
                        format!("⚠️ {}", secret.title)
                    } else if expiring_soon {
                        format!("⏳ {}", secret.title)
                    } else {
                        secret.title.clone()
                    };

                    let title_label = if expired || expiring_soon {
                        egui::RichText::new(title_text).color(Color32::LIGHT_RED)
                    } else {
                        egui::RichText::new(title_text)
                    };

                    ui.label(title_label);
                });

                // 用户名
                row.col(|ui| {
                    let rect = ui.max_rect();
                    ui.painter().rect_filled(rect, 0.0, row_color);
                    ui.label(&secret.username);
                });

                // 环境
                row.col(|ui| {
                    let rect = ui.max_rect();
                    ui.painter().rect_filled(rect, 0.0, row_color);
                    ui.label(&secret.environment);
                });

                // 标签
                row.col(|ui| {
                    let rect = ui.max_rect();
                    ui.painter().rect_filled(rect, 0.0, row_color);
                    ui.label(secret.tags.join(", "));
                });

                // 状态
                row.col(|ui| {
                    let rect = ui.max_rect();
                    ui.painter().rect_filled(rect, 0.0, row_color);

                    if expired {
                        ui.colored_label(Color32::LIGHT_RED, "已过期");
                    } else if expiring_soon {
                        ui.colored_label(Color32::YELLOW, "即将过期");
                    } else {
                        ui.label("正常");
                    }
                });

                // 操作
                row.col(|ui| {
                    let rect = ui.max_rect();
                    ui.painter().rect_filled(rect, 0.0, row_color);

                    ui.horizontal(|ui| {
                        if ui.button("👁 查看").clicked() {
                            app.active_dialog = Some(crate::app::DialogState::ViewSecret { secret_id: secret.secret_id.clone() });
                        }
                        if ui.button("📋 复制").clicked() {
                            app.active_dialog = Some(crate::app::DialogState::CopySecret { secret_id: secret.secret_id.clone() });
                        }
                    });
                });
            });
        });
}

/// 检查密码是否已过期
fn is_expired(secret: &SecretMeta, now: DateTime<Utc>) -> bool {
    secret.expires_at.map(|exp| exp <= now).unwrap_or(false)
}

/// 检查密码是否即将过期（7 天内）
fn is_expiring_soon(secret: &SecretMeta, now: DateTime<Utc>) -> bool {
    secret
        .expires_at
        .map(|exp| {
            let days_until = (exp - now).num_days();
            (0..=7).contains(&days_until)
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::entry::SecretMeta;

    #[test]
    fn test_is_expired() {
        let now = Utc::now();
        let secret = SecretMeta {
            secret_id: "id".to_string(),
            title: "test".to_string(),
            username: "user".to_string(),
            environment: "prod".to_string(),
            tags: vec![],
            updated_at: now,
            expires_at: Some(now - chrono::Duration::days(1)),
        };
        assert!(is_expired(&secret, now));
    }

    #[test]
    fn test_is_expiring_soon() {
        let now = Utc::now();
        let secret = SecretMeta {
            secret_id: "id".to_string(),
            title: "test".to_string(),
            username: "user".to_string(),
            environment: "prod".to_string(),
            tags: vec![],
            updated_at: now,
            expires_at: Some(now + chrono::Duration::days(3)),
        };
        assert!(is_expiring_soon(&secret, now));
        assert!(!is_expired(&secret, now));
    }

    #[test]
    fn test_not_expired_no_expires_at() {
        let now = Utc::now();
        let secret = SecretMeta {
            secret_id: "id".to_string(),
            title: "test".to_string(),
            username: "user".to_string(),
            environment: "prod".to_string(),
            tags: vec![],
            updated_at: now,
            expires_at: None,
        };
        assert!(!is_expired(&secret, now));
        assert!(!is_expiring_soon(&secret, now));
    }
}
