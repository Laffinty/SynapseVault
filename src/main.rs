use eframe::egui;
use synapse_vault::app::SynapseVaultApp;

fn main() -> eframe::Result<()> {
    // 初始化 tracing 日志
    tracing_subscriber::fmt::init();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 800.0])
            .with_min_inner_size([640.0, 480.0]),
        ..Default::default()
    };

    eframe::run_native(
        "SynapseVault",
        options,
        Box::new(|cc| {
            // 加载编译时内嵌中文字体（WenQuanYi Micro Hei）
            load_chinese_font(&cc.egui_ctx);
            Ok(Box::new(SynapseVaultApp::new(cc)))
        }),
    )
}

/// 从编译时内嵌的二进制数据加载中文字体（WenQuanYi Micro Hei）
fn load_chinese_font(ctx: &egui::Context) {
    // 编译时内嵌，零运行时文件依赖
    let font_data = include_bytes!("../font/wqy.ttf");

    let mut fonts = egui::FontDefinitions::default();

    fonts.font_data.insert(
        "wqy".to_owned(),
        egui::FontData::from_owned(font_data.to_vec()).into(),
    );

    // 将中文字体加入 Proportional 和 Monospace 的 fallback 列表
    fonts
        .families
        .entry(egui::FontFamily::Proportional)
        .or_default()
        .push("wqy".to_owned());
    fonts
        .families
        .entry(egui::FontFamily::Monospace)
        .or_default()
        .push("wqy".to_owned());

    ctx.set_fonts(fonts);
    tracing::info!("中文字体加载成功（内嵌模式）");
}
