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
        Box::new(|cc| Ok(Box::new(SynapseVaultApp::new(cc)))),
    )
}
