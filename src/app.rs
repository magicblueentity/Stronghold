use crate::{
    config::AppConfig,
    i18n::{tr, Language},
    logger::AppLogger,
    models::*,
    modules::{behavior, human_risk, integrity, network, response},
};
use chrono::Local;
use eframe::egui::{self, Color32, RichText};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Dashboard,
    Integrity,
    Behavior,
    Network,
    HumanRisk,
    Response,
}

pub struct StrongholdApp {
    config: AppConfig,
    logger: AppLogger,
    language: Language,
    tab: Tab,
    integrity_report: IntegrityReport,
    behavior_report: BehaviorReport,
    network_report: NetworkReport,
    human_risk_report: HumanRiskReport,
    response_report: ResponseReport,
    last_dashboard: DashboardSnapshot,
    isolate_pid_input: String,
    quarantine_path_input: String,
}

impl StrongholdApp {
    pub fn new(config: AppConfig, logger: AppLogger) -> Self {
        let language = Language::from_config(&config.default_language);
        let integrity_report = integrity::run_scan(&config);
        let behavior_report = behavior::run_scan(&config);
        let network_report = network::run_scan();
        let human_risk_report = human_risk::run_scan(&config);
        let response_report = response::empty_report();
        let last_dashboard = build_dashboard(
            &integrity_report,
            &behavior_report,
            &network_report,
            &human_risk_report,
        );

        Self {
            config,
            logger,
            language,
            tab: Tab::Dashboard,
            integrity_report,
            behavior_report,
            network_report,
            human_risk_report,
            response_report,
            last_dashboard,
            isolate_pid_input: String::new(),
            quarantine_path_input: String::new(),
        }
    }

    fn run_all_scans(&mut self) {
        self.integrity_report = integrity::run_scan(&self.config);
        self.behavior_report = behavior::run_scan(&self.config);
        self.network_report = network::run_scan();
        self.human_risk_report = human_risk::run_scan(&self.config);
        self.last_dashboard = build_dashboard(
            &self.integrity_report,
            &self.behavior_report,
            &self.network_report,
            &self.human_risk_report,
        );
        let _ = self.logger.log("All modules scanned");
    }

    fn risk_color(risk: RiskLevel) -> Color32 {
        match risk {
            RiskLevel::Green => Color32::from_rgb(50, 180, 90),
            RiskLevel::Yellow => Color32::from_rgb(230, 190, 55),
            RiskLevel::Red => Color32::from_rgb(215, 70, 70),
        }
    }
}

impl eframe::App for StrongholdApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let mut style = (*ctx.style()).clone();
        style.visuals = egui::Visuals::dark();
        ctx.set_style(style);

        egui::TopBottomPanel::top("top_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading(tr(
                    self.language,
                    "Stronghold Security Console",
                    "Stronghold Sicherheitskonsole",
                ));
                ui.separator();
                if ui
                    .button(tr(self.language, "Run Full Scan", "Vollscan starten"))
                    .clicked()
                {
                    self.run_all_scans();
                }
                if ui.button("EN").clicked() {
                    self.language = Language::En;
                }
                if ui.button("DE").clicked() {
                    self.language = Language::De;
                }
            });
        });

        egui::SidePanel::left("nav").show(ctx, |ui| {
            ui.label(RichText::new(tr(self.language, "Modules", "Module")).strong());
            nav_button(
                ui,
                &mut self.tab,
                Tab::Dashboard,
                tr(self.language, "Dashboard", "Dashboard"),
            );
            nav_button(ui, &mut self.tab, Tab::Integrity, "System Integrity");
            nav_button(ui, &mut self.tab, Tab::Behavior, "Behavioral Detection");
            nav_button(ui, &mut self.tab, Tab::Network, "Network Surveillance");
            nav_button(ui, &mut self.tab, Tab::HumanRisk, "Human Risk");
            nav_button(ui, &mut self.tab, Tab::Response, "Isolation & Response");
        });

        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
            Tab::Dashboard => render_dashboard(ui, self),
            Tab::Integrity => render_integrity(ui, self),
            Tab::Behavior => render_behavior(ui, self),
            Tab::Network => render_network(ui, self),
            Tab::HumanRisk => render_human_risk(ui, self),
            Tab::Response => render_response(ui, self),
        });
    }
}

fn nav_button(ui: &mut egui::Ui, tab: &mut Tab, me: Tab, title: &str) {
    let selected = *tab == me;
    if ui.selectable_label(selected, title).clicked() {
        *tab = me;
    }
}

fn build_dashboard(
    integrity: &IntegrityReport,
    behavior: &BehaviorReport,
    network: &NetworkReport,
    human: &HumanRiskReport,
) -> DashboardSnapshot {
    let security_score = ((integrity.score as u32
        + behavior.score as u32
        + network.score as u32
        + human.score as u32)
        / 4) as u8;
    let active_threats = integrity.threats.len()
        + behavior.threats.len()
        + network.threats.len()
        + human.threats.len();

    DashboardSnapshot {
        security_score,
        risk_level: RiskLevel::from_score(security_score),
        active_threats,
        network_connections: network.active_connections.len(),
        last_scan: Local::now(),
    }
}

fn render_dashboard(ui: &mut egui::Ui, app: &StrongholdApp) {
    let c = StrongholdApp::risk_color(app.last_dashboard.risk_level);
    ui.heading("Security Dashboard");
    ui.colored_label(
        c,
        format!(
            "Score: {} | Risk: {}",
            app.last_dashboard.security_score,
            app.last_dashboard.risk_level.as_str()
        ),
    );
    ui.label(format!(
        "Active threats: {}",
        app.last_dashboard.active_threats
    ));
    ui.label(format!(
        "Network connections: {}",
        app.last_dashboard.network_connections
    ));
    ui.label(format!(
        "Last scan: {}",
        app.last_dashboard.last_scan.format("%Y-%m-%d %H:%M:%S")
    ));
    ui.separator();
    ui.label("Risk Levels: Green = stable, Yellow = caution, Red = immediate action");
}

fn render_integrity(ui: &mut egui::Ui, app: &StrongholdApp) {
    let r = &app.integrity_report;
    ui.heading("System Integrity Scanner");
    ui.colored_label(
        StrongholdApp::risk_color(r.risk_level),
        format!("Score: {} ({})", r.score, r.risk_level.as_str()),
    );
    ui.label(format!("Running processes: {}", r.running_processes));
    ui.label(format!("Startup items: {}", r.startup_items));
    ui.separator();
    ui.label("Missing critical files:");
    for f in r.missing_critical_files.iter().take(12) {
        ui.label(format!("- {f}"));
    }
}

fn render_behavior(ui: &mut egui::Ui, app: &StrongholdApp) {
    let r = &app.behavior_report;
    ui.heading("Behavioral Threat Detection");
    ui.colored_label(
        StrongholdApp::risk_color(r.risk_level),
        format!("Score: {} ({})", r.score, r.risk_level.as_str()),
    );
    ui.label(format!(
        "High CPU patterns: {}",
        r.suspicious_processes.len()
    ));
    ui.label(format!(
        "High memory patterns: {}",
        r.high_memory_processes.len()
    ));
    ui.label(format!("File anomalies: {}", r.file_anomalies.len()));
}

fn render_network(ui: &mut egui::Ui, app: &StrongholdApp) {
    let r = &app.network_report;
    ui.heading("Network Surveillance Layer");
    ui.colored_label(
        StrongholdApp::risk_color(r.risk_level),
        format!("Score: {} ({})", r.score, r.risk_level.as_str()),
    );
    ui.label(format!(
        "Active connections: {}",
        r.active_connections.len()
    ));
    ui.label(format!("DNS anomalies: {}", r.dns_anomalies.len()));
    ui.separator();
    ui.label("Interactive Network Map (table view):");
    egui::ScrollArea::vertical()
        .max_height(260.0)
        .show(ui, |ui| {
            for conn in r.active_connections.iter().take(80) {
                ui.label(format!(
                    "{} {} -> {} [{}] pid={:?}",
                    conn.protocol, conn.local, conn.remote, conn.state, conn.pid
                ));
            }
        });
}

fn render_human_risk(ui: &mut egui::Ui, app: &StrongholdApp) {
    let r = &app.human_risk_report;
    ui.heading("Human Risk Monitor");
    ui.colored_label(
        StrongholdApp::risk_color(r.risk_level),
        format!("Score: {} ({})", r.score, r.risk_level.as_str()),
    );
    ui.label(format!("Unsafe downloads: {}", r.unsafe_downloads.len()));
    ui.label(format!(
        "Weak-password accounts: {}",
        r.weak_password_accounts.len()
    ));
    ui.label(format!("Risky behavior markers: {}", r.risky_actions.len()));
}

fn render_response(ui: &mut egui::Ui, app: &mut StrongholdApp) {
    ui.heading("Isolation & Response Engine");

    ui.horizontal(|ui| {
        ui.label("PID");
        ui.text_edit_singleline(&mut app.isolate_pid_input);
        if ui.button("Isolate Process").clicked() {
            if let Ok(pid) = app.isolate_pid_input.trim().parse::<u32>() {
                if response::isolate_process(pid).is_ok() {
                    app.response_report.isolated_processes.push(pid);
                    let _ = app.logger.log(&format!("Process isolated: {pid}"));
                }
            }
        }
    });

    ui.horizontal(|ui| {
        ui.label("File");
        ui.text_edit_singleline(&mut app.quarantine_path_input);
        if ui.button("Quarantine File").clicked() {
            if let Ok(path) = response::quarantine_file(
                app.quarantine_path_input.trim(),
                &app.config.quarantine_dir,
            ) {
                app.response_report.quarantined_files.push(path.clone());
                let _ = app.logger.log(&format!("File quarantined: {path}"));
            }
        }
    });

    if ui.button("Revert Registry Changes").clicked() {
        app.response_report.reverted_registry_entries = response::revert_registry_changes();
        let _ = app.logger.log("Registry revert routine executed");
    }

    if ui.button("Create System Snapshot").clicked() {
        let snapshot = "logs/system_snapshot.json";
        if let Ok(path) = response::create_system_snapshot(snapshot) {
            app.response_report.snapshot_file = Some(path.clone());
            let _ = app.logger.log("System snapshot created");
        }
    }

    ui.separator();
    ui.label(format!(
        "Isolated processes: {}",
        app.response_report.isolated_processes.len()
    ));
    ui.label(format!(
        "Quarantined files: {}",
        app.response_report.quarantined_files.len()
    ));
    ui.label(format!(
        "Registry entries reverted: {}",
        app.response_report.reverted_registry_entries.len()
    ));
    if let Some(snapshot) = &app.response_report.snapshot_file {
        ui.label(format!("Snapshot: {snapshot}"));
    }
}
