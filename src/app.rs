use crate::{
    config::AppConfig,
    engine,
    i18n::{tr, Language},
    logger::AppLogger,
    models::*,
    modules::{kernel, response},
};
use chrono::Local;
use eframe::egui::{
    self, vec2, Align2, Color32, FontId, RichText, Sense, Shape, Stroke, StrokeKind,
};
use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    io::Write,
    time::{Duration, Instant},
};

const CONFIG_PATH: &str = "config/config.json";
const MIN_AUTO_SCAN_SECONDS: u64 = 15;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Dashboard,
    Integrity,
    Behavior,
    Network,
    HumanRisk,
    Response,
    Kernel,
    Settings,
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
    status_message: String,
    kernel_state: kernel::KernelServiceState,
    last_scan_at: Instant,
    next_auto_scan_at: Instant,
    scan_runs: u64,
    auto_actions_total: u64,
    handled_pids: HashSet<u32>,
    handled_files: HashSet<String>,
    event_feed: Vec<String>,
    boot_instant: Instant,
}

impl StrongholdApp {
    pub fn new(config: AppConfig, logger: AppLogger) -> Self {
        let language = Language::from_config(&config.default_language);
        let initial_scan = engine::run_full_scan(&config);
        let integrity_report = initial_scan.integrity.clone();
        let behavior_report = initial_scan.behavior.clone();
        let network_report = initial_scan.network.clone();
        let human_risk_report = initial_scan.human_risk.clone();
        let response_report = response::empty_report();
        let last_dashboard = initial_scan.dashboard.clone();
        let kernel_state = kernel::query_service_state(&config.kernel_service_name)
            .unwrap_or(kernel::KernelServiceState::Unknown);

        let now = Instant::now();
        let mut app = Self {
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
            status_message: "Ready".to_string(),
            kernel_state,
            last_scan_at: now,
            next_auto_scan_at: now + Duration::from_secs(180),
            scan_runs: 1,
            auto_actions_total: 0,
            handled_pids: HashSet::new(),
            handled_files: HashSet::new(),
            event_feed: Vec::new(),
            boot_instant: now,
        };
        if let Err(e) = engine::append_scan_summary(
            &app.config.scan_summary_path,
            &engine::build_summary(&initial_scan),
        ) {
            let _ = app.logger.log(&format!("Scan summary write failed: {e}"));
        }
        app.schedule_next_auto_scan();
        app.push_event("Stronghold initialized");
        app
    }

    fn push_event(&mut self, msg: impl Into<String>) {
        let message = msg.into();
        let line = format!("{} | {}", Local::now().format("%H:%M:%S"), message);
        self.event_feed.insert(0, line);
        if self.event_feed.len() > 80 {
            self.event_feed.truncate(80);
        }
        let _ = self.logger.log(&message);
    }

    fn schedule_next_auto_scan(&mut self) {
        let interval = self
            .config
            .auto_scan_interval_seconds
            .max(MIN_AUTO_SCAN_SECONDS);
        self.next_auto_scan_at = Instant::now() + Duration::from_secs(interval);
    }

    fn run_all_scans(&mut self, trigger: &str) {
        let started = Instant::now();
        let full_scan = engine::run_full_scan(&self.config);
        if let Err(e) = engine::append_scan_summary(
            &self.config.scan_summary_path,
            &engine::build_summary(&full_scan),
        ) {
            self.push_event(format!("Scan summary write failed: {e}"));
        }

        self.integrity_report = full_scan.integrity;
        self.behavior_report = full_scan.behavior;
        self.network_report = full_scan.network;
        self.human_risk_report = full_scan.human_risk;
        self.last_dashboard = full_scan.dashboard;
        self.kernel_state = kernel::query_service_state(&self.config.kernel_service_name)
            .unwrap_or(kernel::KernelServiceState::Unknown);

        self.scan_runs += 1;
        self.last_scan_at = Instant::now();
        self.schedule_next_auto_scan();

        if self.config.auto_response_enabled {
            self.run_auto_response();
        }

        let duration_ms = started.elapsed().as_millis();
        self.status_message = format!(
            "{} scan completed in {} ms (score {})",
            trigger, duration_ms, self.last_dashboard.security_score
        );
        self.push_event(self.status_message.clone());
    }

    fn run_auto_response(&mut self) {
        if self.last_dashboard.risk_level == RiskLevel::Green {
            return;
        }

        let outcome = response::run_auto_response_cycle(
            &self.config,
            &self.behavior_report,
            &self.human_risk_report,
            self.last_dashboard.risk_level,
            &mut self.handled_pids,
            &mut self.handled_files,
        );
        if outcome.action_count == 0 {
            return;
        }

        for pid in &outcome.isolated_pids {
            if !self.response_report.isolated_processes.contains(&pid) {
                self.response_report.isolated_processes.push(*pid);
            }
        }
        for path in &outcome.quarantined_paths {
            if !self.response_report.quarantined_files.contains(&path) {
                self.response_report.quarantined_files.push(path.clone());
            }
        }
        for key in &outcome.reverted_registry_entries {
            if !self
                .response_report
                .reverted_registry_entries
                .contains(&key)
            {
                self.response_report
                    .reverted_registry_entries
                    .push(key.clone());
            }
        }
        if let Some(snapshot) = &outcome.snapshot_file {
            self.response_report.snapshot_file = Some(snapshot.clone());
        }

        self.auto_actions_total += outcome.action_count as u64;
        let _ = self.persist_incident_history(
            &outcome,
            "auto-cycle".to_string(),
            self.last_dashboard.security_score,
        );
        self.push_event(format!(
            "Automation executed {} response actions",
            outcome.action_count
        ));
    }

    fn persist_incident_history(
        &self,
        outcome: &response::AutoResponseOutcome,
        trigger: String,
        score: u8,
    ) -> anyhow::Result<()> {
        if let Some(parent) = std::path::Path::new(&self.config.incident_history_path).parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.config.incident_history_path)?;
        let payload = serde_json::json!({
            "ts": Local::now().to_rfc3339(),
            "trigger": trigger,
            "security_score": score,
            "actions": outcome.action_count,
            "isolated_pids": outcome.isolated_pids,
            "quarantined_paths": outcome.quarantined_paths,
            "reverted_registry_entries": outcome.reverted_registry_entries,
            "snapshot_file": outcome.snapshot_file,
        });
        writeln!(file, "{}", serde_json::to_string(&payload)?)?;
        Ok(())
    }

    fn automation_tick(&mut self) {
        if !self.config.auto_scan_enabled {
            return;
        }
        if Instant::now() >= self.next_auto_scan_at {
            self.run_all_scans("Automatic");
        }
    }

    fn risk_color(risk: RiskLevel) -> Color32 {
        match risk {
            RiskLevel::Green => Color32::from_rgb(20, 198, 124),
            RiskLevel::Yellow => Color32::from_rgb(241, 181, 52),
            RiskLevel::Red => Color32::from_rgb(235, 81, 70),
        }
    }

    fn kernel_color(state: kernel::KernelServiceState) -> Color32 {
        match state {
            kernel::KernelServiceState::Running => Color32::from_rgb(20, 198, 124),
            kernel::KernelServiceState::Stopped => Color32::from_rgb(241, 181, 52),
            kernel::KernelServiceState::Missing | kernel::KernelServiceState::Unknown => {
                Color32::from_rgb(235, 81, 70)
            }
        }
    }

    fn automation_label(&self) -> String {
        if !self.config.auto_scan_enabled {
            return "AUTO: OFF".to_string();
        }
        let seconds = self
            .next_auto_scan_at
            .saturating_duration_since(Instant::now())
            .as_secs();
        format!("AUTO: {}s", seconds)
    }
}

impl eframe::App for StrongholdApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        apply_theme(ctx);
        ctx.request_repaint_after(Duration::from_millis(250));
        self.automation_tick();

        egui::TopBottomPanel::top("top_bar")
            .frame(
                egui::Frame::new()
                    .fill(Color32::from_rgb(14, 20, 32))
                    .inner_margin(egui::Margin::same(10)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("STRONGHOLD").size(22.0).strong());
                    ui.label(RichText::new("NATIVE SECURITY CORE").color(Color32::from_gray(170)));
                    ui.separator();

                    if ui
                        .button(tr(self.language, "Run Full Scan", "Vollscan starten"))
                        .clicked()
                    {
                        self.run_all_scans("Manual");
                    }

                    if ui.button("EN").clicked() {
                        self.language = Language::En;
                        self.config.default_language = "en".to_string();
                    }
                    if ui.button("DE").clicked() {
                        self.language = Language::De;
                        self.config.default_language = "de".to_string();
                    }

                    ui.separator();
                    let auto_color = if self.config.auto_scan_enabled {
                        Color32::from_rgb(80, 180, 230)
                    } else {
                        Color32::from_gray(140)
                    };
                    ui.colored_label(auto_color, self.automation_label());
                    ui.separator();
                    ui.label(
                        RichText::new(format!("Status: {}", self.status_message))
                            .color(Color32::from_gray(170)),
                    );
                });
            });

        egui::SidePanel::left("nav")
            .resizable(false)
            .exact_width(210.0)
            .frame(
                egui::Frame::new()
                    .fill(Color32::from_rgb(11, 16, 26))
                    .inner_margin(egui::Margin::same(10)),
            )
            .show(ctx, |ui| {
                ui.label(RichText::new(tr(self.language, "Modules", "Module")).strong());
                ui.add_space(6.0);
                nav_button(ui, &mut self.tab, Tab::Dashboard, "Dashboard");
                nav_button(ui, &mut self.tab, Tab::Integrity, "System Integrity");
                nav_button(ui, &mut self.tab, Tab::Behavior, "Behavior Detection");
                nav_button(ui, &mut self.tab, Tab::Network, "Network Intelligence");
                nav_button(ui, &mut self.tab, Tab::HumanRisk, "Human Risk");
                nav_button(ui, &mut self.tab, Tab::Response, "Response Engine");
                nav_button(ui, &mut self.tab, Tab::Kernel, "Kernel Control");
                nav_button(ui, &mut self.tab, Tab::Settings, "Settings");

                ui.add_space(12.0);
                ui.separator();
                ui.label(RichText::new("Automation").strong());
                ui.label(format!("Scan runs: {}", self.scan_runs));
                ui.label(format!("Auto actions: {}", self.auto_actions_total));
                ui.label(format!(
                    "Uptime: {}s",
                    self.boot_instant.elapsed().as_secs()
                ));
            });

        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(Color32::from_rgb(9, 13, 21)))
            .show(ctx, |ui| {
                draw_backdrop(
                    ui,
                    self.last_dashboard.risk_level,
                    self.boot_instant.elapsed(),
                );
                ui.add_space(6.0);
                match self.tab {
                    Tab::Dashboard => render_dashboard(ui, self),
                    Tab::Integrity => render_integrity(ui, self),
                    Tab::Behavior => render_behavior(ui, self),
                    Tab::Network => render_network(ui, self),
                    Tab::HumanRisk => render_human_risk(ui, self),
                    Tab::Response => render_response(ui, self),
                    Tab::Kernel => render_kernel(ui, self),
                    Tab::Settings => render_settings(ui, self),
                }
            });
    }
}

fn apply_theme(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.visuals = egui::Visuals::dark();
    style.spacing.item_spacing = vec2(10.0, 10.0);
    style.spacing.button_padding = vec2(12.0, 8.0);
    style.visuals.widgets.active.bg_fill = Color32::from_rgb(35, 115, 190);
    style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(25, 90, 150);
    style.visuals.window_fill = Color32::from_rgb(12, 18, 28);
    ctx.set_style(style);
}

fn draw_backdrop(ui: &mut egui::Ui, risk: RiskLevel, elapsed: Duration) {
    let rect = ui.max_rect();
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 0.0, Color32::from_rgb(9, 13, 21));

    let accent = StrongholdApp::risk_color(risk);
    let pulse = (elapsed.as_secs_f32() * 0.8).sin() * 0.5 + 0.5;

    painter.circle_filled(
        egui::pos2(rect.left() + 120.0, rect.top() + 40.0),
        180.0 + pulse * 30.0,
        accent.gamma_multiply(0.12),
    );
    painter.circle_filled(
        egui::pos2(rect.right() - 80.0, rect.top() + 120.0),
        220.0 - pulse * 20.0,
        Color32::from_rgb(70, 140, 230).gamma_multiply(0.10),
    );
}

fn nav_button(ui: &mut egui::Ui, tab: &mut Tab, me: Tab, title: &str) {
    let selected = *tab == me;
    let fill = if selected {
        Color32::from_rgb(38, 112, 188)
    } else {
        Color32::from_rgb(20, 28, 43)
    };
    let text_color = if selected {
        Color32::WHITE
    } else {
        Color32::from_gray(195)
    };

    let button = egui::Button::new(RichText::new(title).color(text_color))
        .fill(fill)
        .stroke(Stroke::new(1.0, Color32::from_rgb(45, 60, 85)));

    if ui.add_sized([ui.available_width(), 30.0], button).clicked() {
        *tab = me;
    }
}

fn glass_card(ui: &mut egui::Ui, title: &str, accent: Color32, body: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new()
        .fill(Color32::from_rgb(14, 21, 33).gamma_multiply(0.96))
        .stroke(Stroke::new(1.0, accent.gamma_multiply(0.35)))
        .inner_margin(egui::Margin::same(12))
        .show(ui, |ui| {
            ui.label(RichText::new(title).color(accent).strong().size(16.0));
            ui.add_space(6.0);
            body(ui);
        });
}

fn metric_card(ui: &mut egui::Ui, title: &str, value: &str, accent: Color32) {
    glass_card(ui, title, accent, |ui| {
        ui.label(RichText::new(value).size(24.0).strong());
    });
}

fn render_dashboard(ui: &mut egui::Ui, app: &StrongholdApp) {
    let accent = StrongholdApp::risk_color(app.last_dashboard.risk_level);
    ui.heading(RichText::new("Command Center").size(26.0));

    ui.columns(2, |columns| {
        glass_card(&mut columns[0], "Security Gauge", accent, |ui| {
            draw_score_gauge(ui, app.last_dashboard.security_score, accent);
            ui.label(format!(
                "Risk level: {}",
                app.last_dashboard.risk_level.as_str()
            ));
        });

        glass_card(
            &mut columns[1],
            "Live Metrics",
            Color32::from_rgb(80, 160, 230),
            |ui| {
                metric_card(
                    ui,
                    "Active Threats",
                    &app.last_dashboard.active_threats.to_string(),
                    accent,
                );
                metric_card(
                    ui,
                    "Connections",
                    &app.last_dashboard.network_connections.to_string(),
                    Color32::from_rgb(80, 160, 230),
                );
                metric_card(
                    ui,
                    "Last Scan",
                    &app.last_dashboard.last_scan.format("%H:%M:%S").to_string(),
                    Color32::from_rgb(130, 140, 170),
                );
            },
        );
    });

    ui.add_space(8.0);
    glass_card(
        ui,
        "Automation Feed",
        Color32::from_rgb(100, 180, 250),
        |ui| {
            egui::ScrollArea::vertical()
                .max_height(210.0)
                .show(ui, |ui| {
                    for line in app.event_feed.iter().take(12) {
                        ui.label(line);
                    }
                });
        },
    );
}

fn draw_score_gauge(ui: &mut egui::Ui, score: u8, accent: Color32) {
    let (rect, _) =
        ui.allocate_exact_size(vec2(ui.available_width().min(320.0), 220.0), Sense::hover());
    let painter = ui.painter_at(rect);
    let center = rect.center();
    let radius = 74.0;

    painter.circle_stroke(
        center,
        radius,
        Stroke::new(14.0, Color32::from_rgb(45, 56, 72)),
    );

    let start = std::f32::consts::PI * 0.75;
    let end = std::f32::consts::PI * 2.25;
    let sweep = (end - start) * (score as f32 / 100.0);
    let steps = 80;
    let mut points = Vec::with_capacity(steps + 1);
    for i in 0..=steps {
        let t = start + (sweep * i as f32 / steps as f32);
        points.push(egui::pos2(
            center.x + t.cos() * radius,
            center.y + t.sin() * radius,
        ));
    }
    painter.add(Shape::line(points, Stroke::new(14.0, accent)));

    painter.text(
        center,
        Align2::CENTER_CENTER,
        format!("{}", score),
        FontId::proportional(42.0),
        Color32::WHITE,
    );
    painter.text(
        egui::pos2(center.x, center.y + 30.0),
        Align2::CENTER_CENTER,
        "SECURITY",
        FontId::proportional(12.0),
        Color32::from_gray(190),
    );
}

fn render_integrity(ui: &mut egui::Ui, app: &StrongholdApp) {
    let r = &app.integrity_report;
    let accent = StrongholdApp::risk_color(r.risk_level);
    glass_card(ui, "System Integrity Scanner", accent, |ui| {
        ui.label(format!("Score: {} ({})", r.score, r.risk_level.as_str()));
        ui.label(format!("Running processes: {}", r.running_processes));
        ui.label(format!("Startup items: {}", r.startup_items));
        ui.separator();
        ui.label("Missing critical files:");
        egui::ScrollArea::vertical()
            .max_height(280.0)
            .show(ui, |ui| {
                if r.missing_critical_files.is_empty() {
                    ui.colored_label(Color32::from_rgb(20, 198, 124), "No critical files missing");
                } else {
                    for f in &r.missing_critical_files {
                        ui.label(format!("- {f}"));
                    }
                }
            });
    });
}

fn render_behavior(ui: &mut egui::Ui, app: &StrongholdApp) {
    let r = &app.behavior_report;
    let accent = StrongholdApp::risk_color(r.risk_level);
    glass_card(ui, "Behavioral Threat Detection", accent, |ui| {
        ui.label(format!("Score: {} ({})", r.score, r.risk_level.as_str()));
        ui.label(format!(
            "High CPU patterns: {}",
            r.suspicious_processes.len()
        ));
        ui.label(format!(
            "High memory patterns: {}",
            r.high_memory_processes.len()
        ));
        ui.label(format!("Suspicious PIDs: {}", r.suspicious_pids.len()));
        ui.label(format!("File anomalies: {}", r.file_anomalies.len()));

        ui.separator();
        ui.label("Top suspicious processes:");
        for proc_line in r.suspicious_processes.iter().take(8) {
            ui.label(format!("- {proc_line}"));
        }
    });
}

fn render_network(ui: &mut egui::Ui, app: &StrongholdApp) {
    let r = &app.network_report;
    let accent = StrongholdApp::risk_color(r.risk_level);
    glass_card(ui, "Network Surveillance Layer", accent, |ui| {
        ui.label(format!("Score: {} ({})", r.score, r.risk_level.as_str()));
        ui.label(format!(
            "Active connections: {}",
            r.active_connections.len()
        ));
        ui.label(format!("DNS anomalies: {}", r.dns_anomalies.len()));
        ui.separator();

        let desired = vec2(ui.available_width(), 230.0);
        let (rect, _) = ui.allocate_exact_size(desired, Sense::hover());
        let painter = ui.painter_at(rect);
        painter.rect_stroke(
            rect,
            6.0,
            Stroke::new(1.0, Color32::from_rgb(45, 65, 95)),
            StrokeKind::Outside,
        );

        let center = rect.center();
        painter.circle_filled(center, 17.0, Color32::from_rgb(20, 198, 124));
        painter.text(
            center,
            Align2::CENTER_CENTER,
            "HOST",
            FontId::proportional(12.0),
            Color32::BLACK,
        );

        for (i, conn) in r.active_connections.iter().take(36).enumerate() {
            let angle = (i as f32 / 36.0) * std::f32::consts::TAU;
            let radius = 72.0 + (i % 4) as f32 * 15.0;
            let node = egui::pos2(
                center.x + radius * angle.cos(),
                center.y + radius * angle.sin(),
            );
            let rc = if conn.state == "ESTABLISHED" {
                Color32::from_rgb(80, 160, 230)
            } else {
                Color32::from_rgb(140, 145, 165)
            };
            painter.line_segment([center, node], Stroke::new(1.0, rc));
            painter.circle_filled(node, 4.0, rc);
        }

        ui.separator();
        egui::ScrollArea::vertical()
            .max_height(220.0)
            .show(ui, |ui| {
                for conn in r.active_connections.iter().take(80) {
                    ui.label(format!(
                        "{} {} -> {} [{}] pid={:?}",
                        conn.protocol, conn.local, conn.remote, conn.state, conn.pid
                    ));
                }
            });
    });
}

fn render_human_risk(ui: &mut egui::Ui, app: &StrongholdApp) {
    let r = &app.human_risk_report;
    let accent = StrongholdApp::risk_color(r.risk_level);
    glass_card(ui, "Human Risk Monitor", accent, |ui| {
        ui.label(format!("Score: {} ({})", r.score, r.risk_level.as_str()));
        ui.label(format!("Unsafe downloads: {}", r.unsafe_downloads.len()));
        ui.label(format!(
            "Weak-password accounts: {}",
            r.weak_password_accounts.len()
        ));
        ui.label(format!("Risk actions: {}", r.risky_actions.len()));

        ui.separator();
        ui.label("Risk actions detected:");
        for entry in r.risky_actions.iter().take(10) {
            ui.label(format!("- {entry}"));
        }
    });
}

fn render_response(ui: &mut egui::Ui, app: &mut StrongholdApp) {
    glass_card(
        ui,
        "Isolation & Response Engine",
        Color32::from_rgb(240, 130, 75),
        |ui| {
            ui.horizontal(|ui| {
                ui.label("PID");
                ui.text_edit_singleline(&mut app.isolate_pid_input);
                if ui.button("Isolate Process").clicked() {
                    match app.isolate_pid_input.trim().parse::<u32>() {
                        Ok(pid) => match response::isolate_process(pid) {
                            Ok(_) => {
                                app.response_report.isolated_processes.push(pid);
                                app.status_message = format!("Process isolated: {pid}");
                                app.push_event(app.status_message.clone());
                                let incident = response::AutoResponseOutcome {
                                    isolated_pids: vec![pid],
                                    action_count: 1,
                                    ..Default::default()
                                };
                                let _ = app.persist_incident_history(
                                    &incident,
                                    "manual-isolate".to_string(),
                                    app.last_dashboard.security_score,
                                );
                            }
                            Err(e) => app.status_message = format!("Isolation failed: {e}"),
                        },
                        Err(_) => app.status_message = "Invalid PID".to_string(),
                    }
                }
            });

            ui.horizontal(|ui| {
                ui.label("File");
                ui.text_edit_singleline(&mut app.quarantine_path_input);
                if ui.button("Quarantine File").clicked() {
                    match response::quarantine_file(
                        app.quarantine_path_input.trim(),
                        &app.config.quarantine_dir,
                    ) {
                        Ok(path) => {
                            app.response_report.quarantined_files.push(path.clone());
                            app.status_message = format!("File quarantined: {path}");
                            app.push_event(app.status_message.clone());
                            let incident = response::AutoResponseOutcome {
                                quarantined_paths: vec![path],
                                action_count: 1,
                                ..Default::default()
                            };
                            let _ = app.persist_incident_history(
                                &incident,
                                "manual-quarantine".to_string(),
                                app.last_dashboard.security_score,
                            );
                        }
                        Err(e) => app.status_message = format!("Quarantine failed: {e}"),
                    }
                }
            });

            ui.horizontal(|ui| {
                if ui.button("Revert Registry Changes").clicked() {
                    app.response_report.reverted_registry_entries =
                        response::revert_registry_changes();
                    let revert_count = app.response_report.reverted_registry_entries.len();
                    app.status_message = format!("Registry entries reverted: {}", revert_count);
                    app.push_event(app.status_message.clone());
                    if revert_count > 0 {
                        let incident = response::AutoResponseOutcome {
                            reverted_registry_entries: app
                                .response_report
                                .reverted_registry_entries
                                .clone(),
                            action_count: 1,
                            ..Default::default()
                        };
                        let _ = app.persist_incident_history(
                            &incident,
                            "manual-registry-revert".to_string(),
                            app.last_dashboard.security_score,
                        );
                    }
                }

                if ui.button("Create System Snapshot").clicked() {
                    let snapshot = "logs/system_snapshot.json";
                    match response::create_system_snapshot(snapshot) {
                        Ok(path) => {
                            app.response_report.snapshot_file = Some(path.clone());
                            app.status_message = "System snapshot created".to_string();
                            app.push_event(app.status_message.clone());
                            let incident = response::AutoResponseOutcome {
                                snapshot_file: Some(path),
                                action_count: 1,
                                ..Default::default()
                            };
                            let _ = app.persist_incident_history(
                                &incident,
                                "manual-snapshot".to_string(),
                                app.last_dashboard.security_score,
                            );
                        }
                        Err(e) => app.status_message = format!("Snapshot failed: {e}"),
                    }
                }
            });

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
        },
    );
}

fn render_kernel(ui: &mut egui::Ui, app: &mut StrongholdApp) {
    let accent = StrongholdApp::kernel_color(app.kernel_state);
    glass_card(ui, "Kernel Control Plane", accent, |ui| {
        let label = match app.kernel_state {
            kernel::KernelServiceState::Running => "Running",
            kernel::KernelServiceState::Stopped => "Stopped",
            kernel::KernelServiceState::Missing => "Missing",
            kernel::KernelServiceState::Unknown => "Unknown",
        };

        ui.colored_label(
            accent,
            format!("Service {}: {label}", app.config.kernel_service_name),
        );

        ui.horizontal(|ui| {
            if ui.button("Refresh State").clicked() {
                app.kernel_state = kernel::query_service_state(&app.config.kernel_service_name)
                    .unwrap_or(kernel::KernelServiceState::Unknown);
            }
            if ui.button("Start Service").clicked() {
                match kernel::start_service(&app.config.kernel_service_name) {
                    Ok(_) => {
                        app.status_message = "Kernel service start requested".to_string();
                        app.push_event(app.status_message.clone());
                        app.kernel_state =
                            kernel::query_service_state(&app.config.kernel_service_name)
                                .unwrap_or(kernel::KernelServiceState::Unknown);
                    }
                    Err(e) => app.status_message = format!("Failed to start service: {e}"),
                }
            }
        });

        ui.separator();
        ui.label("Kernel driver enforcement requires a signed Windows driver package.");
        ui.label("Stronghold controls and monitors the configured kernel service from user mode.");
    });
}

fn render_settings(ui: &mut egui::Ui, app: &mut StrongholdApp) {
    glass_card(ui, "Settings", Color32::from_rgb(100, 170, 240), |ui| {
        ui.horizontal(|ui| {
            ui.label("Language");
            ui.text_edit_singleline(&mut app.config.default_language);
        });

        ui.add(
            egui::Slider::new(&mut app.config.cpu_alert_percent, 10.0..=100.0).text("CPU alert %"),
        );
        ui.add(
            egui::Slider::new(&mut app.config.memory_alert_mb, 128..=32768).text("Memory alert MB"),
        );

        ui.horizontal(|ui| {
            ui.label("Quarantine dir");
            ui.text_edit_singleline(&mut app.config.quarantine_dir);
        });

        ui.horizontal(|ui| {
            ui.label("Kernel service");
            ui.text_edit_singleline(&mut app.config.kernel_service_name);
        });

        ui.horizontal(|ui| {
            ui.label("Scan history file");
            ui.text_edit_singleline(&mut app.config.scan_history_path);
        });

        ui.horizontal(|ui| {
            ui.label("Scan summary file");
            ui.text_edit_singleline(&mut app.config.scan_summary_path);
        });

        ui.horizontal(|ui| {
            ui.label("Incident history file");
            ui.text_edit_singleline(&mut app.config.incident_history_path);
        });

        ui.separator();
        ui.checkbox(&mut app.config.auto_scan_enabled, "Enable automatic scans");
        ui.add(
            egui::Slider::new(
                &mut app.config.auto_scan_interval_seconds,
                MIN_AUTO_SCAN_SECONDS..=3600,
            )
            .text("Auto scan interval (seconds)"),
        );

        ui.checkbox(
            &mut app.config.auto_response_enabled,
            "Enable automatic response actions",
        );
        ui.add(
            egui::Slider::new(&mut app.config.max_auto_isolations_per_cycle, 0..=10)
                .text("Auto isolate max / cycle"),
        );
        ui.add(
            egui::Slider::new(&mut app.config.max_auto_quarantines_per_cycle, 0..=10)
                .text("Auto quarantine max / cycle"),
        );

        ui.checkbox(&mut app.config.enable_ai_module, "Enable local AI module");

        if ui.button("Save Settings").clicked() {
            match app.config.save(CONFIG_PATH) {
                Ok(_) => {
                    app.status_message = "Settings saved".to_string();
                    app.schedule_next_auto_scan();
                    app.push_event("Settings updated");
                }
                Err(e) => app.status_message = format!("Failed to save settings: {e}"),
            }
        }
    });
}
