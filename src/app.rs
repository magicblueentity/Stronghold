use crate::{
    config::AppConfig,
    engine,
    i18n::{
        module_label, network_anomaly_text, risk_level_label, risky_action_text, tr,
        Language,
    },
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
            status_message: tr(language, "Ready", "Bereit").to_string(),
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
        app.push_event(tr(
            language,
            "Stronghold initialized",
            "Stronghold initialisiert",
        ));
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
            let msg = match self.language {
                Language::En => format!("Scan summary write failed: {e}"),
                Language::De => {
                    format!("Scan-Zusammenfassung konnte nicht geschrieben werden: {e}")
                }
            };
            self.push_event(msg);
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
        let prefix = match (trigger, self.language) {
            ("Manual", Language::En) => "Manual scan completed",
            ("Manual", Language::De) => "Manueller Scan abgeschlossen",
            ("Automatic", Language::En) => "Automatic scan completed",
            ("Automatic", Language::De) => "Automatischer Scan abgeschlossen",
            _ => "Scan completed",
        };
        self.status_message = match self.language {
            Language::En => format!(
                "{prefix} in {duration_ms} ms (score {})",
                self.last_dashboard.security_score
            ),
            Language::De => format!(
                "{prefix} in {duration_ms} ms (Wert {})",
                self.last_dashboard.security_score
            ),
        };
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
        let msg = match self.language {
            Language::En => format!(
                "Automation executed {} response actions",
                outcome.action_count
            ),
            Language::De => format!(
                "Automatisierung fuehrte {} Aktionen aus",
                outcome.action_count
            ),
        };
        self.push_event(msg);
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

    fn action_isolate_pid(&mut self, pid: u32, trigger: &str) {
        match response::isolate_process(pid) {
            Ok(_) => {
                if !self.response_report.isolated_processes.contains(&pid) {
                    self.response_report.isolated_processes.push(pid);
                }
                self.status_message = match self.language {
                    Language::En => format!("Process isolated: {pid}"),
                    Language::De => format!("Prozess isoliert: {pid}"),
                };
                self.push_event(self.status_message.clone());
                let incident = response::AutoResponseOutcome {
                    isolated_pids: vec![pid],
                    action_count: 1,
                    ..Default::default()
                };
                let _ = self.persist_incident_history(
                    &incident,
                    trigger.to_string(),
                    self.last_dashboard.security_score,
                );
            }
            Err(e) => {
                self.status_message = match self.language {
                    Language::En => format!("Isolation failed: {e}"),
                    Language::De => format!("Isolation fehlgeschlagen: {e}"),
                };
                self.push_event(self.status_message.clone());
            }
        }
    }

    fn action_quarantine_file(&mut self, file: &str, trigger: &str) {
        match response::quarantine_file(file, &self.config.quarantine_dir) {
            Ok(path) => {
                if !self.response_report.quarantined_files.contains(&path) {
                    self.response_report.quarantined_files.push(path.clone());
                }
                self.status_message = match self.language {
                    Language::En => format!("File quarantined: {path}"),
                    Language::De => format!("Datei quarantiniert: {path}"),
                };
                self.push_event(self.status_message.clone());
                let incident = response::AutoResponseOutcome {
                    quarantined_paths: vec![path],
                    action_count: 1,
                    ..Default::default()
                };
                let _ = self.persist_incident_history(
                    &incident,
                    trigger.to_string(),
                    self.last_dashboard.security_score,
                );
            }
            Err(e) => {
                self.status_message = match self.language {
                    Language::En => format!("Quarantine failed: {e}"),
                    Language::De => format!("Quarantaene fehlgeschlagen: {e}"),
                };
                self.push_event(self.status_message.clone());
            }
        }
    }

    fn action_revert_registry(&mut self, trigger: &str) {
        self.response_report.reverted_registry_entries = response::revert_registry_changes();
        let count = self.response_report.reverted_registry_entries.len();
        self.status_message = match self.language {
            Language::En => format!("Registry entries reverted: {count}"),
            Language::De => format!("Registry-Eintraege zurueckgesetzt: {count}"),
        };
        self.push_event(self.status_message.clone());

        if count > 0 {
            let incident = response::AutoResponseOutcome {
                reverted_registry_entries: self.response_report.reverted_registry_entries.clone(),
                action_count: 1,
                ..Default::default()
            };
            let _ = self.persist_incident_history(
                &incident,
                trigger.to_string(),
                self.last_dashboard.security_score,
            );
        }
    }

    fn action_create_snapshot(&mut self, trigger: &str) {
        let snapshot = "logs/system_snapshot.json";
        match response::create_system_snapshot(snapshot) {
            Ok(path) => {
                self.response_report.snapshot_file = Some(path.clone());
                self.status_message = tr(
                    self.language,
                    "System snapshot created",
                    "System-Snapshot erstellt",
                )
                .to_string();
                self.push_event(self.status_message.clone());
                let incident = response::AutoResponseOutcome {
                    snapshot_file: Some(path),
                    action_count: 1,
                    ..Default::default()
                };
                let _ = self.persist_incident_history(
                    &incident,
                    trigger.to_string(),
                    self.last_dashboard.security_score,
                );
            }
            Err(e) => {
                self.status_message = match self.language {
                    Language::En => format!("Snapshot failed: {e}"),
                    Language::De => format!("Snapshot fehlgeschlagen: {e}"),
                };
                self.push_event(self.status_message.clone());
            }
        }
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
            return tr(self.language, "AUTO: OFF", "AUTO: AUS").to_string();
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
                    ui.label(
                        RichText::new(tr(
                            self.language,
                            "NATIVE SECURITY CORE",
                            "NATIVE SICHERHEITS-KERN",
                        ))
                        .color(Color32::from_gray(170)),
                    );
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
                        RichText::new(format!(
                            "{}: {}",
                            tr(self.language, "Status", "Status"),
                            self.status_message
                        ))
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
                nav_button(
                    ui,
                    &mut self.tab,
                    Tab::Dashboard,
                    tr(self.language, "Dashboard", "Dashboard"),
                );
                nav_button(
                    ui,
                    &mut self.tab,
                    Tab::Integrity,
                    module_label(self.language, ModuleId::Integrity),
                );
                nav_button(
                    ui,
                    &mut self.tab,
                    Tab::Behavior,
                    module_label(self.language, ModuleId::Behavior),
                );
                nav_button(
                    ui,
                    &mut self.tab,
                    Tab::Network,
                    module_label(self.language, ModuleId::Network),
                );
                nav_button(
                    ui,
                    &mut self.tab,
                    Tab::HumanRisk,
                    module_label(self.language, ModuleId::HumanRisk),
                );
                nav_button(
                    ui,
                    &mut self.tab,
                    Tab::Response,
                    module_label(self.language, ModuleId::Response),
                );
                nav_button(
                    ui,
                    &mut self.tab,
                    Tab::Kernel,
                    module_label(self.language, ModuleId::Kernel),
                );
                nav_button(
                    ui,
                    &mut self.tab,
                    Tab::Settings,
                    tr(self.language, "Settings", "Einstellungen"),
                );

                ui.add_space(12.0);
                ui.separator();
                ui.label(
                    RichText::new(tr(self.language, "Automation", "Automatisierung")).strong(),
                );
                ui.label(format!(
                    "{}: {}",
                    tr(self.language, "Scan runs", "Scan-Laeufe"),
                    self.scan_runs
                ));
                ui.label(format!(
                    "{}: {}",
                    tr(self.language, "Auto actions", "Auto-Aktionen"),
                    self.auto_actions_total
                ));
                ui.label(format!(
                    "{}: {}s",
                    tr(self.language, "Uptime", "Laufzeit"),
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
    ui.heading(RichText::new(tr(app.language, "Command Center", "Kommandozentrale")).size(26.0));

    ui.columns(2, |columns| {
        glass_card(
            &mut columns[0],
            tr(app.language, "Security Gauge", "Sicherheitsanzeige"),
            accent,
            |ui| {
                draw_score_gauge(
                    ui,
                    app.last_dashboard.security_score,
                    accent,
                    tr(app.language, "SECURITY", "SICHERHEIT"),
                );
                ui.label(format!(
                    "{}: {}",
                    tr(app.language, "Risk level", "Risikostufe"),
                    risk_level_label(app.language, app.last_dashboard.risk_level)
                ));
            },
        );

        glass_card(
            &mut columns[1],
            tr(app.language, "Live Metrics", "Live-Metriken"),
            Color32::from_rgb(80, 160, 230),
            |ui| {
                metric_card(
                    ui,
                    tr(app.language, "Active Threats", "Aktive Bedrohungen"),
                    &app.last_dashboard.active_threats.to_string(),
                    accent,
                );
                metric_card(
                    ui,
                    tr(app.language, "Connections", "Verbindungen"),
                    &app.last_dashboard.network_connections.to_string(),
                    Color32::from_rgb(80, 160, 230),
                );
                metric_card(
                    ui,
                    tr(app.language, "Last Scan", "Letzter Scan"),
                    &app.last_dashboard.last_scan.format("%H:%M:%S").to_string(),
                    Color32::from_rgb(130, 140, 170),
                );
            },
        );
    });

    ui.add_space(8.0);
    glass_card(
        ui,
        tr(app.language, "Automation Feed", "Aktivitaets-Feed"),
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

fn draw_score_gauge(ui: &mut egui::Ui, score: u8, accent: Color32, label: &str) {
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
        label,
        FontId::proportional(12.0),
        Color32::from_gray(190),
    );
}

fn render_integrity(ui: &mut egui::Ui, app: &StrongholdApp) {
    let r = &app.integrity_report;
    let accent = StrongholdApp::risk_color(r.risk_level);
    glass_card(
        ui,
        tr(
            app.language,
            "System Integrity Scanner",
            "Systemintegritaets-Scan",
        ),
        accent,
        |ui| {
            ui.label(format!(
                "{}: {} ({})",
                tr(app.language, "Score", "Wert"),
                r.score,
                risk_level_label(app.language, r.risk_level)
            ));
            ui.label(format!(
                "{}: {}",
                tr(app.language, "Running processes", "Laufende Prozesse"),
                r.running_processes
            ));
            ui.label(format!(
                "{}: {}",
                tr(app.language, "Startup items", "Autostart-Eintraege"),
                r.startup_items
            ));
            ui.separator();
            ui.label(tr(
                app.language,
                "Missing critical files:",
                "Fehlende kritische Dateien:",
            ));
            egui::ScrollArea::vertical()
                .max_height(280.0)
                .show(ui, |ui| {
                    if r.missing_critical_files.is_empty() {
                        ui.colored_label(
                            Color32::from_rgb(20, 198, 124),
                            tr(
                                app.language,
                                "No critical files missing",
                                "Keine kritischen Dateien fehlen",
                            ),
                        );
                    } else {
                        for f in &r.missing_critical_files {
                            ui.label(format!("- {f}"));
                        }
                    }
                });
        },
    );
}

fn render_behavior(ui: &mut egui::Ui, app: &mut StrongholdApp) {
    let lang = app.language;
    let report = app.behavior_report.clone();
    let accent = StrongholdApp::risk_color(report.risk_level);

    glass_card(
        ui,
        tr(
            lang,
            "Behavioral Threat Detection",
            "Verhaltensbasierte Erkennung",
        ),
        accent,
        |ui| {
            ui.label(format!(
                "{}: {} ({})",
                tr(lang, "Score", "Wert"),
                report.score,
                risk_level_label(lang, report.risk_level)
            ));

            ui.horizontal_wrapped(|ui| {
                ui.label(format!(
                    "{}: {}",
                    tr(lang, "High CPU processes", "Prozesse mit hoher CPU"),
                    report.suspicious_processes.len()
                ));
                ui.label(format!(
                    "{}: {}",
                    tr(lang, "High memory processes", "Prozesse mit hohem RAM"),
                    report.high_memory_processes.len()
                ));
                ui.label(format!(
                    "{}: {}",
                    tr(lang, "File anomalies", "Datei-Anomalien"),
                    report.file_anomalies.len()
                ));
            });

            ui.separator();
            ui.label(RichText::new(tr(lang, "High CPU", "Hohe CPU")).strong());
            egui::ScrollArea::vertical()
                .max_height(220.0)
                .show(ui, |ui| {
                    egui::Grid::new("behavior_cpu_grid")
                        .striped(true)
                        .min_col_width(40.0)
                        .show(ui, |ui| {
                            ui.label(tr(lang, "PID", "PID"));
                            ui.label(tr(lang, "Name", "Name"));
                            ui.label(tr(lang, "CPU", "CPU"));
                            ui.label(tr(lang, "RAM", "RAM"));
                            ui.label("");
                            ui.end_row();

                            for p in report.suspicious_processes.iter().take(60) {
                                ui.label(p.pid.to_string());
                                ui.label(&p.name);
                                ui.label(format!("{:.1}%", p.cpu_percent));
                                ui.label(format!("{} MB", p.memory_mb));
                                if ui.button(tr(lang, "Isolate", "Isolieren")).clicked() {
                                    app.action_isolate_pid(p.pid, "ui-behavior-isolate");
                                }
                                ui.end_row();
                            }
                        });
                });

            ui.add_space(10.0);
            ui.label(RichText::new(tr(lang, "High memory", "Hoher RAM")).strong());
            egui::ScrollArea::vertical()
                .max_height(180.0)
                .show(ui, |ui| {
                    egui::Grid::new("behavior_mem_grid")
                        .striped(true)
                        .min_col_width(40.0)
                        .show(ui, |ui| {
                            ui.label(tr(lang, "PID", "PID"));
                            ui.label(tr(lang, "Name", "Name"));
                            ui.label(tr(lang, "RAM", "RAM"));
                            ui.end_row();

                            for p in report.high_memory_processes.iter().take(50) {
                                ui.label(p.pid.to_string());
                                ui.label(&p.name);
                                ui.label(format!("{} MB", p.memory_mb));
                                ui.end_row();
                            }
                        });
                });

            if !report.file_anomalies.is_empty() {
                ui.add_space(10.0);
                ui.separator();
                ui.label(RichText::new(tr(lang, "File anomalies", "Datei-Anomalien")).strong());
                egui::ScrollArea::vertical()
                    .max_height(160.0)
                    .show(ui, |ui| {
                        for path in report.file_anomalies.iter().take(40) {
                            ui.horizontal_wrapped(|ui| {
                                ui.label(path);
                                if ui.button(tr(lang, "Quarantine", "Quarantaene")).clicked() {
                                    app.action_quarantine_file(path, "ui-behavior-quarantine");
                                }
                            });
                        }
                    });
            }
        },
    );
}

fn render_network(ui: &mut egui::Ui, app: &StrongholdApp) {
    let r = &app.network_report;
    let accent = StrongholdApp::risk_color(r.risk_level);
    glass_card(
        ui,
        tr(
            app.language,
            "Network Surveillance Layer",
            "Netzwerk-Ueberwachung",
        ),
        accent,
        |ui| {
            ui.label(format!(
                "{}: {} ({})",
                tr(app.language, "Score", "Wert"),
                r.score,
                risk_level_label(app.language, r.risk_level)
            ));
            ui.label(format!(
                "{}: {}",
                tr(app.language, "Active connections", "Aktive Verbindungen"),
                r.active_connections.len()
            ));
            ui.label(format!(
                "{}: {}",
                tr(app.language, "Network anomalies", "Netzwerk-Anomalien"),
                r.dns_anomalies.len()
            ));

            if !r.dns_anomalies.is_empty() {
                ui.separator();
                ui.label(
                    RichText::new(tr(app.language, "Anomalies", "Anomalien"))
                        .strong()
                        .color(accent),
                );
                for a in r.dns_anomalies.iter().take(10) {
                    ui.label(format!("- {}", network_anomaly_text(app.language, a)));
                }
            }
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
        },
    );
}

fn render_human_risk(ui: &mut egui::Ui, app: &mut StrongholdApp) {
    let lang = app.language;
    let report = app.human_risk_report.clone();
    let accent = StrongholdApp::risk_color(report.risk_level);

    glass_card(
        ui,
        tr(lang, "Human Risk Monitor", "Menschliches Risiko"),
        accent,
        |ui| {
            ui.label(format!(
                "{}: {} ({})",
                tr(lang, "Score", "Wert"),
                report.score,
                risk_level_label(lang, report.risk_level)
            ));

            ui.horizontal_wrapped(|ui| {
                ui.label(format!(
                    "{}: {}",
                    tr(lang, "Unsafe downloads", "Unsichere Downloads"),
                    report.unsafe_downloads.len()
                ));
                ui.label(format!(
                    "{}: {}",
                    tr(lang, "Weak-password accounts", "Schwache-Passwort-Accounts"),
                    report.weak_password_accounts.len()
                ));
                ui.label(format!(
                    "{}: {}",
                    tr(lang, "Risk actions", "Risiko-Aktionen"),
                    report.risky_actions.len()
                ));
            });

            ui.separator();
            ui.label(
                RichText::new(tr(
                    lang,
                    "Risk actions detected",
                    "Erkannte Risiko-Aktionen",
                ))
                .strong(),
            );
            for action in report.risky_actions.iter().take(10) {
                ui.label(format!("- {}", risky_action_text(lang, action)));
            }

            if !report.weak_password_accounts.is_empty() {
                ui.add_space(8.0);
                ui.separator();
                ui.label(RichText::new(tr(lang, "Weak accounts", "Schwache Accounts")).strong());
                for acc in report.weak_password_accounts.iter().take(20) {
                    ui.label(format!("- {acc}"));
                }
            }

            if !report.unsafe_downloads.is_empty() {
                ui.add_space(8.0);
                ui.separator();
                ui.label(
                    RichText::new(tr(
                        lang,
                        "Recent executable downloads",
                        "Aktuelle EXE/MSI Downloads",
                    ))
                    .strong(),
                );
                egui::ScrollArea::vertical()
                    .max_height(220.0)
                    .show(ui, |ui| {
                        for f in report.unsafe_downloads.iter().take(30) {
                            ui.horizontal_wrapped(|ui| {
                                ui.label(&f.path);
                                if ui.button(tr(lang, "Quarantine", "Quarantaene")).clicked() {
                                    app.action_quarantine_file(&f.path, "ui-humanrisk-quarantine");
                                }
                            });
                            if let Some(modified) = f.modified {
                                ui.label(format!(
                                    "  {}: {}",
                                    tr(lang, "Modified", "Geaendert"),
                                    modified.format("%Y-%m-%d %H:%M")
                                ));
                            }
                        }
                    });
            }
        },
    );
}

fn render_response(ui: &mut egui::Ui, app: &mut StrongholdApp) {
    let lang = app.language;
    glass_card(
        ui,
        tr(lang, "Isolation & Response Engine", "Isolation & Reaktion"),
        Color32::from_rgb(240, 130, 75),
        |ui| {
            ui.horizontal(|ui| {
                ui.label(tr(lang, "PID", "PID"));
                ui.text_edit_singleline(&mut app.isolate_pid_input);
                if ui
                    .button(tr(lang, "Isolate process", "Prozess isolieren"))
                    .clicked()
                {
                    match app.isolate_pid_input.trim().parse::<u32>() {
                        Ok(pid) => app.action_isolate_pid(pid, "manual-isolate"),
                        Err(_) => {
                            app.status_message =
                                tr(lang, "Invalid PID", "Ungueltige PID").to_string();
                            app.push_event(app.status_message.clone());
                        }
                    }
                }
            });

            ui.horizontal(|ui| {
                ui.label(tr(lang, "File", "Datei"));
                ui.text_edit_singleline(&mut app.quarantine_path_input);
                if ui
                    .button(tr(lang, "Quarantine file", "Datei quarantinieren"))
                    .clicked()
                {
                    let path = app.quarantine_path_input.trim().to_string();
                    if path.is_empty() {
                        app.status_message =
                            tr(lang, "No file path provided", "Kein Dateipfad angegeben")
                                .to_string();
                        app.push_event(app.status_message.clone());
                    } else {
                        app.action_quarantine_file(&path, "manual-quarantine");
                    }
                }
            });

            ui.horizontal(|ui| {
                if ui
                    .button(tr(
                        lang,
                        "Revert registry changes",
                        "Registry zuruecksetzen",
                    ))
                    .clicked()
                {
                    app.action_revert_registry("manual-registry-revert");
                }

                if ui
                    .button(tr(
                        lang,
                        "Create system snapshot",
                        "System-Snapshot erstellen",
                    ))
                    .clicked()
                {
                    app.action_create_snapshot("manual-snapshot");
                }
            });

            ui.separator();
            ui.label(format!(
                "{}: {}",
                tr(lang, "Isolated processes", "Isolierte Prozesse"),
                app.response_report.isolated_processes.len()
            ));
            ui.label(format!(
                "{}: {}",
                tr(lang, "Quarantined files", "Quarantinierte Dateien"),
                app.response_report.quarantined_files.len()
            ));
            ui.label(format!(
                "{}: {}",
                tr(
                    lang,
                    "Registry entries reverted",
                    "Registry-Eintraege zurueckgesetzt"
                ),
                app.response_report.reverted_registry_entries.len()
            ));
            if let Some(snapshot) = &app.response_report.snapshot_file {
                ui.label(format!("{}: {snapshot}", tr(lang, "Snapshot", "Snapshot")));
            }
        },
    );
}

fn render_kernel(ui: &mut egui::Ui, app: &mut StrongholdApp) {
    let lang = app.language;
    let accent = StrongholdApp::kernel_color(app.kernel_state);
    glass_card(
        ui,
        tr(lang, "Kernel Control Plane", "Kernel-Kontrollpanel"),
        accent,
        |ui| {
            let label = match app.kernel_state {
                kernel::KernelServiceState::Running => tr(lang, "Running", "Laeuft"),
                kernel::KernelServiceState::Stopped => tr(lang, "Stopped", "Gestoppt"),
                kernel::KernelServiceState::Missing => tr(lang, "Missing", "Fehlt"),
                kernel::KernelServiceState::Unknown => tr(lang, "Unknown", "Unbekannt"),
            };

            ui.colored_label(
                accent,
                format!(
                    "{} {}: {label}",
                    tr(lang, "Service", "Service"),
                    app.config.kernel_service_name
                ),
            );

            ui.horizontal(|ui| {
                if ui
                    .button(tr(lang, "Refresh state", "Status aktualisieren"))
                    .clicked()
                {
                    app.kernel_state = kernel::query_service_state(&app.config.kernel_service_name)
                        .unwrap_or(kernel::KernelServiceState::Unknown);
                }
                if ui
                    .button(tr(lang, "Start service", "Service starten"))
                    .clicked()
                {
                    match kernel::start_service(&app.config.kernel_service_name) {
                        Ok(_) => {
                            app.status_message = tr(
                                lang,
                                "Kernel service start requested",
                                "Kernel-Service Start angefordert",
                            )
                            .to_string();
                            app.push_event(app.status_message.clone());
                            app.kernel_state =
                                kernel::query_service_state(&app.config.kernel_service_name)
                                    .unwrap_or(kernel::KernelServiceState::Unknown);
                        }
                        Err(e) => {
                            app.status_message = match lang {
                                Language::En => format!("Failed to start service: {e}"),
                                Language::De => {
                                    format!("Service konnte nicht gestartet werden: {e}")
                                }
                            }
                        }
                    }
                }
            });

            ui.separator();
            ui.label(tr(
                lang,
                "Kernel driver enforcement requires a signed Windows driver package.",
                "Kernel-Treiber erfordern ein signiertes Windows-Treiberpaket.",
            ));
            ui.label(tr(
                lang,
                "Stronghold controls and monitors the configured kernel service from user mode.",
                "Stronghold steuert und ueberwacht den Kernel-Service im User-Mode.",
            ));
        },
    );
}

fn render_settings(ui: &mut egui::Ui, app: &mut StrongholdApp) {
    let lang = app.language;
    glass_card(
        ui,
        tr(lang, "Settings", "Einstellungen"),
        Color32::from_rgb(100, 170, 240),
        |ui| {
            ui.label(RichText::new(tr(lang, "General", "Allgemein")).strong());
            ui.horizontal(|ui| {
                ui.label(tr(lang, "Language", "Sprache"));
                if ui
                    .radio_value(&mut app.language, Language::En, "English")
                    .clicked()
                {
                    app.config.default_language = "en".to_string();
                }
                if ui
                    .radio_value(&mut app.language, Language::De, "Deutsch")
                    .clicked()
                {
                    app.config.default_language = "de".to_string();
                }
            });

            ui.add(
                egui::Slider::new(&mut app.config.cpu_alert_percent, 10.0..=100.0).text(tr(
                    lang,
                    "CPU alert (%)",
                    "CPU Warnung (%)",
                )),
            );
            ui.add(
                egui::Slider::new(&mut app.config.memory_alert_mb, 128..=32768).text(tr(
                    lang,
                    "Memory alert (MB)",
                    "RAM Warnung (MB)",
                )),
            );

            ui.horizontal(|ui| {
                ui.label(tr(lang, "Quarantine directory", "Quarantaene-Ordner"));
                ui.text_edit_singleline(&mut app.config.quarantine_dir);
            });

            ui.horizontal(|ui| {
                ui.label(tr(lang, "Kernel service name", "Kernel-Service Name"));
                ui.text_edit_singleline(&mut app.config.kernel_service_name);
            });

            ui.add_space(8.0);
            ui.separator();
            ui.label(RichText::new(tr(lang, "Logging", "Logging")).strong());
            ui.horizontal(|ui| {
                ui.label(tr(lang, "Scan history file", "Scan-History Datei"));
                ui.text_edit_singleline(&mut app.config.scan_history_path);
            });
            ui.horizontal(|ui| {
                ui.label(tr(lang, "Scan summary file", "Scan-Summary Datei"));
                ui.text_edit_singleline(&mut app.config.scan_summary_path);
            });
            ui.horizontal(|ui| {
                ui.label(tr(lang, "Incident history file", "Incident-History Datei"));
                ui.text_edit_singleline(&mut app.config.incident_history_path);
            });

            ui.add_space(8.0);
            ui.separator();
            ui.label(RichText::new(tr(lang, "Automation", "Automatisierung")).strong());
            ui.checkbox(
                &mut app.config.auto_scan_enabled,
                tr(
                    lang,
                    "Enable automatic scans",
                    "Automatische Scans aktivieren",
                ),
            );
            ui.add(
                egui::Slider::new(
                    &mut app.config.auto_scan_interval_seconds,
                    MIN_AUTO_SCAN_SECONDS..=3600,
                )
                .text(tr(
                    lang,
                    "Auto scan interval (seconds)",
                    "Auto-Scan Intervall (Sekunden)",
                )),
            );

            ui.checkbox(
                &mut app.config.auto_response_enabled,
                tr(
                    lang,
                    "Enable automatic response actions",
                    "Automatische Reaktionsaktionen aktivieren",
                ),
            );
            ui.add(
                egui::Slider::new(&mut app.config.max_auto_isolations_per_cycle, 0..=10).text(tr(
                    lang,
                    "Auto isolate max / cycle",
                    "Auto-Isolation max / Zyklus",
                )),
            );
            ui.add(
                egui::Slider::new(&mut app.config.max_auto_quarantines_per_cycle, 0..=10).text(tr(
                    lang,
                    "Auto quarantine max / cycle",
                    "Auto-Quarantaene max / Zyklus",
                )),
            );

            ui.add_space(8.0);
            ui.separator();
            ui.label(RichText::new(tr(lang, "AI", "KI")).strong());
            ui.checkbox(
                &mut app.config.enable_ai_module,
                tr(
                    lang,
                    "Enable local AI module",
                    "Lokales KI-Modul aktivieren",
                ),
            );

            ui.add_space(10.0);
            if ui
                .button(tr(lang, "Save settings", "Einstellungen speichern"))
                .clicked()
            {
                match app.config.save(CONFIG_PATH) {
                    Ok(_) => {
                        app.status_message =
                            tr(lang, "Settings saved", "Einstellungen gespeichert").to_string();
                        app.schedule_next_auto_scan();
                        app.push_event(tr(lang, "Settings updated", "Einstellungen aktualisiert"));
                    }
                    Err(e) => {
                        app.status_message = match lang {
                            Language::En => format!("Failed to save settings: {e}"),
                            Language::De => {
                                format!("Einstellungen konnten nicht gespeichert werden: {e}")
                            }
                        }
                    }
                }
            }
        },
    );
}
