use eframe::egui;
use std::collections::VecDeque;
use chrono::{DateTime, Utc};
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use crate::CapturedPacket;

const MAX_ALERTS: usize = 100;

// Apple-style colors
const BACKGROUND: egui::Color32 = egui::Color32::from_rgb(28, 28, 30);
// const ACCENT: egui::Color32 = egui::Color32::from_rgb(0, 122, 255);
const DANGER: egui::Color32 = egui::Color32::from_rgb(255, 59, 48);
const WARNING: egui::Color32 = egui::Color32::from_rgb(255, 149, 0);
const SUCCESS: egui::Color32 = egui::Color32::from_rgb(52, 199, 89);
const TEXT: egui::Color32 = egui::Color32::from_rgb(242, 242, 247);
const SUBTLE: egui::Color32 = egui::Color32::from_rgb(99, 99, 102);

#[derive(Clone)]
#[allow(dead_code)]
pub struct Alert {
    pub timestamp: DateTime<Utc>,
    pub alert_type: String,
    pub source_ip: String,
    pub details: String,
    pub severity: String,
}

// Define tabs
enum ActiveTab {
    Monitor,
    Inspector,
}

pub struct IdsUI {
    alerts: VecDeque<Alert>,
    rx: Receiver<Alert>,
    paused: Arc<AtomicBool>,
    active_tab: ActiveTab,
    packet_rx: Receiver<CapturedPacket>,
    packets: VecDeque<CapturedPacket>,
}

impl IdsUI {
    pub fn new(alert_rx: Receiver<Alert>, packet_rx: Receiver<CapturedPacket>) -> Self {
        Self {
            alerts: VecDeque::with_capacity(MAX_ALERTS),
            rx: alert_rx,
            paused: Arc::new(AtomicBool::new(false)),
            active_tab: ActiveTab::Monitor,
            packet_rx,
            packets: VecDeque::with_capacity(500),
        }
    }

    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Relaxed)
    }

    pub fn get_pause_handle(&self) -> Arc<AtomicBool> {
        self.paused.clone()
    }

    pub fn add_alert(&mut self, alert: Alert) {
        self.alerts.push_front(alert);
        if self.alerts.len() > MAX_ALERTS {
            self.alerts.pop_back();
        }
    }

    fn add_packet(&mut self, pkt: CapturedPacket) {
        self.packets.push_front(pkt);
        if self.packets.len() > 500 {
            self.packets.pop_back();
        }
    }
}

impl eframe::App for IdsUI {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        setup_custom_style(ctx);

        // Minimal header
        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 8.0;
                ui.add(egui::Label::new(
                    egui::RichText::new("Network Monitor")
                        .color(TEXT)
                        .size(18.0)
                        .family(egui::FontFamily::Proportional)
                ));
                
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let pause_text = if self.is_paused() { "Resume" } else { "Pause" };
                    if ui.add(egui::Button::new(
                        egui::RichText::new(pause_text).size(14.0)
                    ).fill(if self.is_paused() { SUCCESS } else { DANGER }))
                    .clicked() {
                        self.paused.store(!self.is_paused(), Ordering::Relaxed);
                    }
                });
            });
            ui.add_space(12.0);
        });

        // Simple tab bar
        egui::TopBottomPanel::top("tab_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.button("Monitor").clicked() {
                    self.active_tab = ActiveTab::Monitor;
                }
                if ui.button("Inspector").clicked() {
                    self.active_tab = ActiveTab::Inspector;
                }
            });
        });

        // Process alerts
        if !self.is_paused() {
            while let Ok(alert) = self.rx.try_recv() {
                self.add_alert(alert);
            }
        }

        // Process new captured packets
        while let Ok(pkt) = self.packet_rx.try_recv() {
            self.add_packet(pkt);
        }

        // Switch UI based on current tab
        match self.active_tab {
            ActiveTab::Monitor => {
                // Main alert panel
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.add_space(8.0);
                    ui.heading("Alert Log");
                    ui.add_space(8.0);
                    egui::ScrollArea::vertical()
                        .auto_shrink([false; 2])
                        .show(ui, |ui| {
                            for alert in self.alerts.iter() {
                                draw_alert_card(ui, alert);
                            }
                        });
                });
            }
            ActiveTab::Inspector => {
                // Main inspector panel
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.add_space(8.0);
                    ui.heading("Network Inspector");
                    ui.add_space(8.0);
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        for pkt in &self.packets {
                            draw_packet_card(ui, pkt);
                        }
                    });
                });
            }
        }

        ctx.request_repaint();
    }
}

fn setup_custom_style(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(6.0, 6.0);
    style.visuals.widgets.noninteractive.rounding = 8.0.into();
    style.visuals.widgets.inactive.rounding = 8.0.into();
    style.visuals.widgets.hovered.rounding = 8.0.into();
    style.visuals.widgets.active.rounding = 8.0.into();
    style.visuals.window_rounding = 12.0.into();
    style.visuals.window_shadow.extrusion = 0.0;
    style.visuals.dark_mode = true;
    style.visuals.panel_fill = BACKGROUND;
    ctx.set_style(style);
}

fn draw_alert_card(ui: &mut egui::Ui, alert: &Alert) {
    let (color, icon) = match alert.severity.as_str() {
        "HIGH" => (DANGER, "⚠"),
        "MEDIUM" => (WARNING, "•"),
        _ => (SUCCESS, "•"),
    };

    egui::Frame::none()
        .fill(BACKGROUND)
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 8.0;
                ui.add(egui::Label::new(
                    egui::RichText::new(icon)
                        .color(color)
                        .size(16.0)
                ));
                
                ui.add(egui::Label::new(
                    egui::RichText::new(format!("{}", alert.timestamp.format("%H:%M:%S")))
                        .color(SUBTLE)
                        .monospace()
                        .size(13.0)
                ));

                ui.add(egui::Label::new(
                    egui::RichText::new(&alert.alert_type)
                        .color(TEXT)
                        .size(14.0)
                        .strong()
                ));

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.add(egui::Label::new(
                        egui::RichText::new(&alert.details)
                            .color(TEXT)
                            .size(13.0)
                            .monospace()
                    ));
                });
            });
        });
    ui.add_space(4.0);
}

fn draw_packet_card(ui: &mut egui::Ui, pkt: &CapturedPacket) {
    egui::Frame::none()
        .fill(BACKGROUND)
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 8.0;
                ui.add(egui::Label::new(
                    egui::RichText::new(format!("Timestamp: {}", pkt.timestamp.format("%H:%M:%S")))
                        .color(SUBTLE)
                        .monospace()
                        .size(13.0)
                ));
                ui.add(egui::Label::new(
                    egui::RichText::new(format!("Source IP: {}", pkt.source_ip))
                        .color(TEXT)
                        .size(14.0)
                        .strong()
                ));
                ui.add(egui::Label::new(
                    egui::RichText::new(format!("Destination IP: {}", pkt.dest_ip))
                        .color(TEXT)
                        .size(14.0)
                        .strong()
                ));
                ui.add(egui::Label::new(
                    egui::RichText::new(format!("Port: {}", pkt.port))
                        .color(TEXT)
                        .size(13.0)
                        .monospace()
                ));
            });
        });
    ui.add_space(4.0);
}
