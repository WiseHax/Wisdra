use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout, Alignment},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Paragraph, Row, Table},
    Terminal,
};
use std::{error::Error, io};
use crate::ghidra_bridge::WisdraReport;

pub fn render_dashboard(report: &WisdraReport) -> Result<(), Box<dyn Error>> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Run the UI loop
    let res = run_app(&mut terminal, report);

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("{:?}", err);
    }

    Ok(())
}

fn run_app<B: Backend>(terminal: &mut Terminal<B>, report: &WisdraReport) -> io::Result<()> {
    loop {
        terminal.draw(|f| {
            // Split the screen vertically into a Header and the main content area
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(2)
                .constraints(
                    [
                        Constraint::Length(3), // Header
                        Constraint::Min(0),    // Main content
                        Constraint::Length(1), // Footer (instructions)
                    ]
                    .as_ref(),
                )
                .split(f.area());

            // Split the main content horizontally into Left Panel (Threat), Middle Panel (API), and Right Panel (Vulns)
            let main_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints(
                    [
                        Constraint::Percentage(25),
                        Constraint::Percentage(35),
                        Constraint::Percentage(40),
                    ]
                    .as_ref(),
                )
                .split(chunks[1]);

            // =========================================================================
            // HEADER
            // =========================================================================
            let header = Paragraph::new("WISDRA :: THREAT INTELLIGENCE DASHBOARD")
                .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
                .alignment(Alignment::Center)
                .block(Block::default().borders(Borders::ALL).style(Style::default().fg(Color::DarkGray)));
            f.render_widget(header, chunks[0]);

            // =========================================================================
            // LEFT PANEL: Threat Assessment
            // =========================================================================
            let risk_color = match report.threat_indicators.risk_label.as_str() {
                "CRITICAL" => Color::Red,
                "HIGH" => Color::LightRed,
                "MODERATE" => Color::Yellow,
                _ => Color::Green,
            };

            let mitre_mappings = crate::mitre::map_to_mitre(report);
            let mut mitre_summary = String::new();
            if !mitre_mappings.is_empty() {
                mitre_summary.push_str("\nMITRE ATT&CK:\n");
                for (_i, m) in mitre_mappings.iter().take(4).enumerate() {
                    mitre_summary.push_str(&format!("- {} ({})\n", m.technique, m.id));
                }
                if mitre_mappings.len() > 4 {
                    mitre_summary.push_str(&format!("  ... and {} more\n", mitre_mappings.len() - 4));
                }
            } else {
                mitre_summary.push_str("\nMITRE ATT&CK: None mapped\n");
            }

            let assessment_text = format!(
                "\nTarget File: {}\nSHA-256: {}\n\nOverall Risk: {} (Score: {})\n\nVulnerabilities:\n- Total: {}\n- Critical: {}\n- Kill Chains: {}\n- Deobfuscated: {}\n\nPacking Detected: {}{}",
                report.metadata.file_name,
                report.metadata.sha256,
                report.threat_indicators.risk_label,
                report.threat_indicators.risk_score,
                report.threat_indicators.vulnerability_count,
                report.threat_indicators.critical_vulns,
                report.threat_indicators.kill_chain_count,
                report.threat_indicators.deobfuscation_artifacts,
                if report.threat_indicators.packing_detected { "YES (High Entropy)" } else { "NO" },
                mitre_summary
            );

            let left_panel = Paragraph::new(assessment_text)
                .style(Style::default().fg(Color::White))
                .block(
                    Block::default()
                        .title(" Threat Assessment ")
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(risk_color))
                );
            f.render_widget(left_panel, main_chunks[0]);

            // =========================================================================
            // MIDDLE PANEL: API Heuristics
            // =========================================================================
            // Build table rows for categorized APIs
            let mut api_rows = Vec::new();
            
            for api in &report.threat_indicators.anti_debug {
                api_rows.push(Row::new(vec![
                    "<anti_debug>".to_string(),
                    api.clone()
                ]).style(Style::default().fg(Color::Yellow)));
            }
            
            for api in &report.threat_indicators.suspicious_imports {
                // If it was already included in anti_debug, skip to avoid dupes in this view
                if !report.threat_indicators.anti_debug.contains(api) {
                    api_rows.push(Row::new(vec![
                        "<suspicious>".to_string(),
                        api.clone()
                    ]).style(Style::default().fg(Color::LightRed)));
                }
            }

            if api_rows.is_empty() {
                api_rows.push(Row::new(vec!["-".to_string(), "No dangerous APIs detected.".to_string()]));
            }

            let table = Table::new(api_rows, [Constraint::Percentage(40), Constraint::Percentage(60)])
                .header(
                    Row::new(vec!["CATEGORY", "WINDOWS API"])
                        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
                        .bottom_margin(1),
                )
                .block(Block::default().title(" Suspicious Operations ").borders(Borders::ALL).border_style(Style::default().fg(Color::DarkGray)))
                .column_spacing(2);
                
            f.render_widget(table, main_chunks[1]);

            // =========================================================================
            // RIGHT PANEL: Vulnerability Intelligence
            // =========================================================================
            let mut vuln_rows = Vec::new();

            for vuln in &report.vulnerabilities {
                let sev_color = match vuln.severity.as_str() {
                    "CRITICAL" => Color::Red,
                    "HIGH" => Color::LightRed,
                    "MEDIUM" => Color::Yellow,
                    _ => Color::Green,
                };
                
                vuln_rows.push(Row::new(vec![
                    vuln.cwe.clone(),
                    vuln.severity.clone(),
                    vuln.dangerous_function.clone(),
                    vuln.caller_address.clone(),
                ]).style(Style::default().fg(sev_color)));
            }

            if vuln_rows.is_empty() {
                vuln_rows.push(Row::new(vec!["-".to_string(), "-".to_string(), "No vulnerabilities detected.".to_string(), "-".to_string()]));
            }

            let vuln_table = Table::new(vuln_rows, [
                Constraint::Percentage(15), 
                Constraint::Percentage(15), 
                Constraint::Percentage(40), 
                Constraint::Percentage(30)
            ])
                .header(
                    Row::new(vec!["CWE", "SEV", "FUNCTION", "CALL_SITE"])
                        .style(Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD))
                        .bottom_margin(1),
                )
                .block(Block::default().title(" Vulnerability Intelligence (P-CODE) ").borders(Borders::ALL).border_style(Style::default().fg(Color::DarkGray)))
                .column_spacing(1);

            f.render_widget(vuln_table, main_chunks[2]);

            // =========================================================================
            // FOOTER
            // =========================================================================
            let footer = Paragraph::new("Press 'q' or 'Esc' to exit")
                .style(Style::default().fg(Color::DarkGray))
                .alignment(Alignment::Right);
            f.render_widget(footer, chunks[2]);
            
        }).map_err(|e| io::Error::other(e.to_string()))?;

        // Handle Input
        if event::poll(std::time::Duration::from_millis(50))?
            && let Event::Key(key) = event::read()?
                && (key.code == KeyCode::Char('q') || key.code == KeyCode::Esc) {
                    return Ok(());
                }
    }
}
