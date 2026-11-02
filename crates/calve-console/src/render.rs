//! Rendering. Pure functions of `App`; they never mutate state or talk to the backend.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use serde_json::Value;

use crate::graph;
use crate::input::{palette_items, selection};
use crate::model::{
    App, Connection, Focus, Hit, NAV, Overlay, PaletteItem, Route, Target, Width, nav_routes,
};
use crate::screens::{self, Body, Col, Screen, Table, visible_rows};
use crate::text::{self, fit, line, truncate};
use crate::theme::{Tone, state_tone};

pub fn draw(frame: &mut Frame<'_>, app: &App) {
    draw_screen(frame, app);
    scrub(frame.buffer_mut());
}

/// The last line of defence against disguised text: whatever a screen built, no control, bidi
/// or invisible character reaches the terminal.
pub fn scrub(buffer: &mut ratatui::buffer::Buffer) {
    for cell in &mut buffer.content {
        if cell.symbol().chars().any(text::disguises) {
            cell.set_symbol("\u{fffd}");
        }
    }
}

fn draw_screen(frame: &mut Frame<'_>, app: &App) {
    let area = frame.area();
    let screen = screens::build(app);
    let [top, body, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(1),
    ])
    .areas(area);
    top_bar(frame, app, top);
    let body = if app.drawer {
        let [main, drawer] =
            Layout::vertical([Constraint::Min(3), Constraint::Length(9)]).areas(body);
        activity_drawer(frame, app, drawer);
        main
    } else {
        body
    };
    if app.fullscreen {
        workspace(frame, app, &screen, body, true);
    } else {
        match app.width() {
            // Ctrl+B hides the navigation pane for room (§5.1).
            Width::Wide if app.panes_hidden => {
                let [main, inspector] =
                    Layout::horizontal([Constraint::Percentage(68), Constraint::Min(30)])
                        .areas(body);
                workspace(frame, app, &screen, main, app.focus != Focus::Inspector);
                inspector_pane(frame, app, &screen, inspector);
            }
            Width::Wide => {
                let [nav, main, inspector] = Layout::horizontal([
                    Constraint::Length(22),
                    Constraint::Percentage(58),
                    Constraint::Min(30),
                ])
                .areas(body);
                navigation(frame, app, nav);
                workspace(frame, app, &screen, main, app.focus == Focus::Workspace);
                inspector_pane(frame, app, &screen, inspector);
            }
            // At medium width Ctrl+B hides the inspector instead.
            Width::Medium if app.panes_hidden => {
                workspace(frame, app, &screen, body, true);
            }
            Width::Medium => {
                let [main, inspector] =
                    Layout::horizontal([Constraint::Percentage(62), Constraint::Min(28)])
                        .areas(body);
                workspace(frame, app, &screen, main, app.focus != Focus::Inspector);
                inspector_pane(frame, app, &screen, inspector);
            }
            Width::Narrow => match app.focus {
                Focus::Navigation => navigation(frame, app, body),
                Focus::Inspector => inspector_pane(frame, app, &screen, body),
                Focus::Workspace => workspace(frame, app, &screen, body, true),
            },
        }
    }
    footer_bar(frame, app, &screen, footer);
    for overlay in app
        .overlays
        .iter()
        .rev()
        .take(2)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
    {
        draw_overlay(frame, app, &screen, overlay, area);
    }
    notifications(frame, app, area);
    if !app.symbols.unicode {
        asciify(frame);
    }
}

/// ASCII mode (§14, §73): every glyph that is not ASCII becomes an ASCII stand-in, including
/// borders, so terminals without Unicode fonts stay legible.
fn asciify(frame: &mut Frame<'_>) {
    let area = frame.area();
    let buffer = frame.buffer_mut();
    for y in area.top()..area.bottom() {
        for x in area.left()..area.right() {
            let cell = &mut buffer[(x, y)];
            let symbol = cell.symbol();
            if symbol.is_ascii() {
                continue;
            }
            let replacement = match symbol {
                "─" | "━" | "═" => "-",
                "│" | "┃" | "║" | "▏" => "|",
                "┌" | "┐" | "└" | "┘" | "├" | "┤" | "┬" | "┴" | "┼" | "╭" | "╮" | "╯" | "╰" => {
                    "+"
                }
                "↑" => "^",
                "↓" => "v",
                "←" => "<",
                "→" | "▶" | "›" => ">",
                "·" | "—" | "–" => "-",
                "“" | "”" => "\"",
                "…" => ".",
                "█" => "#",
                "▲" => "^",
                "▼" => "v",
                _ => "?",
            };
            cell.set_symbol(replacement);
        }
    }
}

/// Every styled span is sanitized here: pack titles, worker output and extension text all pass
/// through, and a screen cannot forget to.
fn span(text: impl Into<String>, style: Style) -> Span<'static> {
    Span::styled(crate::text::sanitize(&text.into()), style)
}

fn top_bar(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let theme = &app.theme;
    let (glyph, tone, health) = health(app);
    let mut spans = vec![
        span(" Calve ", theme.accent().add_modifier(Modifier::BOLD)),
        span(" project: ", theme.muted()),
        span(
            line(if app.project.is_empty() {
                "—"
            } else {
                &app.project
            }),
            theme.text(),
        ),
    ];
    if !app.workspace.is_empty() {
        spans.push(span("  workspace: ", theme.muted()));
        spans.push(span(line(&app.workspace), theme.text()));
    }
    spans.push(span(format!("  {} ", app.route.title()), theme.heading()));
    spans.push(span(format!("  {glyph} {health}"), theme.tone(tone)));
    let right = format!("v{}  ^P Commands  ? Help ", app.version);
    let used: usize = spans.iter().map(|s| text::width(&s.content)).sum();
    let pad = (area.width as usize).saturating_sub(used + text::width(&right));
    if pad > 0 {
        spans.push(span(" ".repeat(pad), theme.text()));
        spans.push(span(right, theme.muted()));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// Health indicator (§6.1): symbol and text, never color alone.
pub fn health(app: &App) -> (&'static str, Tone, &'static str) {
    let s = &app.symbols;
    let degraded = app.value("status").is_some_and(|status| {
        ["recovery", "extension_problems", "provider_problems"]
            .iter()
            .any(|key| status[*key].as_array().is_some_and(|a| !a.is_empty()))
    });
    match app.connection {
        Connection::Connecting => (s.tone(Tone::Neutral), Tone::Neutral, "connecting"),
        Connection::Offline => (s.tone(Tone::Danger), Tone::Danger, "offline"),
        Connection::Disconnected => (s.tone(Tone::Warning), Tone::Warning, "daemon disconnected"),
        _ if degraded => (s.tone(Tone::Warning), Tone::Warning, "degraded"),
        Connection::Daemon => (s.tone(Tone::Running), Tone::Success, "healthy"),
        Connection::Local => (s.tone(Tone::Running), Tone::Success, "healthy · in-process"),
    }
}

fn footer_bar(frame: &mut Frame<'_>, app: &App, screen: &Screen, area: Rect) {
    let theme = &app.theme;
    let mut spans = Vec::new();
    if app.filter_editing || screen_filter(app, screen).is_some() {
        let filter = screen_filter(app, screen).unwrap_or_default();
        let what = if matches!(screen.body, Body::Diff(_) | Body::Log { .. }) {
            " /search: "
        } else {
            " /filter: "
        };
        spans.push(span(what, theme.accent()));
        spans.push(span(line(&filter), theme.text()));
        spans.push(span(
            if app.filter_editing {
                "▏  enter apply  esc clear  "
            } else {
                "  esc clear  "
            },
            theme.muted(),
        ));
    }
    let shown: Vec<&crate::model::Loaded> = current_keys(app)
        .iter()
        .filter_map(|key| app.loaded(key))
        .filter(|l| l.value.is_some())
        .collect();
    let stale = shown.iter().any(|l| l.error.is_some()) || !app.can_act();
    if stale && let Some(at) = shown.iter().map(|l| l.at).min() {
        // §6.2: cached content stays readable and says how old it is.
        spans.push(span(
            format!(
                " STALE · last update {} ago{}  ",
                text::relative(at, app.now),
                if app.can_act() {
                    ""
                } else {
                    " · actions disabled"
                }
            ),
            theme.tone(Tone::Warning),
        ));
    }
    if let Some(key) = table_key(screen)
        && let Some(count) = app
            .collections
            .get(key)
            .map(|c| c.marked.len())
            .filter(|n| *n > 0)
    {
        spans.push(span(
            format!(" {} {count} selected ", app.symbols.tone(Tone::Success)),
            theme.tone(Tone::Success),
        ));
    }
    if let Some(live) = live_marker(app) {
        spans.push(live);
    }
    let loading = current_keys(app).iter().any(|key| {
        app.loaded(key)
            .is_some_and(|l| l.loading && l.value.is_some())
    });
    if loading {
        spans.push(span(
            format!(" Refreshing{} ", app.symbols.ellipsis()),
            theme.muted(),
        ));
    }
    for (key, label) in screen
        .hints
        .iter()
        .take(if app.show_footer { 8 } else { 0 })
    {
        spans.push(span(format!(" {key} "), theme.accent()));
        spans.push(span(format!("{label} "), theme.muted()));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// `● LIVE` while following (§42.3, §28); `paused` once the user scrolled away.
fn live_marker(app: &App) -> Option<Span<'static>> {
    let following = match (&app.route, app.tab_name()) {
        (Route::Events, _) => app.events_live,
        (Route::Execution(_), Some("Output")) => app.log_follow,
        _ => return None,
    };
    Some(if following {
        span(
            format!(" {} LIVE ", app.symbols.tone(Tone::Running)),
            app.theme.tone(Tone::Running),
        )
    } else {
        span(" paused · f follow ", app.theme.muted())
    })
}

fn current_keys(app: &App) -> Vec<String> {
    crate::model::route_requests(&app.route)
        .into_iter()
        .map(|(key, _)| key)
        .collect()
}

fn screen_filter(app: &App, screen: &Screen) -> Option<String> {
    let key = table_key(screen)?;
    app.collections
        .get(key)
        .map(|c| c.filter.clone())
        .filter(|f| !f.is_empty() || app.filter_editing)
}

pub fn table_key(screen: &Screen) -> Option<&str> {
    match &screen.body {
        Body::Table(table) => Some(&table.key),
        Body::Graph(graph) => Some(&graph.key),
        Body::Diff(key) => Some(key),
        Body::Log { key, .. } => Some(key),
        _ => None,
    }
}

fn pane_block(app: &App, title: String, focused: bool) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(app.theme.border(focused))
        .title(span(
            format!(" {title} "),
            if focused {
                app.theme.heading()
            } else {
                app.theme.muted()
            },
        ))
}

fn navigation(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let theme = &app.theme;
    let focused = app.focus == Focus::Navigation;
    let block = pane_block(app, "Navigation".into(), focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let badge = |route: &Route| -> Option<usize> {
        match route {
            Route::ChangePacks => app
                .value("packs")
                .and_then(|p| p["counts"].as_object())
                .map(|c| c.values().filter_map(Value::as_u64).sum::<u64>() as usize),
            Route::Baselines => app
                .value("baselines")
                .and_then(Value::as_array)
                .map(Vec::len),
            Route::Inbox => app
                .value("status")
                .and_then(|s| s["attention_items"].as_u64())
                .map(|n| n as usize)
                .filter(|n| *n > 0),
            Route::Overview => app
                .value("overview")
                .and_then(|o| o["needs_attention"].as_array())
                .map(Vec::len)
                .filter(|n| *n > 0),
            _ => None,
        }
    };
    let mut lines = Vec::new();
    let mut index = 0;
    for (section, routes) in NAV {
        if !lines.is_empty() {
            lines.push(Line::from(""));
        }
        lines.push(Line::from(span(format!(" {section}"), theme.muted())));
        for route in routes.iter() {
            let current = app.route.section() == *route;
            let cursor = focused && app.nav_index == index;
            let marker = if current {
                app.symbols.selected_marker()
            } else {
                " "
            };
            let count = badge(route).map(|n| n.to_string()).unwrap_or_default();
            let width = inner.width as usize;
            let label = fit(
                &format!("{marker} {}", route.title()),
                width.saturating_sub(count.len() + 1),
                app.symbols.ellipsis(),
            );
            let style = if cursor {
                theme.selected(true)
            } else if current {
                theme.accent().add_modifier(Modifier::BOLD)
            } else {
                theme.text()
            };
            let row = inner.y + lines.len() as u16;
            if row < inner.y + inner.height {
                app.hits.borrow_mut().push((
                    Rect {
                        x: inner.x,
                        y: row,
                        width: inner.width,
                        height: 1,
                    },
                    Hit::Nav(index),
                ));
            }
            lines.push(Line::from(vec![
                span(label, style),
                span(format!("{count} "), theme.muted()),
            ]));
            index += 1;
        }
    }
    frame.render_widget(Paragraph::new(lines), inner);
}

fn workspace(frame: &mut Frame<'_>, app: &App, screen: &Screen, area: Rect, focused: bool) {
    let title = if app.fullscreen {
        format!(
            "Calve / {}{}",
            app.route.title(),
            app.tab_name()
                .map(|t| format!(" / {t}"))
                .unwrap_or_default()
        )
    } else {
        app.route.title()
    };
    let block = pane_block(app, text::line(&title), focused);
    let mut inner = block.inner(area);
    frame.render_widget(block, area);
    let tabs = app.route.tabs();
    if !tabs.is_empty() {
        let mut spans = Vec::new();
        let mut x = inner.x;
        // Tabs that do not fit scroll so the active one stays visible, marked ‹ › (§5.3).
        let widths: Vec<u16> = tabs.iter().map(|t| t.len() as u16 + 2).collect();
        let mut first = 0;
        while first < app.tab() && widths[first..=app.tab()].iter().sum::<u16>() + 2 > inner.width {
            first += 1;
        }
        if first > 0 {
            spans.push(span("‹", app.theme.muted()));
            x += 1;
        }
        for (index, name) in tabs.iter().enumerate().skip(first) {
            let width = name.len() as u16 + 2;
            if x + width + 1 > inner.x + inner.width {
                spans.push(span("›", app.theme.muted()));
                break;
            }
            app.hits.borrow_mut().push((
                Rect {
                    x,
                    y: inner.y,
                    width,
                    height: 1,
                },
                Hit::Tab(index),
            ));
            x += width;
            if index == app.tab() {
                spans.push(span(format!(" {name} "), app.theme.selected(focused)));
            } else {
                spans.push(span(format!(" {name} "), app.theme.muted()));
            }
        }
        frame.render_widget(
            Paragraph::new(Line::from(spans)),
            Rect { height: 1, ..inner },
        );
        inner.y += 2.min(inner.height);
        inner.height = inner.height.saturating_sub(2);
    }
    match &screen.body {
        Body::Table(table) => draw_table(frame, app, table, inner, focused),
        Body::Text(lines) => {
            let scroll = app
                .collections
                .get(&format!("text:{}", crate::model::tab_key(&app.route)))
                .map_or(0, |c| c.scroll);
            frame.render_widget(
                Paragraph::new(lines.clone())
                    .wrap(Wrap { trim: false })
                    .scroll((scroll as u16, 0)),
                inner,
            );
        }
        Body::Graph(graph) => draw_graph(frame, app, graph, inner),
        Body::Diff(_) => draw_diff(frame, app, inner, focused),
        Body::Log {
            key,
            header,
            lines,
            follow,
        } => draw_log(frame, app, key, header, lines, *follow, inner),
        Body::Status { tone, title, body } => {
            let mut lines = vec![
                Line::from(""),
                Line::from(span(
                    format!("{} {title}", app.symbols.tone(*tone)),
                    app.theme.tone(*tone).add_modifier(Modifier::BOLD),
                )),
            ];
            lines.push(Line::from(""));
            for text in body.lines() {
                lines.push(Line::from(span(text.to_owned(), app.theme.muted())));
            }
            frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
        }
    }
}

/// Drops the lowest-priority columns until the rest fit, then gives fill columns the slack.
pub fn fit_columns(columns: &[Col], width: u16) -> Vec<(usize, u16)> {
    let mut kept: Vec<usize> = (0..columns.len()).collect();
    let total = |kept: &[usize]| kept.iter().map(|&i| columns[i].width + 1).sum::<u16>();
    while total(&kept) > width && kept.len() > 1 {
        let worst = *kept
            .iter()
            .max_by_key(|&&i| (columns[i].priority, i))
            .expect("non-empty");
        if columns[worst].priority <= 1 && kept.iter().all(|&i| columns[i].priority <= 1) {
            break;
        }
        kept.retain(|&i| i != worst);
    }
    let slack = width.saturating_sub(total(&kept));
    let fills = kept.iter().filter(|&&i| columns[i].fill).count().max(1) as u16;
    kept.iter()
        .map(|&i| {
            let extra = if columns[i].fill { slack / fills } else { 0 };
            (i, columns[i].width + extra)
        })
        .collect()
}

fn draw_table(frame: &mut Frame<'_>, app: &App, table: &Table, area: Rect, focused: bool) {
    let theme = &app.theme;
    let ellipsis = app.symbols.ellipsis();
    let mut lines: Vec<Line<'static>> = Vec::new();
    if !table.chips.is_empty() {
        let mut spans = Vec::new();
        let filter = app
            .collections
            .get(&table.key)
            .map(|c| c.filter.clone())
            .unwrap_or_default();
        for (name, count) in &table.chips {
            let active = (name == "All" && filter.is_empty())
                || filter == format!("state:{}", name.to_lowercase());
            spans.push(span(
                format!(" {name} {count} "),
                if active {
                    theme.selected(focused)
                } else {
                    theme.muted()
                },
            ));
        }
        lines.push(Line::from(spans));
        lines.push(Line::from(""));
    }
    let filter = app
        .collections
        .get(&table.key)
        .map(|c| c.filter.clone())
        .unwrap_or_default();
    let visible = visible_rows(app, table);
    if visible.is_empty() {
        let (title, body) = if filter.is_empty() {
            table.empty.clone()
        } else {
            // A field this list does not have is named, never answered with silence (§10.1).
            let all: Vec<&screens::Row> =
                table.sections.iter().flat_map(|s| s.rows.iter()).collect();
            let unknown = screens::unknown_fields(&all, &filter);
            let mut known: Vec<&str> = all
                .iter()
                .flat_map(|r| r.search.iter().map(|(n, _)| *n))
                .filter(|n| !matches!(*n, "age" | "instant"))
                .collect();
            known.sort_unstable();
            known.dedup();
            (
                format!("Nothing matches “{}”.", line(&filter)),
                if unknown.is_empty() {
                    "esc clear filter".into()
                } else {
                    format!(
                        "{}: not a field of this list. Fields: {}. esc clear filter",
                        unknown.join(", "),
                        known.join(", ")
                    )
                },
            )
        };
        lines.push(Line::from(""));
        lines.push(Line::from(span(title, theme.heading())));
        if !body.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(span(body, theme.muted())));
        }
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
        return;
    }
    let selected = selection(app, table)
        .and_then(|index| visible.get(index))
        .map(|row| row.id.clone());
    // Entries are cheap references; only the visible window is formatted and styled (§71,
    // §96: lists of 10,000+ rows).
    enum Entry<'a> {
        Blank,
        Title(&'a str),
        Header(usize),
        Empty,
        Row(&'a screens::Row, usize),
    }
    let mut entries: Vec<Entry<'_>> = Vec::new();
    let mut fitted_by_section: Vec<Vec<(usize, u16)>> = Vec::new();
    for (s_index, section) in table.sections.iter().enumerate() {
        fitted_by_section.push(fit_columns(&section.columns, area.width));
        let rows: Vec<&screens::Row> = section
            .rows
            .iter()
            .filter(|row| screens::matches_filter(row, &filter))
            .collect();
        if rows.is_empty() && section.title.is_none() {
            continue;
        }
        if let Some(title) = &section.title {
            if !entries.is_empty() {
                entries.push(Entry::Blank);
            }
            entries.push(Entry::Title(title));
        }
        if section.columns.iter().any(|c| !c.title.is_empty()) {
            entries.push(Entry::Header(s_index));
        }
        if rows.is_empty() {
            entries.push(Entry::Empty);
        }
        for row in rows {
            entries.push(Entry::Row(row, s_index));
        }
    }
    let height = area.height as usize - lines.len().min(area.height as usize);
    let selected_line = entries
        .iter()
        .position(
            |e| matches!(e, Entry::Row(row, _) if Some(row.id.as_str()) == selected.as_deref()),
        )
        .unwrap_or(0);
    let scroll = selected_line.saturating_sub(height.saturating_sub(2));
    let total = entries.len();
    let top = area.y + lines.len() as u16;
    let marked = app.collections.get(&table.key).map(|c| &c.marked);
    for (offset, entry) in entries.iter().skip(scroll).take(height).enumerate() {
        let line = match entry {
            Entry::Blank => Line::from(""),
            Entry::Title(title) => {
                let rule = "─".repeat((area.width as usize).saturating_sub(text::width(title) + 1));
                let rule = if app.symbols.unicode {
                    rule
                } else {
                    "-".repeat(rule.chars().count())
                };
                Line::from(vec![
                    span(format!("{title} "), theme.heading()),
                    span(rule, Style::default().fg(theme.border)),
                ])
            }
            Entry::Header(s_index) => {
                let section = &table.sections[*s_index];
                Line::from(
                    fitted_by_section[*s_index]
                        .iter()
                        .map(|(i, w)| {
                            let sorted = (table.sections.len() == 1)
                                .then(|| app.collections.get(&table.key).and_then(|c| c.sort))
                                .flatten()
                                .filter(|(col, _)| col == i);
                            let title = match sorted {
                                Some((_, true)) => format!("{} ▼", section.columns[*i].title),
                                Some((_, false)) => format!("{} ▲", section.columns[*i].title),
                                None => section.columns[*i].title.to_owned(),
                            };
                            span(
                                format!("{} ", fit(&title, *w as usize, ellipsis)),
                                theme.muted(),
                            )
                        })
                        .collect::<Vec<_>>(),
                )
            }
            Entry::Empty => Line::from(span("  none", theme.muted())),
            Entry::Row(row, s_index) => {
                app.hits.borrow_mut().push((
                    Rect {
                        x: area.x,
                        y: top + offset as u16,
                        width: area.width,
                        height: 1,
                    },
                    Hit::Row {
                        key: table.key.clone(),
                        id: row.id.clone(),
                    },
                ));
                let is_selected = selected.as_deref() == Some(row.id.as_str());
                let mut spans: Vec<Span<'static>> = fitted_by_section[*s_index]
                    .iter()
                    .map(|(i, w)| {
                        let (text, style) = row
                            .cells
                            .get(*i)
                            .map_or(("", theme.text()), |c| (c.text.as_str(), c.style));
                        span(
                            format!("{} ", fit(text, *w as usize, ellipsis)),
                            if is_selected {
                                theme.selected(focused)
                            } else {
                                style
                            },
                        )
                    })
                    .collect();
                if marked.is_some_and(|m| m.contains(&row.id)) {
                    spans.insert(
                        0,
                        span(app.symbols.tone(Tone::Success), theme.tone(Tone::Success)),
                    );
                }
                Line::from(spans)
            }
        };
        lines.push(line);
    }
    frame.render_widget(Paragraph::new(lines), area);
    if total > height && area.height > 2 {
        // A scrollbar shows where the window is in a long list (§53).
        let mut state =
            ratatui::widgets::ScrollbarState::new(total.saturating_sub(height)).position(scroll);
        frame.render_stateful_widget(
            ratatui::widgets::Scrollbar::new(ratatui::widgets::ScrollbarOrientation::VerticalRight)
                .begin_symbol(None)
                .end_symbol(None)
                .track_symbol(Some("│"))
                .thumb_symbol("█"),
            Rect {
                y: top,
                height: area.height.saturating_sub(top - area.y + 1),
                ..area
            },
            &mut state,
        );
    }
    if (total > height || table.total.is_some()) && area.height > 0 {
        // Paged collections say how much is loaded of how much exists.
        let position = match table.total {
            Some(all) => format!(
                "{}/{} of {all}",
                selection(app, table).map_or(0, |i| i + 1),
                visible.len()
            ),
            None => format!(
                "{}/{}",
                selection(app, table).map_or(0, |i| i + 1),
                visible.len()
            ),
        };
        let rect = Rect {
            x: area.x + area.width.saturating_sub(position.len() as u16),
            y: area.y + area.height - 1,
            width: position.len() as u16,
            height: 1,
        };
        frame.render_widget(Paragraph::new(span(position, theme.muted())), rect);
    }
}

fn draw_graph(frame: &mut Frame<'_>, app: &App, graph_body: &screens::Graph, area: Rect) {
    let placement = graph::layout(graph_body.nodes.len(), &graph_body.edges);
    let selected = app
        .collections
        .get(&graph_body.key)
        .and_then(|c| c.selected_id.as_ref())
        .and_then(|id| graph_body.nodes.iter().position(|n| &n.id == id))
        .or(if graph_body.nodes.is_empty() {
            None
        } else {
            Some(0)
        });
    let filter = app
        .collections
        .get(&graph_body.key)
        .map(|c| c.filter.clone())
        .unwrap_or_default();
    let views: Vec<graph::NodeView<'_>> = graph_body
        .nodes
        .iter()
        .map(|n| graph::NodeView {
            label: &n.label,
            tone: n.tone,
            dim: !filter.is_empty() && !screens::matches_search(&n.search, &filter),
        })
        .collect();
    let mut lines = Vec::new();
    if graph_body.total > 200 && app.graph_depth.is_none() {
        lines.push(Line::from(span(
            format!(
                "Graph is large · {} nodes   v list view   f focus neighborhood",
                graph_body.total
            ),
            app.theme.tone(Tone::Warning),
        )));
    }
    if let Some(depth) = app.graph_depth {
        lines.push(Line::from(span(
            format!(
                "Neighborhood depth {depth} · {} of {} nodes   f wider",
                graph_body.nodes.len(),
                graph_body.total
            ),
            app.theme.muted(),
        )));
    }
    if !placement.cyclic.is_empty() {
        lines.push(Line::from(span(
            format!(
                "{} cycle: {} nodes placed last",
                app.symbols.tone(Tone::Warning),
                placement.cyclic.len()
            ),
            app.theme.tone(Tone::Warning),
        )));
    }
    let drawn = graph::render(
        &views,
        &graph_body.edges,
        &placement,
        selected,
        &app.theme,
        &app.symbols,
        area.width as usize,
    );
    // Edges the layers cannot route are listed, never dropped silently (§29.2).
    let mut footer: Vec<Line<'static>> = drawn
        .unrouted
        .iter()
        .map(|(from, to)| {
            Line::from(span(
                format!(
                    "{} not drawn: {} {} {}",
                    app.symbols.tone(Tone::Warning),
                    text::truncate(
                        &line(&graph_body.nodes[*from].label),
                        24,
                        app.symbols.ellipsis()
                    ),
                    app.symbols.arrow(),
                    text::truncate(
                        &line(&graph_body.nodes[*to].label),
                        24,
                        app.symbols.ellipsis()
                    ),
                ),
                app.theme.tone(Tone::Warning),
            ))
        })
        .collect();
    if graph_body.legend {
        let s = &app.symbols;
        footer.push(Line::from(span(
            format!(
                "{} running  {} complete  {} blocked  {} review  {} pending",
                s.tone(Tone::Running),
                s.tone(Tone::Success),
                s.tone(Tone::Warning),
                s.tone(Tone::Review),
                s.tone(Tone::Neutral)
            ),
            app.theme.muted(),
        )));
    }
    // Vertical scroll keeps the selected node in view (§29.1).
    let room = (area.height as usize).saturating_sub(lines.len() + footer.len() + 1);
    let row = selected.map_or(0, |n| placement.positions[n].1 * 2);
    let top = row.saturating_sub(room.saturating_sub(2));
    lines.extend(drawn.lines.into_iter().skip(top).take(room));
    lines.push(Line::from(""));
    lines.extend(footer);
    frame.render_widget(Paragraph::new(lines), area);
}

/// Output and raw text (§28, §24): only the visible window is styled; `/` matches are marked;
/// a following view stays on the newest line.
fn draw_log(
    frame: &mut Frame<'_>,
    app: &App,
    key: &str,
    header: &[Line<'static>],
    log: &[screens::LogLine],
    follow: bool,
    area: Rect,
) {
    let theme = &app.theme;
    let state = app.collections.get(key);
    let search = state.map(|c| c.filter.to_lowercase()).unwrap_or_default();
    let mut lines: Vec<Line<'static>> = header.to_vec();
    if !search.is_empty() {
        let hits = log
            .iter()
            .filter(|l| l.text.to_lowercase().contains(&search))
            .count();
        lines.push(Line::from(span(
            format!("/{search}: {hits} matches  n/N next/previous"),
            theme.muted(),
        )));
    }
    let wrap = app.wrap_logs && key.starts_with("output:");
    let height = (area.height as usize).saturating_sub(lines.len());
    let scroll = if follow && app.log_follow {
        log.len().saturating_sub(height)
    } else {
        state
            .map_or(0, |c| c.scroll)
            .min(log.len().saturating_sub(1))
    };
    for entry in log.iter().skip(scroll).take(height) {
        let hit = !search.is_empty() && entry.text.to_lowercase().contains(&search);
        let mut spans = Vec::new();
        if app.log_timestamps
            && let Some(at) = entry.at
        {
            spans.push(span(
                format!("{} ", text::clock(at, app.now)),
                theme.muted(),
            ));
        }
        let style = match (hit, entry.tone) {
            (true, _) => theme.selected(true),
            (false, Some(tone)) => theme.tone(tone),
            (false, None) => theme.text(),
        };
        let body = if wrap {
            entry.text.clone()
        } else {
            truncate(&entry.text, area.width as usize, app.symbols.ellipsis())
        };
        spans.push(span(body, style));
        lines.push(Line::from(spans));
    }
    let paragraph = Paragraph::new(lines);
    frame.render_widget(
        if wrap {
            paragraph.wrap(Wrap { trim: false })
        } else {
            paragraph
        },
        area,
    );
}

fn draw_diff(frame: &mut Frame<'_>, app: &App, area: Rect, focused: bool) {
    let Route::ChangePack(id) = &app.route else {
        return;
    };
    let Some(pack) = app.value(&format!("pack:{id}")) else {
        return;
    };
    let theme = &app.theme;
    // Borrowed, never copied per frame (§71).
    let files: &[Value] = pack["files"].as_array().map_or(&[], Vec::as_slice);
    if files.is_empty() {
        frame.render_widget(
            Paragraph::new(span("No files in this ChangePack.", theme.muted())),
            area,
        );
        return;
    }
    let files_key = format!("diff-files:{id}");
    let state = app.collections.get(&files_key);
    let index = state.map_or(0, |c| c.selected_index).min(files.len() - 1);
    let search = state.map(|c| c.filter.to_lowercase()).unwrap_or_default();
    // The file list stays down to a 48-column diff area (§33, Scenario C); below that the
    // header still says which file of how many is open.
    let list_width = (area.width / 3).clamp(14, 30);
    let [list_area, diff_area] = if app.fullscreen || area.width < 48 {
        [Rect { width: 0, ..area }, area]
    } else {
        let [list, _gap, diff] = Layout::horizontal([
            Constraint::Length(list_width),
            Constraint::Length(1),
            Constraint::Min(20),
        ])
        .areas(area);
        [list, diff]
    };
    if list_area.width > 0 {
        let mut lines = vec![Line::from(span(
            format!("{} files changed", files.len()),
            theme.muted(),
        ))];
        let height = list_area.height.saturating_sub(1) as usize;
        let start = index.saturating_sub(height.saturating_sub(1));
        for (i, file) in files.iter().enumerate().skip(start).take(height) {
            let counts = format!("+{} -{}", file["added"], file["removed"]);
            let room = (list_area.width as usize).saturating_sub(counts.len() + 1);
            let name = text::middle(
                &line(file["path"].as_str().unwrap_or("")),
                room,
                app.symbols.ellipsis(),
            );
            let style = if i == index {
                theme.selected(focused && !app.diff_lines)
            } else {
                theme.text()
            };
            lines.push(Line::from(vec![
                span(fit(&name, room, app.symbols.ellipsis()), style),
                span(
                    format!(" +{}", file["added"]),
                    Style::default().fg(theme.diff_add),
                ),
                span(
                    format!(" -{}", file["removed"]),
                    Style::default().fg(theme.diff_delete),
                ),
            ]));
        }
        frame.render_widget(Paragraph::new(lines), list_area);
    }
    let file = &files[index];
    let path = file["path"].as_str().unwrap_or("");
    let mut lines = vec![Line::from(vec![
        span(line(path), theme.heading()),
        span(
            format!("  file {}/{}", index + 1, files.len()),
            theme.muted(),
        ),
    ])];
    match app.value(&format!("diff:{id}:{path}")) {
        None => lines.push(Line::from(span(
            format!("Loading diff{}", app.symbols.ellipsis()),
            theme.muted(),
        ))),
        Some(diff) if diff["binary"] == true => {
            lines.push(Line::from(span(
                "Binary file changed",
                theme.tone(Tone::Warning),
            )));
            lines.push(Line::from(span(
                format!(
                    "old size: {}  new size: {}",
                    diff["old_size"], diff["new_size"]
                ),
                theme.muted(),
            )));
            lines.push(Line::from(span(
                format!("digest: {}", diff["digest"].as_str().unwrap_or("")),
                theme.muted(),
            )));
        }
        Some(diff) => {
            let all: &[Value] = diff["lines"].as_array().map_or(&[], Vec::as_slice);
            if !search.is_empty() {
                let matches = all
                    .iter()
                    .filter(|l| {
                        l["text"]
                            .as_str()
                            .is_some_and(|t| t.to_lowercase().contains(&search))
                    })
                    .count();
                lines.push(Line::from(span(
                    format!("/{search}: {matches} matches  n/N next/previous"),
                    theme.muted(),
                )));
            }
            if all.len() > 2000 {
                lines.push(Line::from(span(
                    format!(
                        "Large diff · {} lines · rendered window {}–{}",
                        all.len(),
                        app.diff_scroll + 1,
                        (app.diff_scroll + diff_area.height as usize).min(all.len())
                    ),
                    theme.muted(),
                )));
            }
            let height = diff_area.height.saturating_sub(lines.len() as u16) as usize;
            // Only the visible window is styled (§33.4).
            for entry in all.iter().skip(app.diff_scroll).take(height) {
                let kind = entry["kind"].as_str().unwrap_or("");
                let raw = entry["text"].as_str().unwrap_or("");
                let text = line(raw);
                let hit = !search.is_empty() && raw.to_lowercase().contains(&search);
                let number = |key: &str| {
                    entry[key]
                        .as_u64()
                        .map(|n| format!("{n:>4}"))
                        .unwrap_or_else(|| "    ".into())
                };
                let (marker, style) = match kind {
                    "add" => ("+", Style::default().fg(theme.diff_add)),
                    "delete" => ("-", Style::default().fg(theme.diff_delete)),
                    "hunk" => ("", Style::default().fg(theme.diff_hunk)),
                    _ => (" ", theme.text()),
                };
                if kind == "hunk" {
                    lines.push(Line::from(span(text, style)));
                    continue;
                }
                let width = (diff_area.width as usize).saturating_sub(12);
                let body = if app.diff_wrap {
                    text
                } else {
                    truncate(&text, width, app.symbols.ellipsis())
                };
                let mut spans = vec![
                    span(
                        format!("{} {} ", number("old"), number("new")),
                        if hit {
                            theme.selected(true)
                        } else {
                            theme.muted()
                        },
                    ),
                    span(marker.to_owned(), style),
                ];
                spans.extend(crate::highlight::spans(path, &body, style, theme));
                lines.push(Line::from(spans));
            }
            if diff["truncated"] == true {
                lines.push(Line::from(span(
                    "diff truncated",
                    theme.tone(Tone::Warning),
                )));
            }
        }
    }
    let paragraph = Paragraph::new(lines);
    let paragraph = if app.diff_wrap {
        paragraph.wrap(Wrap { trim: false })
    } else {
        paragraph
    };
    frame.render_widget(paragraph, diff_area);
}

fn inspector_pane(frame: &mut Frame<'_>, app: &App, screen: &Screen, area: Rect) {
    let focused = app.focus == Focus::Inspector;
    let block = pane_block(app, "Inspector".into(), focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let mut lines = screen.inspector.clone();
    if lines.is_empty() {
        lines.push(Line::from(span(
            "Select an item to inspect it.",
            app.theme.muted(),
        )));
    }
    let available: Vec<&PaletteItem> = screen
        .actions
        .iter()
        .filter(|a| a.group == "Actions")
        .collect();
    let scroll = app.collections.get("inspector").map_or(0, |c| c.scroll) as u16;
    if !available.is_empty() && app.can_act() {
        lines.push(Line::from(""));
        lines.push(Line::from(span("Actions", app.theme.heading())));
        for (i, action) in available.iter().take(6).enumerate() {
            // Clickable only when no line above wraps: wrapping shifts the rows actions land on,
            // and a click must never reach the wrong one (§53).
            let row = (lines.len() as u16).checked_sub(scroll);
            let wrapped = lines.iter().any(|l| l.width() > inner.width as usize);
            if let Some(row) = row.filter(|r| *r < inner.height && !wrapped) {
                app.hits.borrow_mut().push((
                    Rect {
                        x: inner.x,
                        y: inner.y + row,
                        width: inner.width,
                        height: 1,
                    },
                    Hit::Action(i),
                ));
            }
            lines.push(Line::from(vec![span(
                format!("  {}", line(&action.label)),
                app.theme.text(),
            )]));
        }
        lines.push(Line::from(span("  a all actions", app.theme.muted())));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0)),
        inner,
    );
}

/// Recent console actions beside the newest daemon events (§43); not the audit stream.
fn activity_drawer(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let block = pane_block(app, "Activity".into(), false);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let [left, right] =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(inner);
    let mut actions: Vec<Line<'static>> = vec![Line::from(span("Console", app.theme.heading()))];
    actions.extend(
        app.activity
            .iter()
            .rev()
            .take((inner.height as usize).saturating_sub(1))
            .map(|(_, tone, text)| {
                Line::from(vec![
                    span(
                        format!("{} ", app.symbols.tone(*tone)),
                        app.theme.tone(*tone),
                    ),
                    span(line(text), app.theme.text()),
                ])
            }),
    );
    if actions.len() == 1 {
        actions.push(Line::from(span(
            "No console actions yet.",
            app.theme.muted(),
        )));
    }
    frame.render_widget(Paragraph::new(actions), left);
    let mut events: Vec<Line<'static>> =
        vec![Line::from(span("Daemon events", app.theme.heading()))];
    match app.value("events").and_then(Value::as_array) {
        Some(list) if !list.is_empty() => events.extend(
            list.iter()
                .take((inner.height as usize).saturating_sub(1))
                .map(|e| {
                    let time = e["timestamp"]
                        .as_str()
                        .or(e["created_at"].as_str())
                        .and_then(|t| text::unix_seconds(&Value::from(t)))
                        .map(|t| text::clock(t, app.now))
                        .unwrap_or_default();
                    Line::from(vec![
                        span(format!("{time:<10}"), app.theme.muted()),
                        span(line(e["kind"].as_str().unwrap_or("")), app.theme.text()),
                        span(
                            format!(
                                " {}",
                                text::short_id(
                                    e["subject"].as_str().unwrap_or(""),
                                    16,
                                    app.symbols.ellipsis()
                                )
                            ),
                            app.theme.accent(),
                        ),
                    ])
                }),
        ),
        Some(_) => events.push(Line::from(span("No events yet.", app.theme.muted()))),
        None => events.push(Line::from(span(
            format!("Loading{}", app.symbols.ellipsis()),
            app.theme.muted(),
        ))),
    }
    frame.render_widget(Paragraph::new(events), right);
}

fn notifications(frame: &mut Frame<'_>, app: &App, area: Rect) {
    for (index, note) in app.notifications.iter().rev().take(3).enumerate() {
        let text = format!(" {} {} ", app.symbols.tone(note.tone), line(&note.text));
        let width = (text::width(&text) as u16 + 2).min(area.width);
        let rect = Rect {
            x: area.x + area.width.saturating_sub(width + 1),
            y: area.y + area.height.saturating_sub(5 + index as u16 * 3),
            width,
            height: 3,
        };
        frame.render_widget(Clear, rect);
        frame.render_widget(
            Paragraph::new(span(text, app.theme.tone(note.tone))).block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(app.theme.tone(note.tone)),
            ),
            rect,
        );
    }
}

fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width.saturating_sub(2));
    let height = height.min(area.height.saturating_sub(2));
    Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 3,
        width,
        height,
    }
}

fn modal(
    frame: &mut Frame<'_>,
    app: &App,
    title: &str,
    area: Rect,
    width: u16,
    lines: Vec<Line<'static>>,
) {
    let height = lines.len() as u16 + 2;
    let rect = centered(area, width, height);
    frame.render_widget(Clear, rect);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(app.theme.border(true))
        .title(span(format!(" {} ", line(title)), app.theme.heading()));
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(block),
        rect,
    );
}

fn item_lines(
    app: &App,
    items: &[PaletteItem],
    selected: usize,
    width: usize,
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let mut group = "";
    for (index, item) in items.iter().enumerate() {
        if item.group != group {
            group = item.group;
            lines.push(Line::from(span(
                group.to_owned(),
                app.theme.muted().add_modifier(Modifier::BOLD),
            )));
        }
        let unavailable = matches!(item.target, Target::Unavailable(_));
        let style = if index == selected {
            app.theme.selected(true)
        } else if unavailable {
            app.theme.muted()
        } else {
            app.theme.text()
        };
        let label = fit(
            &format!("  {}", line(&item.label)),
            width / 2,
            app.symbols.ellipsis(),
        );
        let detail = fit(
            &line(&item.detail),
            width.saturating_sub(width / 2 + 1),
            app.symbols.ellipsis(),
        );
        let detail_style = if index == selected {
            style
        } else if unavailable {
            app.theme.tone(Tone::Warning)
        } else {
            app.theme.muted()
        };
        lines.push(Line::from(vec![
            span(label, style),
            span(detail, detail_style),
        ]));
    }
    if lines.is_empty() {
        lines.push(Line::from(span("  no matches", app.theme.muted())));
    }
    lines
}

fn draw_overlay(frame: &mut Frame<'_>, app: &App, screen: &Screen, overlay: &Overlay, area: Rect) {
    let theme = &app.theme;
    let width = 72.min(area.width.saturating_sub(4));
    match overlay {
        Overlay::Palette {
            query,
            selected,
            tab,
        } => {
            let items = palette_items(app, screen, query, *tab);
            let visible = (area.height as usize).saturating_sub(9).max(4);
            let start = selected.saturating_sub(visible.saturating_sub(1));
            let tabs: Vec<Span<'static>> = ["All", "Objects", "Actions", "Commands"]
                .iter()
                .enumerate()
                .map(|(i, name)| {
                    span(
                        format!(" {name} "),
                        if i == *tab {
                            theme.selected(true)
                        } else {
                            theme.muted()
                        },
                    )
                })
                .collect();
            let mut lines = vec![
                Line::from(tabs),
                Line::from(vec![
                    span("> ", theme.accent()),
                    span(line(query), theme.text()),
                    span("▏", theme.accent()),
                ]),
                Line::from(""),
            ];
            let shown: Vec<PaletteItem> = items.iter().skip(start).take(visible).cloned().collect();
            lines.extend(item_lines(
                app,
                &shown,
                selected - start,
                width as usize - 4,
            ));
            lines.push(Line::from(""));
            lines.push(Line::from(span(
                "↑↓ select  enter run  tab group  esc close",
                theme.muted(),
            )));
            modal(frame, app, "Command Palette", area, width, lines);
        }
        Overlay::Command { input, error, .. } => {
            let mut lines = vec![Line::from(vec![
                span(":", theme.accent()),
                span(line(input), theme.text()),
                span("▏", theme.accent()),
            ])];
            if let Some(error) = error {
                lines.push(Line::from(span(line(error), theme.tone(Tone::Danger))));
            }
            let suggestions = crate::input::command_suggestions(input);
            if !suggestions.is_empty() {
                lines.push(Line::from(span(suggestions.join("  "), theme.muted())));
            }
            lines.push(Line::from(span(
                "enter run  tab complete  ↑↓ history  esc cancel",
                theme.muted(),
            )));
            let rect = Rect {
                x: area.x,
                y: area.y + area.height.saturating_sub(lines.len() as u16 + 3),
                width: area.width,
                height: lines.len() as u16 + 2,
            };
            frame.render_widget(Clear, rect);
            frame.render_widget(
                Paragraph::new(lines).block(
                    Block::default()
                        .borders(Borders::TOP)
                        .border_style(theme.border(true))
                        .title(" Command "),
                ),
                rect,
            );
        }
        Overlay::Actions {
            title,
            items,
            query,
            selected,
        } => {
            let filtered = crate::input::filter_items(items, query);
            let mut lines = Vec::new();
            if !query.is_empty() {
                lines.push(Line::from(vec![
                    span("> ", theme.accent()),
                    span(line(query), theme.text()),
                ]));
            }
            lines.extend(item_lines(app, &filtered, *selected, width as usize - 4));
            if !app.can_act() {
                lines.push(Line::from(span(
                    "Offline: actions are disabled until the backend reconnects.",
                    theme.tone(Tone::Warning),
                )));
            }
            lines.push(Line::from(""));
            lines.push(Line::from(span(
                "↑↓ select  enter run  type to filter  esc close",
                theme.muted(),
            )));
            modal(
                frame,
                app,
                &format!("Actions · {title}"),
                area,
                width,
                lines,
            );
        }
        Overlay::Navigation { query, selected } => {
            let routes = crate::input::nav_matches(query);
            let mut lines = vec![Line::from(vec![
                span("> ", theme.accent()),
                span(line(query), theme.text()),
            ])];
            for (index, route) in routes.iter().enumerate() {
                let style = if index == *selected {
                    theme.selected(true)
                } else {
                    theme.text()
                };
                lines.push(Line::from(span(format!("  {}", route.title()), style)));
            }
            modal(frame, app, "Go to", area, 34, lines);
        }
        Overlay::Help => modal(
            frame,
            app,
            &format!("{} shortcuts", app.route.title()),
            area,
            width,
            help_lines(app, screen),
        ),
        Overlay::Confirm {
            title,
            lines: body,
            preflight,
            ..
        } => {
            let mut lines: Vec<Line<'static>> = body
                .iter()
                .map(|l| Line::from(span(line(l), theme.text())))
                .collect();
            if let Some(key) = preflight {
                lines.push(Line::from(""));
                match app.loaded(key) {
                    Some(l) if l.value.is_some() => {
                        let p = l.value.as_ref().expect("checked");
                        let blockers = p["blockers"].as_array().cloned().unwrap_or_default();
                        if blockers.is_empty() {
                            lines.push(Line::from(span(
                                format!(
                                    "{} Backend preflight: ready",
                                    app.symbols.tone(Tone::Success)
                                ),
                                theme.tone(Tone::Success),
                            )));
                        }
                        for b in blockers {
                            lines.push(Line::from(span(
                                format!(
                                    "{} {}",
                                    app.symbols.tone(Tone::Warning),
                                    line(b["message"].as_str().unwrap_or(""))
                                ),
                                theme.tone(Tone::Warning),
                            )));
                        }
                    }
                    Some(l) if l.error.is_some() => lines.push(Line::from(span(
                        format!(
                            "Preflight failed: {}",
                            line(l.error.as_deref().unwrap_or(""))
                        ),
                        theme.tone(Tone::Warning),
                    ))),
                    _ => lines.push(Line::from(span(
                        format!("Checking with the backend{}", app.symbols.ellipsis()),
                        theme.muted(),
                    ))),
                }
            }
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                span("Enter", theme.accent()),
                span(" confirm     ", theme.muted()),
                span("Esc", theme.accent()),
                span(" cancel", theme.muted()),
            ]));
            modal(frame, app, title, area, width, lines);
        }
        Overlay::Prompt {
            title,
            field,
            input,
            ..
        } => {
            let lines = vec![
                Line::from(span(field.clone(), theme.muted())),
                Line::from(vec![
                    span("> ", theme.accent()),
                    span(line(input), theme.text()),
                    span("▏", theme.accent()),
                ]),
                Line::from(""),
                Line::from(span("enter continue  esc cancel", theme.muted())),
            ];
            modal(frame, app, title, area, width, lines);
        }
        Overlay::Review(form) => {
            let decisions = ["Approve", "Reject", "Comment"];
            let mut lines = vec![Line::from(span(
                "Decision",
                if form.field == 0 {
                    theme.heading()
                } else {
                    theme.muted()
                },
            ))];
            for (index, name) in decisions.iter().enumerate() {
                let mark = if index == form.decision {
                    "(•)"
                } else {
                    "( )"
                };
                let style = if form.field == 0 && index == form.decision {
                    theme.selected(true)
                } else {
                    theme.text()
                };
                lines.push(Line::from(span(format!("  {mark} {name}"), style)));
            }
            lines.push(Line::from(""));
            lines.push(Line::from(span(
                "Comment",
                if form.field == 1 {
                    theme.heading()
                } else {
                    theme.muted()
                },
            )));
            lines.push(Line::from(vec![
                span("> ", theme.accent()),
                span(line(&form.comment), theme.text()),
                span(if form.field == 1 { "▏" } else { "" }, theme.accent()),
            ]));
            if let Some(error) = &form.error {
                lines.push(Line::from(span(
                    format!("{} {}", app.symbols.tone(Tone::Warning), line(error)),
                    theme.tone(Tone::Warning),
                )));
            }
            // The review contract records the decision against the candidate; the evidence it
            // covers is shown for context, never as selectable links the backend would ignore.
            if let Some(pack) = app.value(&format!("pack:{}", form.pack)) {
                lines.push(Line::from(""));
                lines.push(Line::from(span(
                    "Evidence on this candidate",
                    theme.muted(),
                )));
                let current: Vec<&Value> = pack["evidence"]["items"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|e| e["stale"] != true)
                    .collect();
                if current.is_empty() {
                    lines.push(Line::from(span("  none", theme.muted())));
                }
                for e in current.iter().take(6) {
                    lines.push(Line::from(span(
                        format!(
                            "  {} {}  {}",
                            app.symbols.tone(Tone::Success),
                            text::short_id(
                                e["evidence"]["id"].as_str().unwrap_or(""),
                                16,
                                app.symbols.ellipsis()
                            ),
                            text::label(e["evidence"]["kind"].as_str().unwrap_or(""))
                        ),
                        theme.text(),
                    )));
                }
                // What OpenAEVC's policy still wants, in its words; Calve has no reviewer list.
                let wanted: Vec<&str> = pack["explain"]["missing"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|m| m["condition"].as_str())
                    .collect();
                lines.push(Line::from(span(
                    if pack["requires_review"] != true {
                        "No review is required by this pack's policy".to_owned()
                    } else if wanted.is_empty() {
                        "The pack's review policy is satisfied for this candidate".to_owned()
                    } else {
                        format!("Policy still needs: {}", wanted.join("; "))
                    },
                    theme.muted(),
                )));
            }
            lines.push(Line::from(""));
            lines.push(Line::from(span(
                format!(
                    "Binds to generation {} of {}",
                    form.generation,
                    text::short_id(&form.pack, 20, app.symbols.ellipsis())
                ),
                theme.muted(),
            )));
            lines.push(Line::from(span(
                "tab field  ↑↓/space choose  ctrl+enter submit  esc cancel",
                theme.muted(),
            )));
            modal(frame, app, "Review", area, width, lines);
        }
        Overlay::Explain { title, lines: body } => {
            let lines: Vec<Line<'static>> = body
                .iter()
                .map(|(tone, text)| {
                    if text.is_empty() {
                        Line::from("")
                    } else if *tone == Tone::Neutral {
                        Line::from(span(line(text), theme.text()))
                    } else {
                        Line::from(vec![
                            span(format!("  {} ", app.symbols.tone(*tone)), theme.tone(*tone)),
                            span(line(text), theme.text()),
                        ])
                    }
                })
                .collect();
            modal(frame, app, title, area, width, lines);
        }
        Overlay::Result { title, value } => {
            let mut lines = structured_lines(app, value, (area.height as usize).saturating_sub(8));
            lines.push(Line::from(""));
            lines.push(Line::from(span("esc close  y copy", theme.muted())));
            modal(frame, app, title, area, width.max(60), lines);
        }
    }
}

/// Generic structured renderer: human fields first, never a raw dump by default (§81).
pub fn structured_lines(app: &App, value: &Value, max: usize) -> Vec<Line<'static>> {
    let theme = &app.theme;
    let mut lines = Vec::new();
    match value {
        Value::Object(map) => {
            for (key, entry) in map.iter() {
                let rendered = match entry {
                    Value::String(s)
                        if key.contains("state") || key == "status" || key == "decision" =>
                    {
                        let tone = state_tone(s);
                        Line::from(vec![
                            span(format!("{:<18}", text::label(key)), theme.muted()),
                            span(
                                format!("{} {}", app.symbols.tone(tone), s),
                                theme.tone(tone),
                            ),
                        ])
                    }
                    _ => Line::from(vec![
                        span(format!("{:<18}", text::label(key)), theme.muted()),
                        span(
                            truncate(&text::scalar(entry), 60, app.symbols.ellipsis()),
                            theme.text(),
                        ),
                    ]),
                };
                lines.push(rendered);
            }
        }
        Value::Array(items) => {
            for entry in items.iter().take(max) {
                let summary = match entry {
                    Value::Object(map) => map
                        .iter()
                        .take(3)
                        .map(|(k, v)| format!("{}: {}", text::label(k), text::scalar(v)))
                        .collect::<Vec<_>>()
                        .join("  "),
                    other => text::scalar(other),
                };
                lines.push(Line::from(span(
                    truncate(&summary, 70, app.symbols.ellipsis()),
                    theme.text(),
                )));
            }
            if items.is_empty() {
                lines.push(Line::from(span("No items.", theme.muted())));
            }
        }
        other => lines.push(Line::from(span(text::scalar(other), theme.text()))),
    }
    lines.truncate(max.max(3));
    lines
}

/// Keys valid here plus global keys (§51): `r` says what it does on this screen, and direct
/// action keys appear only when no other binding claims them.
fn help_lines(app: &App, screen: &Screen) -> Vec<Line<'static>> {
    let theme = &app.theme;
    let pack = matches!(app.route, Route::ChangePack(_));
    let review = screen
        .actions
        .iter()
        .any(|a| matches!(a.target, Target::Review { .. }));
    let r = match app.tab_name() {
        Some("Verify") => "rerun verification",
        _ if pack && review => "review",
        _ => "refresh (also F5)",
    };
    let mut groups: Vec<(&str, Vec<(String, String)>)> = vec![(
        "NAVIGATION",
        [
            ("j / ↓", "next"),
            ("k / ↑", "previous"),
            ("gg / G", "first / last"),
            ("h l", "outward / inward"),
            ("enter", "open"),
            ("esc", "back / close"),
            ("tab", "next pane or tab"),
            ("g", "go to"),
            ("alt+← →", "history"),
        ]
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect(),
    )];
    let mut contextual: Vec<(String, String)> = screen
        .hints
        .iter()
        .filter(|(k, _)| !["^P", ":", "?"].contains(k))
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    contextual.push(("a".into(), "contextual actions".into()));
    if screen.explain.is_some() {
        contextual.push(("x".into(), "explain state".into()));
    }
    if pack {
        contextual.push(("e".into(), "evidence".into()));
    }
    // Direct action keys that nothing else on this screen uses.
    let taken = "qjkhlgGzyxafwnNsre/:?";
    for action in screen.actions.iter().filter(|a| a.group == "Actions") {
        if let Some(key) = action.detail.strip_prefix("key ")
            && !key.chars().all(|c| taken.contains(c))
            && !contextual.iter().any(|(k, _)| k == key)
        {
            contextual.push((key.to_owned(), action.label.to_lowercase()));
        }
    }
    groups.push(("THIS SCREEN", contextual));
    groups.push((
        "GLOBAL",
        [
            ("ctrl+p", "commands and objects"),
            ("/", "filter (field:value, updated:<1h)"),
            (":", "command mode"),
            ("z", "fullscreen"),
            ("r", r),
            ("y", "copy reference"),
            ("ctrl+l", "activity"),
            ("ctrl+b", "hide side pane"),
            ("q", "close / quit"),
            ("?", "this help"),
        ]
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect(),
    ));
    let mut lines = Vec::new();
    for (title, keys) in groups {
        lines.push(Line::from(span(title, theme.heading())));
        for (key, meaning) in keys {
            lines.push(Line::from(vec![
                span(format!("  {key:<12}"), theme.accent()),
                span(meaning, theme.text()),
            ]));
        }
        lines.push(Line::from(""));
    }
    if !app.custom_keys.is_empty() {
        lines.push(Line::from(span("CUSTOM KEYS", theme.heading())));
        for (action, key) in &app.custom_keys {
            lines.push(Line::from(vec![
                span(format!("  {key:<12}"), theme.accent()),
                span(action.clone(), theme.text()),
            ]));
        }
        lines.push(Line::from(""));
    }
    lines.push(Line::from(span("esc close", theme.muted())));
    lines
}

pub fn nav_count() -> usize {
    nav_routes().len()
}
