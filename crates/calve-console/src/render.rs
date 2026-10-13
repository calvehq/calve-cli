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
                _ => "?",
            };
            cell.set_symbol(replacement);
        }
    }
}

fn span(text: impl Into<String>, style: Style) -> Span<'static> {
    Span::styled(text.into(), style)
}

fn top_bar(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let theme = &app.theme;
    let (tone, health) = match app.connection {
        Connection::Daemon => (Tone::Success, "healthy"),
        Connection::Local => (Tone::Success, "local"),
        Connection::Offline => (Tone::Danger, "offline"),
    };
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
    spans.push(span(
        format!("  {} {health}", app.symbols.tone(tone)),
        theme.tone(tone),
    ));
    let right = format!("v{}  ^P Commands  ? Help ", app.version);
    let used: usize = spans.iter().map(|s| text::width(&s.content)).sum();
    let pad = (area.width as usize).saturating_sub(used + text::width(&right));
    if pad > 0 {
        spans.push(span(" ".repeat(pad), theme.text()));
        spans.push(span(right, theme.muted()));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn footer_bar(frame: &mut Frame<'_>, app: &App, screen: &Screen, area: Rect) {
    let theme = &app.theme;
    let mut spans = Vec::new();
    if app.filter_editing || screen_filter(app, screen).is_some() {
        let filter = screen_filter(app, screen).unwrap_or_default();
        spans.push(span(" /filter: ", theme.accent()));
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
    let stale = current_keys(app).iter().any(|key| {
        app.loaded(key)
            .is_some_and(|l| l.error.is_some() && l.value.is_some())
    }) || app.connection == Connection::Offline;
    if stale {
        spans.push(span(
            " STALE · actions disabled  ",
            theme.tone(Tone::Warning),
        ));
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
    for (key, label) in screen.hints.iter().take(8) {
        spans.push(span(format!(" {key} "), theme.accent()));
        spans.push(span(format!("{label} "), theme.muted()));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
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
            Route::ChangePacks => app.value("packs").and_then(Value::as_array).map(Vec::len),
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
        for (index, name) in tabs.iter().enumerate() {
            let width = name.len() as u16 + 2;
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
        Body::Diff => draw_diff(frame, app, inner, focused),
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
            (
                format!("Nothing matches “{}”.", line(&filter)),
                "esc clear filter".into(),
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
    let mut row_lines: Vec<(Option<String>, Line<'static>)> = Vec::new();
    for section in &table.sections {
        let rows: Vec<_> = section
            .rows
            .iter()
            .filter(|row| screens::matches_filter(row, &filter))
            .collect();
        if rows.is_empty() && section.title.is_none() {
            continue;
        }
        let fitted = fit_columns(&section.columns, area.width);
        if let Some(title) = &section.title {
            if !row_lines.is_empty() {
                row_lines.push((None, Line::from("")));
            }
            let rule = "─".repeat((area.width as usize).saturating_sub(text::width(title) + 1));
            let rule = if app.symbols.unicode {
                rule
            } else {
                "-".repeat(rule.chars().count())
            };
            row_lines.push((
                None,
                Line::from(vec![
                    span(format!("{title} "), theme.heading()),
                    span(rule, Style::default().fg(theme.border)),
                ]),
            ));
        }
        if section.columns.iter().any(|c| !c.title.is_empty()) {
            let header: Vec<Span<'static>> = fitted
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
                .collect();
            row_lines.push((None, Line::from(header)));
        }
        if rows.is_empty() {
            row_lines.push((None, Line::from(span("  none", theme.muted()))));
        }
        for row in rows {
            let is_selected = selected.as_deref() == Some(row.id.as_str());
            let marked = app
                .collections
                .get(&table.key)
                .is_some_and(|c| c.marked.contains(&row.id));
            let spans: Vec<Span<'static>> = fitted
                .iter()
                .map(|(i, w)| {
                    let cell = row
                        .cells
                        .get(*i)
                        .cloned()
                        .unwrap_or_else(|| screens::cell("", theme.text()));
                    let style = if is_selected {
                        theme.selected(focused)
                    } else {
                        cell.style
                    };
                    span(
                        format!("{} ", fit(&cell.text, *w as usize, ellipsis)),
                        style,
                    )
                })
                .collect();
            let mut spans = spans;
            if marked {
                spans.insert(
                    0,
                    span(app.symbols.tone(Tone::Success), theme.tone(Tone::Success)),
                );
            }
            row_lines.push((Some(row.id.clone()), Line::from(spans)));
        }
    }
    let height = area.height as usize - lines.len().min(area.height as usize);
    let selected_line = row_lines
        .iter()
        .position(|(id, _)| id.is_some() && id.as_deref() == selected.as_deref())
        .unwrap_or(0);
    let scroll = selected_line.saturating_sub(height.saturating_sub(2));
    let total = row_lines.len();
    let top = area.y + lines.len() as u16;
    for (offset, (id, _)) in row_lines.iter().skip(scroll).take(height).enumerate() {
        if let Some(id) = id {
            let rect = Rect {
                x: area.x,
                y: top + offset as u16,
                width: area.width,
                height: 1,
            };
            app.hits.borrow_mut().push((
                rect,
                Hit::Row {
                    key: table.key.clone(),
                    id: id.clone(),
                },
            ));
        }
    }
    lines.extend(
        row_lines
            .into_iter()
            .skip(scroll)
            .take(height)
            .map(|(_, line)| line),
    );
    frame.render_widget(Paragraph::new(lines), area);
    if total > height && area.height > 0 {
        let position = format!(
            "{}/{}",
            selection(app, table).map_or(0, |i| i + 1),
            visible.len()
        );
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
    let views: Vec<graph::NodeView<'_>> = graph_body
        .nodes
        .iter()
        .map(|n| graph::NodeView {
            label: &n.label,
            tone: n.tone,
        })
        .collect();
    let mut lines = Vec::new();
    if graph_body.nodes.len() > 200 {
        lines.push(Line::from(span(
            format!(
                "Graph is large · {} nodes   l list view",
                graph_body.nodes.len()
            ),
            app.theme.tone(Tone::Warning),
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
    lines.extend(graph::render(
        &views,
        &graph_body.edges,
        &placement,
        selected,
        &app.theme,
        &app.symbols,
        area.width as usize,
    ));
    if graph_body.legend {
        lines.push(Line::from(""));
        let s = &app.symbols;
        lines.push(Line::from(span(
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
    frame.render_widget(Paragraph::new(lines), area);
}

fn draw_diff(frame: &mut Frame<'_>, app: &App, area: Rect, focused: bool) {
    let Route::ChangePack(id) = &app.route else {
        return;
    };
    let Some(pack) = app.value(&format!("pack:{id}")) else {
        return;
    };
    let theme = &app.theme;
    let files = pack["files"].as_array().cloned().unwrap_or_default();
    if files.is_empty() {
        frame.render_widget(
            Paragraph::new(span("No files in this ChangePack.", theme.muted())),
            area,
        );
        return;
    }
    let files_key = format!("diff-files:{id}");
    let index = app
        .collections
        .get(&files_key)
        .map_or(0, |c| c.selected_index)
        .min(files.len() - 1);
    let narrow = area.width < 70;
    let [list_area, diff_area] = if app.fullscreen || narrow {
        [Rect { width: 0, ..area }, area]
    } else {
        Layout::horizontal([
            Constraint::Length(30.min(area.width / 3)),
            Constraint::Min(20),
        ])
        .areas(area)
    };
    if list_area.width > 0 {
        let mut lines = vec![Line::from(span(
            format!("{} files changed", files.len()),
            theme.muted(),
        ))];
        for (i, file) in files.iter().enumerate() {
            let counts = format!("+{} -{}", file["added"], file["removed"]);
            let name = text::middle(
                file["path"].as_str().unwrap_or(""),
                (list_area.width as usize).saturating_sub(counts.len() + 2),
                app.symbols.ellipsis(),
            );
            let style = if i == index {
                theme.selected(focused)
            } else {
                theme.text()
            };
            lines.push(Line::from(vec![
                span(
                    fit(
                        &name,
                        (list_area.width as usize).saturating_sub(counts.len() + 1),
                        app.symbols.ellipsis(),
                    ),
                    style,
                ),
                span(
                    format!("+{}", file["added"]),
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
    let mut lines = vec![Line::from(span(line(path), theme.heading()))];
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
            let all = diff["lines"].as_array().cloned().unwrap_or_default();
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
                let text = line(entry["text"].as_str().unwrap_or(""));
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
                        theme.muted(),
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
    if !available.is_empty() && app.can_act() {
        lines.push(Line::from(""));
        lines.push(Line::from(span("Actions", app.theme.heading())));
        for action in available.iter().take(6) {
            lines.push(Line::from(vec![span(
                format!("  {}", line(&action.label)),
                app.theme.text(),
            )]));
        }
        lines.push(Line::from(span("  a all actions", app.theme.muted())));
    }
    let scroll = app.collections.get("inspector").map_or(0, |c| c.scroll) as u16;
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0)),
        inner,
    );
}

fn activity_drawer(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let block = pane_block(app, "Activity".into(), false);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let lines: Vec<Line<'static>> = app
        .activity
        .iter()
        .rev()
        .take(inner.height as usize)
        .map(|(_, tone, text)| {
            Line::from(vec![
                span(
                    format!("{} ", app.symbols.tone(*tone)),
                    app.theme.tone(*tone),
                ),
                span(line(text), app.theme.text()),
            ])
        })
        .collect();
    let lines = if lines.is_empty() {
        vec![Line::from(span(
            "No console actions yet.",
            app.theme.muted(),
        ))]
    } else {
        lines
    };
    frame.render_widget(Paragraph::new(lines), inner);
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
        Overlay::Palette { query, selected } => {
            let items = palette_items(app, screen, query);
            let visible = (area.height as usize).saturating_sub(8).max(4);
            let start = selected.saturating_sub(visible.saturating_sub(1));
            let mut lines = vec![
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
                "↑↓ select  enter run  esc close",
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
            title, lines: body, ..
        } => {
            let mut lines: Vec<Line<'static>> = body
                .iter()
                .map(|l| Line::from(span(line(l), theme.text())))
                .collect();
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
                "tab field  ↑↓/space choose  ctrl+s or enter (on comment) submit  esc cancel",
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

fn help_lines(app: &App, screen: &Screen) -> Vec<Line<'static>> {
    let theme = &app.theme;
    let mut groups: Vec<(&str, Vec<(&str, &str)>)> = vec![(
        "NAVIGATION",
        vec![
            ("j / ↓", "next"),
            ("k / ↑", "previous"),
            ("h l", "outward / inward"),
            ("enter", "open"),
            ("esc", "back / close"),
            ("tab", "next pane or tab"),
            ("g", "go to"),
            ("alt+← →", "history"),
        ],
    )];
    let mut contextual: Vec<(&str, &str)> = screen
        .hints
        .iter()
        .map(|(k, v)| (*k, *v))
        .filter(|(k, _)| !["^P", ":", "?"].contains(k))
        .collect();
    contextual.push(("a", "contextual actions"));
    if screen.explain.is_some() {
        contextual.push(("x", "explain state"));
    }
    groups.push(("THIS SCREEN", contextual));
    groups.push((
        "GLOBAL",
        vec![
            ("ctrl+p", "commands and objects"),
            ("/", "filter (field:value)"),
            (":", "command mode"),
            ("z", "fullscreen"),
            ("r", "refresh"),
            ("y", "copy ID"),
            ("ctrl+l", "activity"),
            ("q", "quit"),
            ("?", "this help"),
        ],
    ));
    let mut lines = Vec::new();
    for (title, keys) in groups {
        lines.push(Line::from(span(title, theme.heading())));
        for (key, meaning) in keys {
            lines.push(Line::from(vec![
                span(format!("  {key:<12}"), theme.accent()),
                span(meaning.to_owned(), theme.text()),
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
