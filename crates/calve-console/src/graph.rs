//! Deterministic layered graph layout and text rendering (console-ux §29, §79).

use ratatui::style::Style;
use ratatui::text::{Line, Span};

use crate::text;
use crate::theme::{Symbols, Theme, Tone};

/// (layer, row) per node. Layers follow longest dependency paths; nodes on a cycle are placed
/// after everything acyclic and reported so the renderer can say so.
pub struct Placement {
    pub positions: Vec<(usize, usize)>,
    pub cyclic: Vec<usize>,
}

pub fn layout(count: usize, edges: &[(usize, usize)]) -> Placement {
    let mut indegree = vec![0usize; count];
    let mut outgoing = vec![Vec::new(); count];
    for &(from, to) in edges {
        if from < count && to < count && from != to {
            indegree[to] += 1;
            outgoing[from].push(to);
        }
    }
    let mut layer = vec![0usize; count];
    let mut queue: std::collections::VecDeque<usize> =
        (0..count).filter(|&n| indegree[n] == 0).collect();
    let mut seen = vec![false; count];
    while let Some(node) = queue.pop_front() {
        seen[node] = true;
        for &next in &outgoing[node] {
            layer[next] = layer[next].max(layer[node] + 1);
            indegree[next] -= 1;
            if indegree[next] == 0 {
                queue.push_back(next);
            }
        }
    }
    let cyclic: Vec<usize> = (0..count).filter(|&n| !seen[n]).collect();
    let max_layer = layer.iter().copied().max().unwrap_or(0);
    for &node in &cyclic {
        layer[node] = max_layer + 1;
    }
    let layers = layer.iter().copied().max().map_or(0, |m| m + 1);
    let mut by_layer: Vec<Vec<usize>> = vec![Vec::new(); layers];
    for node in 0..count {
        by_layer[layer[node]].push(node);
    }
    // One barycenter pass keeps related nodes near each other; ties keep input order.
    let mut row = vec![0f64; count];
    for (index, &node) in by_layer.first().into_iter().flatten().enumerate() {
        row[node] = index as f64;
    }
    for layer_nodes in by_layer.iter_mut().skip(1) {
        let mut keyed: Vec<(f64, usize, usize)> = layer_nodes
            .iter()
            .enumerate()
            .map(|(order, &node)| {
                let parents: Vec<f64> = edges
                    .iter()
                    .filter(|(_, to)| *to == node)
                    .map(|(from, _)| row[*from])
                    .collect();
                let center = if parents.is_empty() {
                    order as f64
                } else {
                    parents.iter().sum::<f64>() / parents.len() as f64
                };
                (center, order, node)
            })
            .collect();
        keyed.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)));
        *layer_nodes = keyed.iter().map(|(_, _, node)| *node).collect();
        for (index, &node) in layer_nodes.iter().enumerate() {
            row[node] = index as f64;
        }
    }
    let mut positions = vec![(0, 0); count];
    for (l, nodes) in by_layer.iter().enumerate() {
        for (r, &node) in nodes.iter().enumerate() {
            positions[node] = (l, r);
        }
    }
    Placement { positions, cyclic }
}

#[derive(Clone, Copy)]
pub enum Direction {
    Left,
    Right,
    Up,
    Down,
}

/// Nearest node in the requested direction (§29.1).
pub fn neighbor(positions: &[(usize, usize)], from: usize, direction: Direction) -> Option<usize> {
    let (layer, row) = *positions.get(from)?;
    let candidates = positions.iter().enumerate().filter(|(index, (l, r))| {
        *index != from
            && match direction {
                Direction::Left => *l < layer,
                Direction::Right => *l > layer,
                Direction::Up => *l == layer && *r < row,
                Direction::Down => *l == layer && *r > row,
            }
    });
    candidates
        .min_by_key(|(_, (l, r))| (l.abs_diff(layer) * 100 + r.abs_diff(row), *l, *r))
        .map(|(index, _)| index)
}

const UP: u8 = 1;
const DOWN: u8 = 2;
const LEFT: u8 = 4;
const RIGHT: u8 = 8;

fn junction(mask: u8, unicode: bool) -> char {
    if !unicode {
        return match mask {
            m if m & (UP | DOWN) != 0 && m & (LEFT | RIGHT) != 0 => '+',
            m if m & (UP | DOWN) != 0 => '|',
            _ => '-',
        };
    }
    match mask {
        m if m == LEFT | RIGHT || m == LEFT || m == RIGHT => '─',
        m if m == UP | DOWN || m == UP || m == DOWN => '│',
        m if m == DOWN | RIGHT => '┌',
        m if m == DOWN | LEFT => '┐',
        m if m == UP | RIGHT => '└',
        m if m == UP | LEFT => '┘',
        m if m == UP | DOWN | RIGHT => '├',
        m if m == UP | DOWN | LEFT => '┤',
        m if m == LEFT | RIGHT | DOWN => '┬',
        m if m == LEFT | RIGHT | UP => '┴',
        _ => '┼',
    }
}

pub struct NodeView<'a> {
    pub label: &'a str,
    pub tone: Tone,
}

/// Renders nodes as `[✓ label]` boxes on a grid and edges as routed connectors. Returns lines
/// clipped horizontally around `scroll_x`.
pub fn render(
    nodes: &[NodeView<'_>],
    edges: &[(usize, usize)],
    placement: &Placement,
    selected: Option<usize>,
    theme: &Theme,
    symbols: &Symbols,
    width: usize,
) -> Vec<Line<'static>> {
    const NODE: usize = 22;
    const GAP: usize = 6;
    let layers = placement
        .positions
        .iter()
        .map(|(l, _)| l + 1)
        .max()
        .unwrap_or(0);
    let rows = placement
        .positions
        .iter()
        .map(|(_, r)| r + 1)
        .max()
        .unwrap_or(0);
    let canvas_w = layers * (NODE + GAP);
    let canvas_h = rows * 2;
    let mut masks = vec![vec![0u8; canvas_w + 1]; canvas_h + 1];
    let mut arrows = vec![vec![false; canvas_w + 1]; canvas_h + 1];
    let at = |node: usize| {
        let (l, r) = placement.positions[node];
        (l * (NODE + GAP), r * 2)
    };
    for &(from, to) in edges {
        if from >= nodes.len() || to >= nodes.len() || from == to {
            continue;
        }
        let (fx, fy) = at(from);
        let (tx, ty) = at(to);
        let start = fx + NODE;
        let end = tx.saturating_sub(1);
        if end <= start {
            continue;
        }
        let mid = start + GAP / 2;
        for cell in &mut masks[fy][start..mid] {
            *cell |= LEFT | RIGHT;
        }
        masks[fy][mid] |= LEFT;
        if fy != ty {
            let (top, bottom) = (fy.min(ty), fy.max(ty));
            masks[top][mid] |= DOWN;
            masks[bottom][mid] |= UP;
            for row in masks.iter_mut().take(bottom).skip(top + 1) {
                row[mid] |= UP | DOWN;
            }
        }
        masks[ty][mid] |= RIGHT;
        for cell in &mut masks[ty][mid + 1..end] {
            *cell |= LEFT | RIGHT;
        }
        arrows[ty][end] = true;
    }
    // Start drawing so the selected node stays visible.
    let scroll = selected
        .map(|node| at(node).0)
        .filter(|x| *x + NODE > width)
        .map_or(0, |x| (x + NODE).saturating_sub(width));
    let mut lines = Vec::new();
    for y in 0..canvas_h.max(1) {
        let mut spans: Vec<Span<'static>> = Vec::new();
        let mut x = 0;
        while x < canvas_w {
            if let Some(node) = (0..nodes.len()).find(|&n| at(n) == (x, y)) {
                let view = &nodes[node];
                let body = text::truncate(&text::line(view.label), NODE - 5, symbols.ellipsis());
                let label = text::fit(
                    &format!("[{} {body}]", symbols.tone(view.tone)),
                    NODE,
                    symbols.ellipsis(),
                );
                let style = if selected == Some(node) {
                    theme.selected(true)
                } else {
                    theme.tone(view.tone)
                };
                spans.push(Span::styled(label, style));
                x += NODE;
                continue;
            }
            let ch = if arrows[y][x] {
                if symbols.unicode { '▶' } else { '>' }
            } else if masks[y][x] != 0 {
                junction(masks[y][x], symbols.unicode)
            } else {
                ' '
            };
            spans.push(Span::styled(
                ch.to_string(),
                Style::default().fg(theme.muted),
            ));
            x += 1;
        }
        lines.push(clip(spans, scroll, width));
    }
    lines
}

/// Keeps the characters in `[scroll, scroll + width)`.
fn clip(spans: Vec<Span<'static>>, scroll: usize, width: usize) -> Line<'static> {
    let mut out = Vec::new();
    let mut column = 0;
    for span in spans {
        let text: String = span.content.chars().collect();
        let w = text::width(&text);
        if column + w <= scroll || column >= scroll + width {
            column += w;
            continue;
        }
        let skip = scroll.saturating_sub(column);
        let keep: String = text
            .chars()
            .skip(skip)
            .take(scroll + width - column.max(scroll))
            .collect();
        out.push(Span::styled(keep, span.style));
        column += w;
    }
    Line::from(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layers_follow_dependencies_and_detect_cycles() {
        let placement = layout(4, &[(0, 1), (1, 2), (0, 2)]);
        assert_eq!(placement.positions[0].0, 0);
        assert_eq!(placement.positions[1].0, 1);
        assert_eq!(placement.positions[2].0, 2);
        assert!(placement.cyclic.is_empty());
        let cyclic = layout(2, &[(0, 1), (1, 0)]);
        assert_eq!(cyclic.cyclic.len(), 2);
        // Same input, same output.
        assert_eq!(
            layout(4, &[(0, 1), (1, 2), (0, 2)]).positions,
            placement.positions
        );
    }

    #[test]
    fn neighbor_moves_spatially() {
        let placement = layout(3, &[(0, 1), (0, 2)]);
        let right = neighbor(&placement.positions, 0, Direction::Right).unwrap();
        assert!(right == 1 || right == 2);
        let down = neighbor(&placement.positions, 1, Direction::Down);
        assert_eq!(down, Some(2));
        assert_eq!(neighbor(&placement.positions, 0, Direction::Left), None);
    }
}
