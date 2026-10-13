//! Theme tokens and the status vocabulary (console-ux §12–14). Widgets never pick raw colors;
//! every state is also spelled out in text so color is never the only signal.

use ratatui::style::{Color, Modifier, Style};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThemeName {
    Dark,
    Light,
    HighContrast,
    /// No color at all (NO_COLOR, `--no-color`, or `ui.color = never`).
    Mono,
}

impl ThemeName {
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "dark" => Self::Dark,
            "light" => Self::Light,
            "high-contrast" => Self::HighContrast,
            "mono" | "none" => Self::Mono,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Theme {
    pub name: ThemeName,
    pub fg: Color,
    pub muted: Color,
    pub accent: Color,
    pub border: Color,
    pub border_focus: Color,
    pub selection_bg: Color,
    pub selection_fg: Color,
    pub success: Color,
    pub running: Color,
    pub review: Color,
    pub warning: Color,
    pub danger: Color,
    pub diff_add: Color,
    pub diff_delete: Color,
    pub diff_hunk: Color,
}

impl Theme {
    pub fn new(name: ThemeName) -> Self {
        match name {
            ThemeName::Dark => Self {
                name,
                fg: Color::Rgb(0xd6, 0xde, 0xeb),
                muted: Color::Rgb(0x7a, 0x88, 0x9e),
                accent: Color::Rgb(0x4f, 0xb3, 0xff),
                border: Color::Rgb(0x2c, 0x3a, 0x4f),
                border_focus: Color::Rgb(0x4f, 0xb3, 0xff),
                selection_bg: Color::Rgb(0x1f, 0x6f, 0xd1),
                selection_fg: Color::Rgb(0xff, 0xff, 0xff),
                success: Color::Rgb(0x4c, 0xd1, 0x7a),
                running: Color::Rgb(0x4f, 0xb3, 0xff),
                review: Color::Rgb(0xf2, 0xc1, 0x4e),
                warning: Color::Rgb(0xf2, 0xa1, 0x3c),
                danger: Color::Rgb(0xf0, 0x5d, 0x5e),
                diff_add: Color::Rgb(0x4c, 0xd1, 0x7a),
                diff_delete: Color::Rgb(0xf0, 0x5d, 0x5e),
                diff_hunk: Color::Rgb(0x9d, 0x7c, 0xf2),
            },
            ThemeName::Light => Self {
                name,
                fg: Color::Rgb(0x1d, 0x26, 0x33),
                muted: Color::Rgb(0x5d, 0x6b, 0x80),
                accent: Color::Rgb(0x0b, 0x61, 0xc4),
                border: Color::Rgb(0xc3, 0xcc, 0xd9),
                border_focus: Color::Rgb(0x0b, 0x61, 0xc4),
                selection_bg: Color::Rgb(0x0b, 0x61, 0xc4),
                selection_fg: Color::Rgb(0xff, 0xff, 0xff),
                success: Color::Rgb(0x1a, 0x7f, 0x37),
                running: Color::Rgb(0x0b, 0x61, 0xc4),
                review: Color::Rgb(0x9a, 0x67, 0x00),
                warning: Color::Rgb(0xa8, 0x4a, 0x00),
                danger: Color::Rgb(0xc2, 0x1f, 0x2b),
                diff_add: Color::Rgb(0x1a, 0x7f, 0x37),
                diff_delete: Color::Rgb(0xc2, 0x1f, 0x2b),
                diff_hunk: Color::Rgb(0x6a, 0x3d, 0xc4),
            },
            ThemeName::HighContrast => Self {
                name,
                fg: Color::White,
                muted: Color::Gray,
                accent: Color::Cyan,
                border: Color::White,
                border_focus: Color::Yellow,
                selection_bg: Color::Yellow,
                selection_fg: Color::Black,
                success: Color::LightGreen,
                running: Color::LightCyan,
                review: Color::LightYellow,
                warning: Color::Yellow,
                danger: Color::LightRed,
                diff_add: Color::LightGreen,
                diff_delete: Color::LightRed,
                diff_hunk: Color::LightMagenta,
            },
            ThemeName::Mono => Self {
                name,
                fg: Color::Reset,
                muted: Color::Reset,
                accent: Color::Reset,
                border: Color::Reset,
                border_focus: Color::Reset,
                selection_bg: Color::Reset,
                selection_fg: Color::Reset,
                success: Color::Reset,
                running: Color::Reset,
                review: Color::Reset,
                warning: Color::Reset,
                danger: Color::Reset,
                diff_add: Color::Reset,
                diff_delete: Color::Reset,
                diff_hunk: Color::Reset,
            },
        }
    }

    pub fn text(&self) -> Style {
        Style::default().fg(self.fg)
    }

    pub fn muted(&self) -> Style {
        Style::default().fg(self.muted)
    }

    pub fn accent(&self) -> Style {
        Style::default().fg(self.accent)
    }

    pub fn heading(&self) -> Style {
        Style::default().fg(self.fg).add_modifier(Modifier::BOLD)
    }

    /// Selection stays visible without color through reverse video in mono mode.
    pub fn selected(&self, focused: bool) -> Style {
        if self.name == ThemeName::Mono {
            let style = Style::default().add_modifier(Modifier::REVERSED);
            return if focused {
                style.add_modifier(Modifier::BOLD)
            } else {
                style
            };
        }
        if focused {
            Style::default().bg(self.selection_bg).fg(self.selection_fg)
        } else {
            Style::default().bg(self.border).fg(self.fg)
        }
    }

    pub fn border(&self, focused: bool) -> Style {
        let style = Style::default().fg(if focused {
            self.border_focus
        } else {
            self.border
        });
        if focused && self.name == ThemeName::Mono {
            style.add_modifier(Modifier::BOLD)
        } else {
            style
        }
    }

    pub fn tone(&self, tone: Tone) -> Style {
        Style::default().fg(match tone {
            Tone::Success => self.success,
            Tone::Running => self.running,
            Tone::Review => self.review,
            Tone::Warning => self.warning,
            Tone::Danger => self.danger,
            Tone::Neutral => self.muted,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Success,
    Running,
    Review,
    Warning,
    Danger,
    Neutral,
}

/// Unicode symbols with ASCII fallbacks (console-ux §14).
#[derive(Debug, Clone, Copy)]
pub struct Symbols {
    pub unicode: bool,
}

impl Symbols {
    pub fn tone(&self, tone: Tone) -> &'static str {
        match (tone, self.unicode) {
            (Tone::Success, true) => "✓",
            (Tone::Running, true) => "●",
            (Tone::Review, true) => "◆",
            (Tone::Warning, true) => "!",
            (Tone::Danger, true) => "×",
            (Tone::Neutral, true) => "○",
            (Tone::Success, false) => "[ok]",
            (Tone::Running, false) => "[*]",
            (Tone::Review, false) => "[?]",
            (Tone::Warning, false) => "[!]",
            (Tone::Danger, false) => "[x]",
            (Tone::Neutral, false) => "[ ]",
        }
    }

    pub fn arrow(&self) -> &'static str {
        if self.unicode { "→" } else { "->" }
    }

    pub fn back_arrow(&self) -> &'static str {
        if self.unicode { "←" } else { "<-" }
    }

    pub fn ellipsis(&self) -> &'static str {
        if self.unicode { "…" } else { "..." }
    }

    pub fn selected_marker(&self) -> &'static str {
        if self.unicode { "›" } else { ">" }
    }
}

/// Maps any authoritative state string onto the shared vocabulary. Unknown states are neutral
/// and keep their own text, so nothing is hidden.
pub fn state_tone(state: &str) -> Tone {
    match state.to_ascii_uppercase().as_str() {
        "PROMOTED" | "QUALIFIED" | "SUCCEEDED" | "PASS" | "PASSED" | "COMPLETE" | "COMPLETED"
        | "VERIFIED" | "VALID" | "HEALTHY" | "ALLOW" | "APPROVE" | "APPROVED" | "ACTIVE" | "OK"
        | "INSTALLED" | "SUCCESS" => Tone::Success,
        "RUNNING" | "IN_PROGRESS" | "STARTING" | "ADMITTED" | "EXECUTING" => Tone::Running,
        "SEALED" | "REVIEW" | "REVIEWING" | "WAITING" | "COMMENT" => Tone::Review,
        "BLOCKED" | "QUARANTINED" | "WARN" | "WARNING" | "INCONCLUSIVE" | "STALE" | "CANCELLED"
        | "SUPERSEDED" | "DEGRADED" | "UPDATE" => Tone::Warning,
        "FAILED" | "FAIL" | "LOST" | "REJECT" | "REJECTED" | "DENY" | "INVALID" | "ERROR"
        | "DANGER" | "FAILURE" | "OFFLINE" => Tone::Danger,
        _ => Tone::Neutral,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn states_map_to_vocabulary_and_ascii() {
        assert_eq!(state_tone("PROMOTED"), Tone::Success);
        assert_eq!(state_tone("sealed"), Tone::Review);
        assert_eq!(state_tone("FAILED"), Tone::Danger);
        assert_eq!(state_tone("whatever"), Tone::Neutral);
        let ascii = Symbols { unicode: false };
        assert_eq!(ascii.tone(Tone::Danger), "[x]");
        assert!(ascii.tone(Tone::Success).is_ascii());
    }
}
