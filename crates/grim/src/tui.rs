//! The TUI: a thin view over the daemon's verbs (DESIGN §6).
//!
//! Nothing here decrypts, derives, or touches SQL — every action is a `Request` on the socket.
//! `App` is intentionally dumb so it can be rendered into a `TestBackend` and asserted on.

use std::path::Path;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use grim_core::protocol::{call, ItemRow, Request, Response};
use grim_core::{Error, Result};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap};

use crate::clipboard;

const REVEAL_SECS: u64 = 10;
const TOAST_SECS: u64 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Locked,
    Browsing,
    Filtering,
}

#[derive(Debug, Clone, Default)]
pub struct DetailView {
    pub id: String,
    pub title: String,
    pub category: String,
    pub fields: Vec<(String, String, bool)>,
    pub notes: String,
}

pub struct App {
    pub vault: String,
    pub rows: Vec<ItemRow>,
    pub selected: usize,
    pub filter: String,
    pub mode: Mode,
    pub passphrase: String,
    pub detail: Option<DetailView>,
    pub toast: Option<(String, Instant)>,
    pub reveal_until: Option<Instant>,
}

impl App {
    pub fn new() -> Self {
        Self {
            vault: String::new(),
            rows: Vec::new(),
            selected: 0,
            filter: String::new(),
            mode: Mode::Locked,
            passphrase: String::new(),
            detail: None,
            toast: None,
            reveal_until: None,
        }
    }

    /// Filtered rows, in display order.
    pub fn visible(&self) -> Vec<&ItemRow> {
        let needle = self.filter.to_ascii_lowercase();
        self.rows
            .iter()
            .filter(|r| {
                needle.is_empty()
                    || r.title.to_ascii_lowercase().contains(&needle)
                    || r.subtitle.to_ascii_lowercase().contains(&needle)
                    || r.url_host.to_ascii_lowercase().contains(&needle)
            })
            .collect()
    }

    pub fn selected_row(&self) -> Option<ItemRow> {
        self.visible().get(self.selected).map(|r| (*r).clone())
    }

    pub fn move_down(&mut self) {
        let n = self.visible().len();
        if n > 0 && self.selected + 1 < n {
            self.selected += 1;
        }
    }

    pub fn move_up(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    pub fn toast(&mut self, msg: impl Into<String>) {
        self.toast = Some((msg.into(), Instant::now()));
    }

    pub fn revealing(&self) -> bool {
        matches!(self.reveal_until, Some(t) if t > Instant::now())
    }

    fn tick(&mut self) {
        if let Some((_, at)) = &self.toast {
            if at.elapsed() > Duration::from_secs(TOAST_SECS) {
                self.toast = None;
            }
        }
        if matches!(self.reveal_until, Some(t) if t <= Instant::now()) {
            self.reveal_until = None;
        }
    }

    pub fn draw(&self, f: &mut Frame) {
        let area = f.area();
        if self.mode == Mode::Locked {
            self.draw_locked(f, area);
            return;
        }

        let chunks = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(1),
        ])
        .split(area);

        // header
        let filter_note = if self.filter.is_empty() {
            String::new()
        } else {
            format!("   filter: {}", self.filter)
        };
        let header = Line::from(vec![
            Span::styled(" GRIMOIRE ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(format!(
                " {}   {} item(s){}",
                self.vault,
                self.visible().len(),
                filter_note
            )),
        ]);
        f.render_widget(Paragraph::new(header), chunks[0]);

        let body =
            Layout::horizontal([Constraint::Percentage(46), Constraint::Percentage(54)]).split(chunks[1]);

        // item list
        let visible = self.visible();
        let items: Vec<ListItem> = visible
            .iter()
            .enumerate()
            .map(|(i, row)| {
                let style = if i == self.selected {
                    Style::default().add_modifier(Modifier::REVERSED)
                } else {
                    Style::default()
                };
                ListItem::new(Line::from(format!(
                    "{:<9} {:<10} {}",
                    short(&row.id),
                    row.category,
                    row.title
                )))
                .style(style)
            })
            .collect();
        f.render_widget(
            List::new(items).block(Block::default().borders(Borders::ALL).title(" items ")),
            body[0],
        );

        // detail pane
        let lines: Vec<Line> = match &self.detail {
            None => vec![Line::from("select an item")],
            Some(d) => {
                let mut v = vec![
                    Line::from(Span::styled(
                        format!("{}  [{}]", d.title, d.category),
                        Style::default().add_modifier(Modifier::BOLD),
                    )),
                    Line::from(format!("id {}", short(&d.id))),
                    Line::from(""),
                ];
                for (name, value, conceal) in &d.fields {
                    let shown = if *conceal && !self.revealing() {
                        format!("{}…  ({} chars, r to reveal)", "•".repeat(8.min(value.len())), value.len())
                    } else {
                        value.clone()
                    };
                    v.push(Line::from(format!("{:<10} {}", name, shown)));
                }
                if !d.notes.is_empty() {
                    v.push(Line::from(""));
                    v.push(Line::from(Span::styled("notes", Style::default().add_modifier(Modifier::BOLD))));
                    for l in d.notes.lines() {
                        v.push(Line::from(l.to_string()));
                    }
                }
                v
            }
        };
        f.render_widget(
            Paragraph::new(lines)
                .block(Block::default().borders(Borders::ALL).title(" detail "))
                .wrap(Wrap { trim: true }),
            body[1],
        );

        // footer
        let footer = match self.mode {
            Mode::Filtering => {
                format!(" /{}_    Enter accept · Esc clear", self.filter)
            }
            _ => " j/k move · / search · y copy · t totp · r reveal · ^L lock · q quit".to_string(),
        };
        f.render_widget(Paragraph::new(footer), chunks[2]);

        // toast
        if let Some((msg, _)) = &self.toast {
            let w = (msg.chars().count() as u16 + 4).min(area.width);
            let rect = Rect::new(area.width.saturating_sub(w + 1), area.height.saturating_sub(3), w, 1);
            f.render_widget(Clear, rect);
            f.render_widget(Paragraph::new(format!(" {msg} ")), rect);
        }
    }

    fn draw_locked(&self, f: &mut Frame, area: Rect) {
        let w = area.width.saturating_sub(4).min(64).max(20);
        let h = 7.min(area.height);
        let rect = Rect::new(
            area.x + (area.width.saturating_sub(w)) / 2,
            area.y + (area.height.saturating_sub(h)) / 2,
            w,
            h,
        );
        f.render_widget(Clear, rect);
        let masked: String = "•".repeat(self.passphrase.chars().count());
        let toast = self
            .toast
            .as_ref()
            .map(|(m, _)| m.clone())
            .unwrap_or_else(|| "vault is locked".to_string());
        let body = vec![
            Line::from(toast),
            Line::from(""),
            Line::from(format!("passphrase: {masked}_")),
            Line::from(""),
            Line::from("Enter unlock · Esc quit"),
        ];
        f.render_widget(
            Paragraph::new(body)
                .block(Block::default().borders(Borders::ALL).title(" grimd "))
                .wrap(Wrap { trim: true }),
            rect,
        );
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

fn short(id: &str) -> &str {
    &id[..id.len().min(8)]
}

// ------------------------------------------------------------------ transport

fn ask(socket: &Path, req: Request) -> Result<Response> {
    match call(socket, &req)? {
        Response::Error { message } => Err(Error::Daemon(message)),
        other => Ok(other),
    }
}

fn load_items(app: &mut App, socket: &Path) -> Result<()> {
    if let Response::Items { items } = ask(socket, Request::ListItems)? {
        app.rows = items;
        app.selected = app.selected.min(app.rows.len().saturating_sub(1));
    }
    refresh_detail(app, socket)?;
    Ok(())
}

fn refresh_detail(app: &mut App, socket: &Path) -> Result<()> {
    let Some(row) = app.selected_row() else {
        app.detail = None;
        return Ok(());
    };
    if let Response::Item { id, category, overview, detail } = ask(
        socket,
        Request::GetItem { needle: row.id.clone() },
    )? {
        let fields = detail
            .fields
            .into_iter()
            .map(|f| (f.name, f.value, f.conceal))
            .collect::<Vec<_>>();
        app.detail = Some(DetailView {
            id,
            title: overview.title,
            category,
            fields,
            notes: detail.notes,
        });
    }
    Ok(())
}

/// Copy one field by name from the selected item, returning what happened.
fn copy_field(app: &mut App, socket: &Path, field: &str) -> Result<()> {
    let Some(row) = app.selected_row() else {
        return Ok(());
    };
    match ask(socket, Request::RevealField { needle: row.id, field: field.to_string() }) {
        Ok(Response::Value { value }) => match clipboard::copy(&value) {
            Ok(tool) => app.toast(format!("copied {field} via {tool} — clear in {}s", clipboard::CLEAR_HINT_SECS)),
            Err(e) => app.toast(format!("{field} copied? no: {e}")),
        },
        Ok(_) => app.toast("unexpected reply"),
        Err(e) => app.toast(format!("{e}")),
    }
    Ok(())
}

fn copy_totp(app: &mut App, socket: &Path) -> Result<()> {
    let Some(row) = app.selected_row() else {
        return Ok(());
    };
    match ask(socket, Request::TotpNow { needle: row.id }) {
        Ok(Response::Totp { code, remaining }) => {
            let copied = clipboard::copy(&code);
            app.toast(match copied {
                Ok(tool) => format!("totp {code} ({remaining}s) copied via {tool}"),
                Err(_) => format!("totp {code} ({remaining}s)"),
            });
        }
        Ok(_) => app.toast("unexpected reply"),
        Err(e) => app.toast(format!("{e}")),
    }
    Ok(())
}

// ------------------------------------------------------------------ event loop

pub fn run(socket: &Path) -> Result<()> {
    let mut terminal = ratatui::init();
    let result = event_loop(&mut terminal, socket);
    ratatui::restore();
    result
}

/// Render one frame to text instead of the terminal — for review, docs, and CI diffs.
pub fn snapshot(socket: &Path, width: u16, height: u16) -> Result<String> {
    let mut app = App::new();
    if let Ok(Response::Status { locked, vault, .. }) = ask(socket, Request::Status) {
        app.vault = vault;
        if locked {
            app.mode = Mode::Locked;
        } else {
            app.mode = Mode::Browsing;
            load_items(&mut app, socket)?;
        }
    }
    let mut term = ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height))?;
    term.draw(|f| app.draw(f))?;
    Ok(flatten(term.backend().buffer()))
}

fn flatten(buf: &ratatui::buffer::Buffer) -> String {
    let width = buf.area.width as usize;
    let mut out = String::new();
    for line in buf.content.chunks(width.max(1)) {
        for cell in line {
            out.push_str(cell.symbol());
        }
        out.push('\n');
    }
    out
}

fn event_loop(terminal: &mut ratatui::DefaultTerminal, socket: &Path) -> Result<()> {
    let mut app = App::new();

    // start from the daemon's actual state rather than assuming
    if let Ok(Response::Status { locked, vault, .. }) = ask(socket, Request::Status) {
        app.vault = vault;
        if locked {
            app.mode = Mode::Locked;
        } else {
            app.mode = Mode::Browsing;
            load_items(&mut app, socket)?;
        }
    }
    app.vault = if app.vault.is_empty() { socket.display().to_string() } else { app.vault };

    loop {
        app.tick();
        terminal.draw(|f| app.draw(f))?;

        if !event::poll(Duration::from_millis(200))? {
            continue;
        }
        let Event::Key(key) = event::read()? else { continue };
        if key.kind != event::KeyEventKind::Press {
            continue;
        }

        match app.mode {
            Mode::Locked => match key.code {
                KeyCode::Esc => return Ok(()),
                KeyCode::Enter => {
                    let pass = std::mem::take(&mut app.passphrase);
                    match ask(socket, Request::Unlock { passphrase: pass }) {
                        Ok(_) => {
                            app.mode = Mode::Browsing;
                            app.toast("unlocked");
                            load_items(&mut app, socket)?;
                        }
                        Err(e) => {
                            app.toast(format!("{e}"));
                        }
                    }
                }
                KeyCode::Backspace => {
                    app.passphrase.pop();
                }
                KeyCode::Char(c) => app.passphrase.push(c),
                _ => {}
            },
            Mode::Filtering => match key.code {
                KeyCode::Esc => {
                    app.filter.clear();
                    app.mode = Mode::Browsing;
                    app.selected = 0;
                    refresh_detail(&mut app, socket)?;
                }
                KeyCode::Enter => {
                    app.mode = Mode::Browsing;
                }
                KeyCode::Backspace => {
                    app.filter.pop();
                    app.selected = 0;
                    refresh_detail(&mut app, socket)?;
                }
                KeyCode::Char(c) => {
                    app.filter.push(c);
                    app.selected = 0;
                    refresh_detail(&mut app, socket)?;
                }
                _ => {}
            },
            Mode::Browsing => {
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('l') {
                    let _ = ask(socket, Request::Lock);
                    app.mode = Mode::Locked;
                    app.rows.clear();
                    app.detail = None;
                    app.passphrase.clear();
                    app.toast("locked");
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') => return Ok(()),
                    KeyCode::Char('j') | KeyCode::Down => {
                        app.move_down();
                        refresh_detail(&mut app, socket)?;
                    }
                    KeyCode::Char('k') | KeyCode::Up => {
                        app.move_up();
                        refresh_detail(&mut app, socket)?;
                    }
                    KeyCode::Char('g') => {
                        app.selected = 0;
                        refresh_detail(&mut app, socket)?;
                    }
                    KeyCode::Char('G') => {
                        app.selected = app.visible().len().saturating_sub(1);
                        refresh_detail(&mut app, socket)?;
                    }
                    KeyCode::Char('/') => {
                        app.mode = Mode::Filtering;
                    }
                    KeyCode::Char('r') => {
                        app.reveal_until = Some(Instant::now() + Duration::from_secs(REVEAL_SECS));
                        app.toast(format!("revealed for {REVEAL_SECS}s"));
                    }
                    KeyCode::Char('y') => copy_field(&mut app, socket, "password")?,
                    KeyCode::Char('t') => copy_totp(&mut app, socket)?,
                    _ => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn row(id: &str, title: &str, host: &str) -> ItemRow {
        ItemRow {
            id: id.into(),
            category: "login".into(),
            title: title.into(),
            subtitle: "hella".into(),
            url_host: host.into(),
        }
    }

    fn rendered(app: &App, w: u16, h: u16) -> String {
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| app.draw(f)).unwrap();
        let buf = term.backend().buffer();
        let width = buf.area.width as usize;
        let mut out = String::new();
        for line in buf.content.chunks(width.max(1)) {
            for cell in line {
                out.push_str(cell.symbol());
            }
            out.push('\n');
        }
        out
    }

    fn browsing() -> App {
        let mut app = App::new();
        app.mode = Mode::Browsing;
        app.vault = "/tmp/v.db".into();
        app.rows = vec![row("abcdef1234", "github", "github.com"), row("beef5678", "gitea", "gitea.local")];
        app.detail = Some(DetailView {
            id: "abcdef1234".into(),
            title: "github".into(),
            category: "login".into(),
            fields: vec![
                ("username".into(), "hella".into(), false),
                ("password".into(), "hunter2".into(), true),
            ],
            notes: "2fa enrolled".into(),
        });
        app
    }

    #[test]
    fn locked_screen_prompts_and_masks_typing() {
        let mut app = App::new();
        app.passphrase = "secret".into();
        let text = rendered(&app, 80, 24);
        assert!(text.contains("vault is locked"), "{text}");
        assert!(text.contains("••••••"), "passphrase must be masked: {text}");
        assert!(!text.contains("secret"), "passphrase leaked to the screen: {text}");
    }

    #[test]
    fn browsing_screen_shows_items_detail_and_keys() {
        let text = rendered(&browsing(), 100, 22);
        assert!(text.contains("GRIMOIRE"));
        assert!(text.contains("github"));
        assert!(text.contains("gitea"));
        assert!(text.contains("2fa enrolled"));
        assert!(text.contains("^L lock"));
        // concealed field is masked until revealed (7-char value → 7 bullets)
        assert!(text.contains("(7 chars, r to reveal)"), "{text}");
        assert!(!text.contains("hunter2"), "password shown without reveal: {text}");
    }

    #[test]
    fn reveal_shows_values_only_while_active() {
        let mut app = browsing();
        app.reveal_until = Some(Instant::now() + Duration::from_secs(REVEAL_SECS));
        assert!(rendered(&app, 100, 22).contains("hunter2"));

        app.reveal_until = Some(Instant::now() - Duration::from_secs(1));
        assert!(!rendered(&app, 100, 22).contains("hunter2"));
    }

    #[test]
    fn filter_narrows_the_list_and_is_reported() {
        let mut app = browsing();
        app.filter = "gitea".into();
        app.selected = 0;
        let text = rendered(&app, 100, 22);
        assert!(text.contains("filter: gitea"));
        assert_eq!(app.visible().len(), 1);
        assert_eq!(app.selected_row().unwrap().title, "gitea");
        assert!(text.contains("1 item(s)"));
    }

    #[test]
    fn selection_movement_is_bounded() {
        let mut app = browsing();
        app.move_up();
        assert_eq!(app.selected, 0);
        app.move_down();
        app.move_down();
        assert_eq!(app.selected, 1, "must not wrap past the end");
    }
}
