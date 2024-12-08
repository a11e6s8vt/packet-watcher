use ratatui::widgets::TableState;
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    widgets::{Block, Borders, Cell, Row, Table},
    Frame,
};

pub struct App {
    state: TableState,
    items: Vec<Vec<String>>,
}

impl App {
    pub fn new() -> App {
        let items = vec![];
        let mut state = TableState::default();
        state.select(Some(0));

        App { state, items }
    }

    pub fn next(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i >= self.items.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }

    pub fn previous(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i == 0 {
                    self.items.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }

    pub fn add_row(&mut self, row: Vec<String>) {
        self.items.push(row);
        self.state.select(Some(self.items.len() - 1)); // Auto-scroll to the last row
    }
}

pub fn draw_ui(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(100)].as_ref())
        .split(f.area());

    // Header row
    let header = Row::new(vec![
        Cell::from("Family"),
        Cell::from("Protocol"),
        Cell::from("Local Addr."),
        Cell::from("Remote Addr."),
        Cell::from("Direction"),
        Cell::from("Action"),
        Cell::from("Reason for Action"),
    ]);

    let widths = [
        Constraint::Percentage(13),
        Constraint::Percentage(13),
        Constraint::Percentage(16),
        Constraint::Percentage(16),
        Constraint::Percentage(13),
        Constraint::Percentage(13),
        Constraint::Percentage(16),
    ];

    let rows = app.items.iter().map(|item| Row::new(item.clone()));

    let table = Table::new(rows, widths)
        .header(header.clone())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Packet-Watcher"),
        )
        .row_highlight_style(Style::default().fg(Color::Yellow))
        .highlight_symbol(">> ");

    f.render_stateful_widget(table, chunks[0], &mut app.state);
}
