//! The Panels tab as plain data: the list being edited, where each tile will
//! sit, and what has been added or removed since the last save.
//!
//! Nothing here touches the wall. Add, remove, move and import only change the
//! session; the wall changes when [`crate::apply::prepare_apply`] turns the
//! session into a plan and the GUI executes it.

use crate::overrides::is_reserved;
use soc_core::Panel;
use std::collections::BTreeSet;

/// An unconfigured tile, as added at the glass.
pub fn blank_panel(id: &str, grid: (u32, u32)) -> Panel {
    let mut panel = Panel::new(id);
    panel.grid = grid;
    panel
}

/// One open settings window's view of the panels.
#[derive(Debug, Clone, PartialEq)]
pub struct PanelSession {
    panels: Vec<Panel>,
    /// Where each panel will sit after Apply, in `panels` order.
    grids: Vec<(u32, u32)>,
    added: Vec<String>,
    removed: BTreeSet<String>,
}

impl PanelSession {
    pub fn new(panels: &[Panel]) -> PanelSession {
        PanelSession {
            panels: panels.to_vec(),
            grids: panels.iter().map(|p| p.grid).collect(),
            added: Vec::new(),
            removed: BTreeSet::new(),
        }
    }

    /// The panels as they will be listed, in order.
    pub fn panels(&self) -> &[Panel] {
        &self.panels
    }

    fn index(&self, id: &str) -> Option<usize> {
        self.panels.iter().position(|p| p.id == id)
    }

    /// The cell `id` will occupy after Apply.
    pub fn grid_of(&self, id: &str) -> Option<(u32, u32)> {
        self.index(id).map(|i| self.grids[i])
    }

    /// Ids of panels created in this session (not yet on the wall).
    pub fn added(&self) -> &[String] {
        &self.added
    }

    /// Ids of panels on the wall that this session removed.
    pub fn removed(&self) -> &BTreeSet<String> {
        &self.removed
    }

    pub fn is_added(&self, id: &str) -> bool {
        self.added.iter().any(|a| a == id)
    }

    /// The first empty cell in reading order, or `None` when the grid is
    /// full. (The Python host's own version grew a row instead, placing the
    /// panel outside the grid — which the loader then refuses.)
    pub fn free_cell(&self, cols: u32, rows: u32) -> Option<(u32, u32)> {
        (0..rows).flat_map(|row| (0..cols).map(move |col| (col, row))).find(|cell| !self.grids.contains(cell))
    }

    /// An unused `panel-N` id, never one that was removed in this session.
    pub fn next_panel_id(&self) -> String {
        let mut n = self.panels.len() + 1;
        loop {
            let id = format!("panel-{n}");
            if self.index(&id).is_none() && !self.removed.contains(&id) && !is_reserved(&id) {
                return id;
            }
            n += 1;
        }
    }

    /// Add a blank panel in the first free cell. `None` when the grid is full:
    /// a panel outside the grid would fail validation at the next boot.
    pub fn add_panel(&mut self, cols: u32, rows: u32) -> Option<&Panel> {
        let cell = self.free_cell(cols, rows)?;
        let panel = blank_panel(&self.next_panel_id(), cell);
        self.added.push(panel.id.clone());
        self.grids.push(cell);
        self.panels.push(panel);
        self.panels.last()
    }

    /// Remove a panel from the list; the next Apply drops it from the wall.
    /// Returns whether it was there.
    pub fn remove_panel(&mut self, id: &str) -> bool {
        let Some(i) = self.index(id) else {
            return false;
        };
        self.panels.remove(i);
        self.grids.remove(i);
        let unsaved = self.is_added(id);
        self.added.retain(|a| a != id);
        // One added here never reached the wall, so there is nothing to remove.
        if !unsaved {
            self.removed.insert(id.to_string());
        }
        true
    }

    /// Move a panel up (`-1`) or down (`+1`) the list, swapping grid cells
    /// with its neighbour. Returns whether anything moved.
    pub fn move_panel(&mut self, id: &str, direction: i32) -> bool {
        let Some(i) = self.index(id) else {
            return false;
        };
        let Some(j) =
            isize::try_from(direction).ok().and_then(|d| i.checked_add_signed(d)).filter(|j| *j < self.panels.len())
        else {
            return false;
        };
        // The panels trade places in the list; each takes the other's cell.
        self.panels.swap(i, j);
        true
    }

    /// Replace the list with imported panels (already validated by the
    /// loader). Panels on the wall that the import does not mention become
    /// removals; imported ones the wall does not have become additions.
    pub fn import(&mut self, new_panels: Vec<Panel>) {
        let on_wall: BTreeSet<String> = self
            .panels
            .iter()
            .map(|p| p.id.clone())
            .filter(|id| !self.is_added(id))
            .chain(self.removed.iter().cloned())
            .collect();
        let new_ids: BTreeSet<&str> = new_panels.iter().map(|p| p.id.as_str()).collect();
        self.removed = on_wall.iter().filter(|id| !new_ids.contains(id.as_str())).cloned().collect();
        self.added = new_panels.iter().map(|p| p.id.clone()).filter(|id| !on_wall.contains(id)).collect();
        self.grids = new_panels.iter().map(|p| p.grid).collect();
        self.panels = new_panels;
    }

    /// Call after a successful save: what is on screen is now the baseline.
    pub fn commit(&mut self) {
        for (panel, cell) in self.panels.iter_mut().zip(&self.grids) {
            panel.grid = *cell;
        }
        self.added.clear();
        self.removed.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn panel(id: &str, grid: (u32, u32)) -> Panel {
        let mut p = blank_panel(id, grid);
        p.url = Some("http://a.test/".into());
        p
    }

    fn two() -> PanelSession {
        PanelSession::new(&[panel("p1", (0, 0)), panel("p2", (1, 0))])
    }

    #[test]
    fn blank_panel_is_an_unconfigured_direct_tile() {
        let p = blank_panel("panel-3", (0, 1));
        assert_eq!((p.id.as_str(), p.grid), ("panel-3", (0, 1)));
        assert!(!p.configured() && !p.auto_login());
        assert_eq!(p.keepalive.strategy, soc_core::KeepAliveStrategy::None);
    }

    #[test]
    fn add_uses_a_free_cell_and_refuses_when_full() {
        let mut full = two();
        assert!(full.add_panel(2, 1).is_none());
        assert_eq!(full.panels().len(), 2);

        let mut s = two();
        let added = s.add_panel(2, 2).unwrap().clone();
        assert_eq!((added.id.as_str(), added.grid), ("panel-3", (0, 1)));
        assert_eq!(s.added(), ["panel-3"]);
        assert_eq!(s.grid_of("panel-3"), Some((0, 1)));
    }

    #[test]
    fn new_ids_never_collide() {
        let mut s = PanelSession::new(&[panel("panel-3", (0, 0)), panel("panel-4", (1, 0))]);
        let id = s.add_panel(2, 2).unwrap().id.clone();
        assert_eq!(id, "panel-5");
        // A removed panel's id is not handed out again in the same session.
        let mut s = PanelSession::new(&[panel("panel-1", (0, 0)), panel("panel-2", (1, 0))]);
        s.remove_panel("panel-2");
        assert_eq!(s.next_panel_id(), "panel-3");
    }

    #[test]
    fn removing_an_unsaved_panel_leaves_no_trace() {
        let mut s = two();
        let id = s.add_panel(2, 2).unwrap().id.clone();
        assert!(s.remove_panel(&id));
        assert!(s.added().is_empty() && s.removed().is_empty());
        assert!(s.remove_panel("p2"));
        assert!(!s.remove_panel("p2"));
        assert_eq!(s.removed().iter().collect::<Vec<_>>(), ["p2"]);
        assert_eq!(s.free_cell(2, 1), Some((1, 0)), "the removed panel's cell is free again");
    }

    #[test]
    fn move_swaps_cells_and_only_commits_on_apply() {
        let mut s = two();
        assert!(s.move_panel("p1", 1));
        assert_eq!(s.panels().iter().map(|p| p.id.as_str()).collect::<Vec<_>>(), ["p2", "p1"]);
        assert_eq!((s.grid_of("p1"), s.grid_of("p2")), (Some((1, 0)), Some((0, 0))));
        // Closing the window now loses nothing: the panels still say where they are.
        assert_eq!(s.panels()[1].grid, (0, 0));
        assert!(!s.move_panel("p1", 1), "already last");
        assert!(!s.move_panel("p2", -1), "already first");
        assert!(!s.move_panel("nope", 1));
        s.commit();
        assert_eq!(s.panels()[1].grid, (1, 0));
    }

    #[test]
    fn import_turns_the_difference_into_additions_and_removals() {
        let mut s = two();
        s.add_panel(2, 2);
        s.import(vec![panel("p1", (0, 0)), panel("p3", (1, 0))]);
        assert_eq!(s.panels().iter().map(|p| p.id.as_str()).collect::<Vec<_>>(), ["p1", "p3"]);
        assert_eq!(s.added(), ["p3"]);
        assert_eq!(s.removed().iter().collect::<Vec<_>>(), ["p2"]);
        assert_eq!(s.grid_of("p3"), Some((1, 0)));
        // A second import that brings p2 back cancels its removal.
        s.import(vec![panel("p1", (0, 0)), panel("p2", (1, 0))]);
        assert!(s.added().is_empty() && s.removed().is_empty());
    }
}
