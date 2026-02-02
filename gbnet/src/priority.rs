//! Priority accumulator for bandwidth-limited entity replication.
//!
//! [`PriorityAccumulator`] tracks per-entity priority that grows over time,
//! ensuring all entities eventually get sent even at low priority.

use std::collections::HashMap;
use std::hash::Hash;

/// Per-entity priority tracking entry.
struct PriorityEntry {
    base: f32,
    accumulated: f32,
}

/// Accumulates priority per entity and drains the highest-priority entities
/// that fit within a byte budget.
pub struct PriorityAccumulator<Id: Hash + Eq> {
    entries: HashMap<Id, PriorityEntry>,
}

impl<Id: Hash + Eq + Clone> PriorityAccumulator<Id> {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Register an entity with a base priority. Higher base = more frequent sends.
    pub fn register(&mut self, id: Id, base_priority: f32) {
        self.entries.insert(
            id,
            PriorityEntry {
                base: base_priority,
                accumulated: 0.0,
            },
        );
    }

    /// Remove an entity from tracking.
    pub fn unregister(&mut self, id: &Id) {
        self.entries.remove(id);
    }

    /// Advance accumulated priority for all entities by `dt` seconds.
    pub fn accumulate(&mut self, dt: f32) {
        for entry in self.entries.values_mut() {
            entry.accumulated += entry.base * dt;
        }
    }

    /// Apply a priority modifier to a specific entity (e.g. from interest management).
    pub fn apply_modifier(&mut self, id: &Id, modifier: f32) {
        if let Some(entry) = self.entries.get_mut(id) {
            entry.accumulated *= modifier;
        }
    }

    /// Drain the highest-priority entities that fit within `budget_bytes`.
    /// `size_fn` returns the serialized size in bytes for a given entity ID.
    /// Returns the selected entity IDs in priority order (highest first).
    pub fn drain_top<F>(&mut self, budget_bytes: usize, size_fn: F) -> Vec<Id>
    where
        F: Fn(&Id) -> usize,
    {
        // Collect and sort by accumulated priority (descending)
        let mut sorted: Vec<_> = self
            .entries
            .iter()
            .map(|(id, entry)| (id.clone(), entry.accumulated))
            .collect();
        sorted.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        let mut selected = Vec::new();
        let mut remaining = budget_bytes;

        for (id, _priority) in sorted {
            let size = size_fn(&id);
            if size > remaining {
                continue;
            }
            remaining -= size;
            selected.push(id);
        }

        // Reset accumulated priority for selected entities
        for id in &selected {
            if let Some(entry) = self.entries.get_mut(id) {
                entry.accumulated = 0.0;
            }
        }

        selected
    }

    /// Number of tracked entities.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the accumulator is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get the current accumulated priority for an entity.
    pub fn get_priority(&self, id: &Id) -> Option<f32> {
        self.entries.get(id).map(|e| e.accumulated)
    }
}

impl<Id: Hash + Eq + Clone> Default for PriorityAccumulator<Id> {
    fn default() -> Self {
        Self::new()
    }
}
