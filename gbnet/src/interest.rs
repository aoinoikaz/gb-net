//! Interest management for area-of-interest filtering.
//!
//! Determines which entities are relevant to a given observer, reducing
//! bandwidth by only replicating nearby or important entities.

/// Trait for determining entity relevance to an observer.
pub trait InterestManager {
    /// Returns `true` if the entity at `entity_pos` is relevant to the observer
    /// at `observer_pos`.
    fn relevant(&self, entity_pos: [f32; 3], observer_pos: [f32; 3]) -> bool;

    /// Returns a priority modifier for the entity relative to the observer.
    /// Values > 1.0 increase priority, < 1.0 decrease it. Default returns 1.0.
    fn priority_mod(&self, _entity_pos: [f32; 3], _observer_pos: [f32; 3]) -> f32 {
        1.0
    }
}

/// Radius-based interest: entities within `radius` distance are relevant.
pub struct RadiusInterest {
    pub radius: f32,
    radius_sq: f32,
}

impl RadiusInterest {
    pub fn new(radius: f32) -> Self {
        Self {
            radius,
            radius_sq: radius * radius,
        }
    }
}

impl InterestManager for RadiusInterest {
    fn relevant(&self, entity_pos: [f32; 3], observer_pos: [f32; 3]) -> bool {
        let dx = entity_pos[0] - observer_pos[0];
        let dy = entity_pos[1] - observer_pos[1];
        let dz = entity_pos[2] - observer_pos[2];
        let dist_sq = dx * dx + dy * dy + dz * dz;
        dist_sq <= self.radius_sq
    }

    fn priority_mod(&self, entity_pos: [f32; 3], observer_pos: [f32; 3]) -> f32 {
        let dx = entity_pos[0] - observer_pos[0];
        let dy = entity_pos[1] - observer_pos[1];
        let dz = entity_pos[2] - observer_pos[2];
        let dist_sq = dx * dx + dy * dy + dz * dz;
        if dist_sq >= self.radius_sq {
            return 0.0;
        }
        // Linear falloff: closer entities get higher priority
        1.0 - (dist_sq / self.radius_sq).sqrt()
    }
}

/// Grid cell coordinate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct GridCell {
    x: i32,
    y: i32,
    z: i32,
}

/// Grid-based area-of-interest: entities in the same or neighboring cells
/// are considered relevant.
pub struct GridInterest {
    pub cell_size: f32,
    inv_cell_size: f32,
}

impl GridInterest {
    pub fn new(cell_size: f32) -> Self {
        Self {
            cell_size,
            inv_cell_size: 1.0 / cell_size,
        }
    }

    fn to_cell(&self, pos: [f32; 3]) -> GridCell {
        GridCell {
            x: (pos[0] * self.inv_cell_size).floor() as i32,
            y: (pos[1] * self.inv_cell_size).floor() as i32,
            z: (pos[2] * self.inv_cell_size).floor() as i32,
        }
    }
}

impl InterestManager for GridInterest {
    fn relevant(&self, entity_pos: [f32; 3], observer_pos: [f32; 3]) -> bool {
        let ec = self.to_cell(entity_pos);
        let oc = self.to_cell(observer_pos);
        (ec.x - oc.x).abs() <= 1 && (ec.y - oc.y).abs() <= 1 && (ec.z - oc.z).abs() <= 1
    }
}
