#[derive(Clone, Debug)]
pub struct IdMap {
    mappings: Vec<Mapping>,
}

/// Map the range of IDs `[from_id, from_id + qty) --> [to_id, to_id + qty)`
#[derive(Clone, Debug, Copy, Eq, PartialEq)]
struct Mapping {
    inner_id: u32,
    outer_id: u32,
    qty: u32,
}

impl Default for IdMap {
    fn default() -> Self {
        Self::new()
    }
}

impl IdMap {
    pub const MAX_QTY: u32 = u32::MAX;

    pub fn new() -> IdMap {
        IdMap {
            mappings: Vec::new(),
        }
    }

    pub fn map_one(&mut self, outer_id: u32, inner_id: u32) {
        self.mappings.push(Mapping {
            inner_id,
            outer_id,
            qty: 1,
        });
    }

    pub fn map_many(&mut self, outer_id: u32, inner_id: u32, qty: u32) {
        if qty == 0 {
            return;
        }
        self.mappings.push(Mapping {
            inner_id,
            outer_id,
            qty,
        });
    }

    /// Format the [`IdMap`] in the style of a `/proc/PID/uid_map` or `/proc/PID/gid_map` file.
    pub fn into_idmap_file_contents(&self) -> String {
        let mut contents = String::new();
        for mapping in &self.mappings {
            contents.push_str(&format!(
                "{} {} {}\n",
                mapping.inner_id, mapping.outer_id, mapping.qty
            ));
        }
        contents
    }
}
