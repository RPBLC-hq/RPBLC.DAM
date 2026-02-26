use dam_vault::VaultStore;
use std::collections::HashSet;
use std::sync::Arc;

use crate::resolve::resolve_text;

/// Buffers streaming text chunks and resolves PII references, handling
/// references that may be split across chunk boundaries.
///
/// Usage:
/// - Call `push()` with each text chunk — it returns resolved text that
///   is safe to emit, holding back any partial reference at the end.
/// - Call `finish()` when the content block ends — it flushes the entire
///   buffer (resolving any complete refs, leaving partials as-is).
pub struct StreamingResolver {
    vault: Arc<VaultStore>,
    allowed_refs: Arc<HashSet<String>>,
    buffer: String,
}

impl StreamingResolver {
    pub fn new(vault: Arc<VaultStore>, allowed_refs: Arc<HashSet<String>>) -> Self {
        Self {
            vault,
            allowed_refs,
            buffer: String::new(),
        }
    }

    /// Append a text chunk. Returns resolved text that can be emitted now.
    ///
    /// Scans backwards from the end of the buffer for an unmatched `[`
    /// (a potential partial reference). Everything before it gets resolved
    /// and returned; the tail is held until more data arrives.
    pub fn push(&mut self, chunk: &str) -> String {
        self.buffer.push_str(chunk);

        // Find the last `[` that doesn't have a matching `]` after it.
        let hold_from = self.find_partial_ref_start();

        if let Some(pos) = hold_from {
            // Split: resolve and emit everything before pos, hold the rest
            let emittable = self.buffer[..pos].to_string();
            let held = self.buffer[pos..].to_string();
            self.buffer = held;
            resolve_text(&self.vault, &emittable, Some(&self.allowed_refs))
        } else {
            // No partial ref — resolve and emit the entire buffer
            let emittable = std::mem::take(&mut self.buffer);
            resolve_text(&self.vault, &emittable, Some(&self.allowed_refs))
        }
    }

    /// Flush the remaining buffer (called at content_block_stop).
    /// Returns any remaining text, resolved as much as possible.
    pub fn finish(&mut self) -> String {
        let remaining = std::mem::take(&mut self.buffer);
        if remaining.is_empty() {
            return String::new();
        }
        resolve_text(&self.vault, &remaining, Some(&self.allowed_refs))
    }

    /// Find the byte offset of a potential partial reference at the end
    /// of the buffer. Returns `Some(pos)` if there's an unmatched `[`
    /// near the end, `None` if everything is complete.
    fn find_partial_ref_start(&self) -> Option<usize> {
        // Longest possible reference: `[custom:aaaaaaaaaaaaaaaa]` = 25 chars
        // (longest tag "custom" = 6 + colon + 16 hex + brackets).
        // Use a wider window for safety margin.
        let search_window = 35;
        let start = self.buffer.len().saturating_sub(search_window);
        let tail = &self.buffer[start..];

        // Find the last `[` in the tail
        if let Some(rel_pos) = tail.rfind('[') {
            let abs_pos = start + rel_pos;
            let after_bracket = &self.buffer[abs_pos..];

            // If there's a `]` after this `[`, the reference is complete
            if after_bracket.contains(']') {
                None
            } else {
                Some(abs_pos)
            }
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dam_core::PiiType;
    use dam_vault::generate_kek;
    use std::collections::HashSet;

    fn test_vault_with_entry() -> (Arc<VaultStore>, String) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.keep().join("test.db");
        let vault = Arc::new(VaultStore::open(&path, generate_kek()).unwrap());
        let pii_ref = vault
            .store_pii(PiiType::Email, "alice@example.com", None, None)
            .unwrap();
        (vault, pii_ref.display())
    }

    #[test]
    fn single_chunk_complete_ref() {
        let (vault, display) = test_vault_with_entry();
        let mut resolver = StreamingResolver::new(vault, Arc::new(HashSet::new()));
        let result = resolver.push(&format!("Hello {display} world"));
        assert_eq!(result, "Hello alice@example.com world");
        assert_eq!(resolver.finish(), "");
    }

    #[test]
    fn ref_split_across_two_chunks() {
        let (vault, display) = test_vault_with_entry();
        // display is like "[email:a3f71bc9]"
        let mid = display.len() / 2;
        let part1 = &format!("Hello {}", &display[..mid]);
        let part2 = &format!("{} world", &display[mid..]);

        let mut resolver = StreamingResolver::new(vault, Arc::new(HashSet::new()));
        let out1 = resolver.push(part1);
        assert_eq!(out1, "Hello ");

        let out2 = resolver.push(part2);
        assert_eq!(out2, "alice@example.com world");
        assert_eq!(resolver.finish(), "");
    }

    #[test]
    fn ref_split_across_three_chunks() {
        let (vault, display) = test_vault_with_entry();
        // Split "[email:a3f71bc9]" into three parts
        let third = display.len() / 3;
        let p1 = &display[..third];
        let p2 = &display[third..third * 2];
        let p3 = &display[third * 2..];

        let mut resolver = StreamingResolver::new(vault, Arc::new(HashSet::new()));

        let out1 = resolver.push(p1);
        assert_eq!(out1, "");

        let out2 = resolver.push(p2);
        assert_eq!(out2, "");

        let out3 = resolver.push(&format!("{p3} done"));
        assert_eq!(out3, "alice@example.com done");
    }

    #[test]
    fn no_refs_pass_through() {
        let (vault, _) = test_vault_with_entry();
        let mut resolver = StreamingResolver::new(vault, Arc::new(HashSet::new()));
        assert_eq!(resolver.push("Hello "), "Hello ");
        assert_eq!(resolver.push("world"), "world");
        assert_eq!(resolver.finish(), "");
    }

    #[test]
    fn finish_flushes_partial() {
        let (vault, display) = test_vault_with_entry();
        // Push only the start of a ref (no closing bracket)
        let partial = &display[..display.len() - 1]; // missing `]`

        let mut resolver = StreamingResolver::new(vault, Arc::new(HashSet::new()));
        let out = resolver.push(partial);
        assert_eq!(out, "");

        // finish should emit the partial text as-is (unresolvable)
        let flushed = resolver.finish();
        assert_eq!(flushed, partial);
    }

    #[test]
    fn unknown_ref_left_intact() {
        let (vault, _) = test_vault_with_entry();
        let mut resolver = StreamingResolver::new(vault, Arc::new(HashSet::new()));
        let out = resolver.push("See [phone:deadbeef] here");
        assert_eq!(out, "See [phone:deadbeef] here");
    }

    #[test]
    fn multiple_refs_in_one_chunk() {
        let (vault, display) = test_vault_with_entry();
        let phone_ref = vault
            .store_pii(PiiType::Phone, "555-1234", None, None)
            .unwrap();
        let phone_display = phone_ref.display();

        let mut resolver = StreamingResolver::new(vault, Arc::new(HashSet::new()));
        let out = resolver.push(&format!("{display} and {phone_display}"));
        // Original format is preserved through the vault round-trip
        assert_eq!(out, "alice@example.com and 555-1234");
    }

    #[test]
    fn bracket_in_normal_text_not_held_forever() {
        let (vault, _) = test_vault_with_entry();
        let mut resolver = StreamingResolver::new(vault, Arc::new(HashSet::new()));

        // A `[` without reference format — gets held initially
        let out1 = resolver.push("array[0");
        assert_eq!(out1, "array");

        // Next chunk completes non-ref bracket usage
        let out2 = resolver.push("] done");
        assert_eq!(out2, "[0] done");
    }
}
