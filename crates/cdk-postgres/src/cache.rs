//! Prepared statements kept per connection, so that each SQL text is prepared once on it.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::{Mutex, MutexGuard, PoisonError};

/// How many prepared statements a connection keeps. A swap, mint or melt uses a few dozen
/// distinct SQL texts; an `IN (...)` list adds one per list length, so the cache needs a bound.
pub(crate) const CAPACITY: usize = 256;

/// A connection's prepared statements, by SQL text: at most `capacity`, oldest out first.
///
/// The lock is held only to look up, add or remove, never across an `await`. Two tasks that
/// prepare the same SQL at once both prepare it; the first one added is kept, and the other is
/// dropped (for a prepared statement, that closes it on the server).
pub(crate) struct StatementCache<V> {
    capacity: usize,
    entries: Mutex<Entries<V>>,
}

struct Entries<V> {
    by_sql: HashMap<String, V>,
    /// The SQL texts in the order they were added, oldest first.
    order: VecDeque<String>,
}

impl<V: Clone> StatementCache<V> {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: Mutex::new(Entries {
                by_sql: HashMap::new(),
                order: VecDeque::new(),
            }),
        }
    }

    fn entries(&self) -> MutexGuard<'_, Entries<V>> {
        // Nothing here panics while holding the lock; if something did, the map and the queue
        // could at worst disagree about one SQL text, which only costs a prepare. Go on.
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The value cached for `sql`, if any.
    pub(crate) fn get(&self, sql: &str) -> Option<V> {
        self.entries().by_sql.get(sql).cloned()
    }

    /// Caches `value` for `sql`, removing the oldest entries to stay within the capacity, and
    /// returns the value now cached for `sql`: `value`, or the one another task added first.
    pub(crate) fn insert(&self, sql: &str, value: V) -> V {
        let mut entries = self.entries();
        if let Some(existing) = entries.by_sql.get(sql) {
            return existing.clone();
        }
        while entries.by_sql.len() >= self.capacity {
            let Some(oldest) = entries.order.pop_front() else {
                break;
            };
            entries.by_sql.remove(&oldest);
        }
        entries.order.push_back(sql.to_owned());
        entries.by_sql.insert(sql.to_owned(), value.clone());
        value
    }

    /// Forgets the value cached for `sql`, if any.
    pub(crate) fn remove(&self, sql: &str) {
        let mut entries = self.entries();
        if entries.by_sql.remove(sql).is_some() {
            entries.order.retain(|cached| cached != sql);
        }
    }

    /// How many values are cached.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries().by_sql.len()
    }
}

impl<V> fmt::Debug for StatementCache<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cached = self
            .entries
            .lock()
            .map(|entries| entries.by_sql.len())
            .unwrap_or_default();
        f.debug_struct("StatementCache")
            .field("capacity", &self.capacity)
            .field("cached", &cached)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_what_it_is_given() {
        let cache = StatementCache::new(4);
        assert_eq!(cache.get("SELECT 1"), None);
        assert_eq!(cache.insert("SELECT 1", 1), 1);
        assert_eq!(cache.get("SELECT 1"), Some(1));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn keeps_the_first_value_for_a_sql_text() {
        let cache = StatementCache::new(4);
        cache.insert("SELECT 1", 1);
        assert_eq!(
            cache.insert("SELECT 1", 2),
            1,
            "the value added first is kept"
        );
        assert_eq!(cache.get("SELECT 1"), Some(1));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn removes_the_oldest_at_capacity() {
        let cache = StatementCache::new(2);
        cache.insert("a", 1);
        cache.insert("b", 2);
        cache.insert("c", 3);
        assert_eq!(cache.get("a"), None, "the oldest is gone");
        assert_eq!(cache.get("b"), Some(2));
        assert_eq!(cache.get("c"), Some(3));
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn remove_forgets_a_sql_text() {
        let cache = StatementCache::new(2);
        cache.insert("a", 1);
        cache.insert("b", 2);
        cache.remove("a");
        cache.remove("not cached");
        assert_eq!(cache.get("a"), None);
        assert_eq!(cache.len(), 1);
        // With "a" gone from the queue too, adding two more removes only "b".
        cache.insert("c", 3);
        assert_eq!(cache.get("b"), Some(2));
        cache.insert("d", 4);
        assert_eq!(cache.get("b"), None);
        assert_eq!(cache.get("c"), Some(3));
        assert_eq!(cache.get("d"), Some(4));
    }
}
