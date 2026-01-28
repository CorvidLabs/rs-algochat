//! PSK state management for counter tracking and replay protection.
//!
//! Tracks send and receive counters to ensure messages are processed
//! in order and replayed messages are rejected.

use std::collections::HashSet;

use crate::psk_types::PSK_COUNTER_WINDOW;
use crate::types::{AlgoChatError, Result};

/// State for a PSK conversation with a single peer.
///
/// Tracks the send counter, the peer's last known counter, and a set
/// of seen counters for replay protection.
#[derive(Debug, Clone)]
pub struct PSKState {
    /// The next counter value to use when sending.
    pub send_counter: u32,
    /// The highest counter value received from the peer.
    pub peer_last_counter: u32,
    /// Set of recently seen counter values (for replay detection).
    pub seen_counters: HashSet<u32>,
}

impl PSKState {
    /// Creates a new PSK state with all counters at zero.
    pub fn new() -> Self {
        Self {
            send_counter: 0,
            peer_last_counter: 0,
            seen_counters: HashSet::new(),
        }
    }

    /// Validates a received counter value.
    ///
    /// A counter is valid if:
    /// 1. It has not been seen before (replay protection)
    /// 2. It is within the acceptable window of the last known counter
    ///
    /// # Arguments
    /// * `counter` - The counter value from the received message
    ///
    /// # Returns
    /// `Ok(true)` if valid, `Err` if invalid
    pub fn validate_counter(&self, counter: u32) -> Result<bool> {
        if self.seen_counters.contains(&counter) {
            return Err(AlgoChatError::DecryptionError(format!(
                "Replay detected: counter {} already seen",
                counter
            )));
        }

        if counter < self.peer_last_counter {
            let gap = self.peer_last_counter - counter;
            if gap > PSK_COUNTER_WINDOW {
                return Err(AlgoChatError::DecryptionError(format!(
                    "Counter {} is outside the acceptable window (last: {}, window: {})",
                    counter, self.peer_last_counter, PSK_COUNTER_WINDOW
                )));
            }
        }

        Ok(true)
    }

    /// Records a received counter value and updates state.
    ///
    /// This should be called after successfully decrypting a message.
    ///
    /// # Arguments
    /// * `counter` - The counter value from the received message
    pub fn record_receive(&mut self, counter: u32) {
        self.seen_counters.insert(counter);

        if counter > self.peer_last_counter {
            self.peer_last_counter = counter;
        }

        if self.peer_last_counter > PSK_COUNTER_WINDOW {
            let cutoff = self.peer_last_counter - PSK_COUNTER_WINDOW;
            self.seen_counters.retain(|&c| c >= cutoff);
        }
    }

    /// Advances and returns the next send counter.
    ///
    /// # Returns
    /// The counter value to use for the next outgoing message
    pub fn advance_send_counter(&mut self) -> u32 {
        let counter = self.send_counter;
        self.send_counter = self.send_counter.wrapping_add(1);
        counter
    }
}

impl Default for PSKState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_state() {
        let state = PSKState::new();
        assert_eq!(state.send_counter, 0);
        assert_eq!(state.peer_last_counter, 0);
        assert!(state.seen_counters.is_empty());
    }

    #[test]
    fn test_advance_send_counter() {
        let mut state = PSKState::new();
        assert_eq!(state.advance_send_counter(), 0);
        assert_eq!(state.advance_send_counter(), 1);
        assert_eq!(state.advance_send_counter(), 2);
        assert_eq!(state.send_counter, 3);
    }

    #[test]
    fn test_validate_and_record() {
        let mut state = PSKState::new();

        assert!(state.validate_counter(0).unwrap());
        state.record_receive(0);
        assert_eq!(state.peer_last_counter, 0);

        assert!(state.validate_counter(1).unwrap());
        state.record_receive(1);
        assert_eq!(state.peer_last_counter, 1);

        assert!(state.validate_counter(5).unwrap());
        state.record_receive(5);
        assert_eq!(state.peer_last_counter, 5);
    }

    #[test]
    fn test_replay_detection() {
        let mut state = PSKState::new();
        state.record_receive(0);
        let result = state.validate_counter(0);
        assert!(result.is_err());
    }

    #[test]
    fn test_counter_window() {
        let mut state = PSKState::new();
        state.record_receive(300);
        assert_eq!(state.peer_last_counter, 300);

        assert!(state.validate_counter(200).unwrap());

        let result = state.validate_counter(50);
        assert!(result.is_err());
    }

    #[test]
    fn test_out_of_order_messages() {
        let mut state = PSKState::new();

        assert!(state.validate_counter(3).unwrap());
        state.record_receive(3);
        assert!(state.validate_counter(1).unwrap());
        state.record_receive(1);
        assert!(state.validate_counter(2).unwrap());
        state.record_receive(2);
        assert!(state.validate_counter(0).unwrap());
        state.record_receive(0);

        assert_eq!(state.peer_last_counter, 3);
    }

    #[test]
    fn test_seen_counter_pruning() {
        let mut state = PSKState::new();
        for i in 0..10 {
            state.record_receive(i);
        }
        state.record_receive(PSK_COUNTER_WINDOW + 100);
        assert!(!state.seen_counters.contains(&0));
    }

    #[test]
    fn test_wrapping_send_counter() {
        let mut state = PSKState::new();
        state.send_counter = u32::MAX;
        let counter = state.advance_send_counter();
        assert_eq!(counter, u32::MAX);
        assert_eq!(state.send_counter, 0);
    }
}
