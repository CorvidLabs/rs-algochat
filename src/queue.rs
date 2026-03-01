//! Message queue for offline message support.
//!
//! This module provides a queue for managing pending outgoing messages,
//! supporting offline message composition and automatic retry.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;

use crate::models::{PendingMessage, PendingStatus};
use crate::types::Result;

/// Configuration for the send queue.
#[derive(Debug, Clone)]
pub struct QueueConfig {
    /// Maximum number of retry attempts.
    pub max_retries: u32,
    /// Delay between retry attempts.
    pub retry_delay: Duration,
    /// Maximum queue size.
    pub max_queue_size: usize,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            retry_delay: Duration::from_secs(5),
            max_queue_size: 100,
        }
    }
}

/// A queue for managing pending outgoing messages.
pub struct SendQueue {
    queue: Arc<RwLock<VecDeque<PendingMessage>>>,
    config: QueueConfig,
}

impl SendQueue {
    /// Creates a new send queue with the given configuration.
    pub fn new(config: QueueConfig) -> Self {
        Self {
            queue: Arc::new(RwLock::new(VecDeque::new())),
            config,
        }
    }

    /// Creates a new send queue with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(QueueConfig::default())
    }

    /// Enqueues a new message for sending.
    pub async fn enqueue(&self, message: PendingMessage) -> Result<()> {
        let mut queue = self.queue.write().await;

        if queue.len() >= self.config.max_queue_size {
            // Remove oldest failed messages to make room
            queue.retain(|m| {
                m.status != PendingStatus::Failed || m.can_retry(self.config.max_retries)
            });

            if queue.len() >= self.config.max_queue_size {
                return Err(crate::types::AlgoChatError::StorageFailed(
                    "Queue is full".to_string(),
                ));
            }
        }

        queue.push_back(message);
        Ok(())
    }

    /// Returns the next message ready for sending.
    pub async fn next_pending(&self) -> Option<PendingMessage> {
        let queue = self.queue.read().await;
        queue
            .iter()
            .find(|m| m.status == PendingStatus::Pending)
            .cloned()
    }

    /// Returns all pending messages.
    pub async fn all_pending(&self) -> Vec<PendingMessage> {
        let queue = self.queue.read().await;
        queue
            .iter()
            .filter(|m| m.status == PendingStatus::Pending)
            .cloned()
            .collect()
    }

    /// Returns messages ready for retry.
    pub async fn ready_for_retry(&self) -> Vec<PendingMessage> {
        let queue = self.queue.read().await;
        let now = SystemTime::now();

        queue
            .iter()
            .filter(|m| {
                if !m.can_retry(self.config.max_retries) {
                    return false;
                }

                match m.last_attempt {
                    Some(last) => now
                        .duration_since(last)
                        .map(|d| d >= self.config.retry_delay)
                        .unwrap_or(true),
                    None => true,
                }
            })
            .cloned()
            .collect()
    }

    /// Marks a message as currently sending.
    pub async fn mark_sending(&self, id: &str) -> Result<()> {
        let mut queue = self.queue.write().await;

        if let Some(msg) = queue.iter_mut().find(|m| m.id == id) {
            msg.mark_sending();
            Ok(())
        } else {
            Err(crate::types::AlgoChatError::MessageNotFound(id.to_string()))
        }
    }

    /// Marks a message as successfully sent.
    pub async fn mark_sent(&self, id: &str) -> Result<()> {
        let mut queue = self.queue.write().await;

        if let Some(msg) = queue.iter_mut().find(|m| m.id == id) {
            msg.mark_sent();
            Ok(())
        } else {
            Err(crate::types::AlgoChatError::MessageNotFound(id.to_string()))
        }
    }

    /// Marks a message as failed with an error.
    pub async fn mark_failed(&self, id: &str, error: &str) -> Result<()> {
        let mut queue = self.queue.write().await;

        if let Some(msg) = queue.iter_mut().find(|m| m.id == id) {
            msg.mark_failed(error.to_string());
            Ok(())
        } else {
            Err(crate::types::AlgoChatError::MessageNotFound(id.to_string()))
        }
    }

    /// Removes a message from the queue.
    pub async fn remove(&self, id: &str) -> Option<PendingMessage> {
        let mut queue = self.queue.write().await;

        if let Some(pos) = queue.iter().position(|m| m.id == id) {
            queue.remove(pos)
        } else {
            None
        }
    }

    /// Removes all sent messages from the queue.
    pub async fn prune_sent(&self) {
        let mut queue = self.queue.write().await;
        queue.retain(|m| m.status != PendingStatus::Sent);
    }

    /// Removes all messages that have exceeded max retries.
    pub async fn prune_failed(&self) {
        let mut queue = self.queue.write().await;
        let max_retries = self.config.max_retries;
        queue.retain(|m| m.status != PendingStatus::Failed || m.can_retry(max_retries));
    }

    /// Clears all messages from the queue.
    pub async fn clear(&self) {
        let mut queue = self.queue.write().await;
        queue.clear();
    }

    /// Returns the number of messages in the queue.
    pub async fn len(&self) -> usize {
        let queue = self.queue.read().await;
        queue.len()
    }

    /// Returns true if the queue is empty.
    pub async fn is_empty(&self) -> bool {
        let queue = self.queue.read().await;
        queue.is_empty()
    }

    /// Returns the number of pending messages.
    pub async fn pending_count(&self) -> usize {
        let queue = self.queue.read().await;
        queue
            .iter()
            .filter(|m| m.status == PendingStatus::Pending)
            .count()
    }

    /// Returns the number of failed messages.
    pub async fn failed_count(&self) -> usize {
        let queue = self.queue.read().await;
        queue
            .iter()
            .filter(|m| m.status == PendingStatus::Failed)
            .count()
    }

    /// Returns messages for a specific recipient.
    pub async fn messages_for(&self, recipient: &str) -> Vec<PendingMessage> {
        let queue = self.queue.read().await;
        queue
            .iter()
            .filter(|m| m.recipient == recipient)
            .cloned()
            .collect()
    }

    /// Resets a failed message to pending status for retry.
    pub async fn reset_for_retry(&self, id: &str) -> Result<()> {
        let mut queue = self.queue.write().await;

        if let Some(msg) = queue.iter_mut().find(|m| m.id == id) {
            if msg.can_retry(self.config.max_retries) {
                msg.status = PendingStatus::Pending;
                Ok(())
            } else {
                Err(crate::types::AlgoChatError::StorageFailed(
                    "Message has exceeded max retries".to_string(),
                ))
            }
        } else {
            Err(crate::types::AlgoChatError::MessageNotFound(id.to_string()))
        }
    }
}

impl Default for SendQueue {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_message(_id: &str, recipient: &str) -> PendingMessage {
        PendingMessage::new(recipient.to_string(), "Test content".to_string(), None)
    }

    #[tokio::test]
    async fn test_enqueue_and_dequeue() {
        let queue = SendQueue::with_defaults();

        let msg = test_message("1", "recipient1");
        let id = msg.id.clone();

        queue.enqueue(msg).await.unwrap();
        assert_eq!(queue.len().await, 1);

        let pending = queue.next_pending().await;
        assert!(pending.is_some());
        assert_eq!(pending.unwrap().id, id);
    }

    #[tokio::test]
    async fn test_mark_status() {
        let queue = SendQueue::with_defaults();

        let msg = test_message("1", "recipient1");
        let id = msg.id.clone();

        queue.enqueue(msg).await.unwrap();

        queue.mark_sending(&id).await.unwrap();
        assert_eq!(queue.pending_count().await, 0);

        queue.mark_sent(&id).await.unwrap();
        queue.prune_sent().await;
        assert!(queue.is_empty().await);
    }

    #[tokio::test]
    async fn test_failed_and_retry() {
        let queue = SendQueue::new(QueueConfig {
            max_retries: 2,
            retry_delay: Duration::from_millis(10),
            max_queue_size: 100,
        });

        let msg = test_message("1", "recipient1");
        let id = msg.id.clone();

        queue.enqueue(msg).await.unwrap();
        queue.mark_sending(&id).await.unwrap();
        queue.mark_failed(&id, "Test error").await.unwrap();

        assert_eq!(queue.failed_count().await, 1);

        // Should be ready for retry after delay
        tokio::time::sleep(Duration::from_millis(20)).await;
        let ready = queue.ready_for_retry().await;
        assert_eq!(ready.len(), 1);
    }

    #[tokio::test]
    async fn test_queue_full() {
        let queue = SendQueue::new(QueueConfig {
            max_retries: 3,
            retry_delay: Duration::from_secs(1),
            max_queue_size: 2,
        });

        queue.enqueue(test_message("1", "r1")).await.unwrap();
        queue.enqueue(test_message("2", "r2")).await.unwrap();

        // Third enqueue should fail — queue is full
        let result = queue.enqueue(test_message("3", "r3")).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_queue_remove() {
        let queue = SendQueue::with_defaults();
        let msg = test_message("1", "recipient1");
        let id = msg.id.clone();

        queue.enqueue(msg).await.unwrap();
        assert_eq!(queue.len().await, 1);

        let removed = queue.remove(&id).await;
        assert!(removed.is_some());
        assert!(queue.is_empty().await);

        // Remove non-existent
        let removed = queue.remove("nonexistent").await;
        assert!(removed.is_none());
    }

    #[tokio::test]
    async fn test_queue_prune_failed() {
        let queue = SendQueue::new(QueueConfig {
            max_retries: 1,
            retry_delay: Duration::from_millis(1),
            max_queue_size: 100,
        });

        let msg = test_message("1", "r1");
        let id = msg.id.clone();

        queue.enqueue(msg).await.unwrap();
        queue.mark_sending(&id).await.unwrap();
        queue.mark_failed(&id, "error").await.unwrap();

        assert_eq!(queue.len().await, 1);
        // Message has 1 retry, max_retries is 1, so can_retry is false
        queue.prune_failed().await;
        assert!(queue.is_empty().await);
    }

    #[tokio::test]
    async fn test_queue_clear() {
        let queue = SendQueue::with_defaults();
        queue.enqueue(test_message("1", "r1")).await.unwrap();
        queue.enqueue(test_message("2", "r2")).await.unwrap();

        assert_eq!(queue.len().await, 2);
        queue.clear().await;
        assert!(queue.is_empty().await);
    }

    #[tokio::test]
    async fn test_queue_messages_for_recipient() {
        let queue = SendQueue::with_defaults();
        queue.enqueue(test_message("1", "alice")).await.unwrap();
        queue.enqueue(test_message("2", "bob")).await.unwrap();
        queue.enqueue(test_message("3", "alice")).await.unwrap();

        let alice_msgs = queue.messages_for("alice").await;
        assert_eq!(alice_msgs.len(), 2);

        let bob_msgs = queue.messages_for("bob").await;
        assert_eq!(bob_msgs.len(), 1);

        let charlie_msgs = queue.messages_for("charlie").await;
        assert!(charlie_msgs.is_empty());
    }

    #[tokio::test]
    async fn test_queue_all_pending() {
        let queue = SendQueue::with_defaults();
        let msg1 = test_message("1", "r1");
        let id1 = msg1.id.clone();

        queue.enqueue(msg1).await.unwrap();
        queue.enqueue(test_message("2", "r2")).await.unwrap();

        // Mark first as sending
        queue.mark_sending(&id1).await.unwrap();

        let pending = queue.all_pending().await;
        assert_eq!(pending.len(), 1); // Only the second message
    }

    #[tokio::test]
    async fn test_queue_reset_for_retry() {
        let queue = SendQueue::new(QueueConfig {
            max_retries: 3,
            retry_delay: Duration::from_millis(1),
            max_queue_size: 100,
        });

        let msg = test_message("1", "r1");
        let id = msg.id.clone();

        queue.enqueue(msg).await.unwrap();
        queue.mark_sending(&id).await.unwrap();
        queue.mark_failed(&id, "temporary error").await.unwrap();

        // Reset for retry
        queue.reset_for_retry(&id).await.unwrap();

        let pending = queue.pending_count().await;
        assert_eq!(pending, 1);
    }

    #[tokio::test]
    async fn test_queue_reset_for_retry_exceeded() {
        let queue = SendQueue::new(QueueConfig {
            max_retries: 1,
            retry_delay: Duration::from_millis(1),
            max_queue_size: 100,
        });

        let msg = test_message("1", "r1");
        let id = msg.id.clone();

        queue.enqueue(msg).await.unwrap();
        queue.mark_sending(&id).await.unwrap();
        queue.mark_failed(&id, "error").await.unwrap();

        // Should fail — max retries exceeded
        let result = queue.reset_for_retry(&id).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_queue_mark_nonexistent() {
        let queue = SendQueue::with_defaults();

        let result = queue.mark_sending("nonexistent").await;
        assert!(result.is_err());

        let result = queue.mark_sent("nonexistent").await;
        assert!(result.is_err());

        let result = queue.mark_failed("nonexistent", "error").await;
        assert!(result.is_err());

        let result = queue.reset_for_retry("nonexistent").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_queue_not_ready_for_retry_too_soon() {
        let queue = SendQueue::new(QueueConfig {
            max_retries: 3,
            retry_delay: Duration::from_secs(3600), // 1 hour
            max_queue_size: 100,
        });

        let msg = test_message("1", "r1");
        let id = msg.id.clone();

        queue.enqueue(msg).await.unwrap();
        queue.mark_sending(&id).await.unwrap();
        queue.mark_failed(&id, "error").await.unwrap();

        // Should not be ready — retry_delay hasn't elapsed
        let ready = queue.ready_for_retry().await;
        assert!(ready.is_empty());
    }

    #[tokio::test]
    async fn test_queue_prune_sent() {
        let queue = SendQueue::with_defaults();

        let msg1 = test_message("1", "r1");
        let msg2 = test_message("2", "r2");
        let id1 = msg1.id.clone();

        queue.enqueue(msg1).await.unwrap();
        queue.enqueue(msg2).await.unwrap();

        queue.mark_sending(&id1).await.unwrap();
        queue.mark_sent(&id1).await.unwrap();

        queue.prune_sent().await;
        assert_eq!(queue.len().await, 1);
    }
}
