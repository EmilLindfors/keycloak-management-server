use crate::application::ports::{DomainEvent, EventError, EventPublisher};
use async_trait::async_trait;
use tokio::sync::mpsc;
use tracing::info;

/// Simple in-memory event publisher for testing and development
pub struct MemoryEventPublisher {
    sender: mpsc::UnboundedSender<DomainEvent>,
}

impl MemoryEventPublisher {
    pub fn new() -> (Self, mpsc::UnboundedReceiver<DomainEvent>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        (Self { sender }, receiver)
    }
}

#[async_trait]
impl EventPublisher for MemoryEventPublisher {
    async fn publish(&self, event: DomainEvent) -> Result<(), EventError> {
        info!(
            "Publishing event: {} for aggregate {}",
            event.event_type, event.aggregate_id
        );

        self.sender
            .send(event)
            .map_err(|e| EventError::PublishFailed {
                message: format!("Failed to send event: {e}"),
            })?;

        Ok(())
    }

    async fn publish_batch(&self, events: Vec<DomainEvent>) -> Result<(), EventError> {
        info!("Publishing batch of {} events", events.len());

        for event in events {
            self.publish(event).await?;
        }

        Ok(())
    }

    async fn flush(&self) -> Result<(), EventError> {
        // In-memory publisher doesn't need flushing
        Ok(())
    }
}

impl Default for MemoryEventPublisher {
    fn default() -> Self {
        let (publisher, _) = Self::new();
        publisher
    }
}
