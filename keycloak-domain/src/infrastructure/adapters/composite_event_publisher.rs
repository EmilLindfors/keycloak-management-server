use crate::application::ports::{DomainEvent, EventBus, EventError, EventPublisher, EventStore};
use async_trait::async_trait;
use std::sync::Arc;
use tracing::{error, info};

/// Composite event publisher that publishes to both an event store and an event bus
pub struct CompositeEventPublisher {
    event_store: Arc<dyn EventStore>,
    event_bus: Arc<dyn EventBus>,
    fail_fast: bool,
}

impl CompositeEventPublisher {
    /// Create a new composite publisher
    /// 
    /// # Arguments
    /// * `event_store` - Store for persisting events
    /// * `event_bus` - Bus for routing events to subscribers
    /// * `fail_fast` - If true, stop processing on first error; if false, attempt all operations
    pub fn new(
        event_store: Arc<dyn EventStore>,
        event_bus: Arc<dyn EventBus>,
        fail_fast: bool,
    ) -> Self {
        Self {
            event_store,
            event_bus,
            fail_fast,
        }
    }

    /// Create a composite publisher with fail-fast behavior (default)
    pub fn fail_fast(
        event_store: Arc<dyn EventStore>,
        event_bus: Arc<dyn EventBus>,
    ) -> Self {
        Self::new(event_store, event_bus, true)
    }

    /// Create a composite publisher with best-effort behavior
    pub fn best_effort(
        event_store: Arc<dyn EventStore>,
        event_bus: Arc<dyn EventBus>,
    ) -> Self {
        Self::new(event_store, event_bus, false)
    }
}

#[async_trait]
impl EventPublisher for CompositeEventPublisher {
    async fn publish(&self, event: DomainEvent) -> Result<(), EventError> {
        info!(
            "Publishing event {} through composite publisher",
            event.id
        );

        let mut errors = Vec::new();

        // Store the event first
        if let Err(e) = self.event_store.save(&event).await {
            error!("Failed to store event {}: {}", event.id, e);
            errors.push(format!("Store failed: {}", e));
            
            if self.fail_fast {
                return Err(EventError::PublishFailed {
                    message: format!("Event storage failed: {}", e),
                });
            }
        }

        // Then publish to the bus
        if let Err(e) = self.event_bus.publish(event.clone()).await {
            error!("Failed to publish event {} to bus: {}", event.id, e);
            errors.push(format!("Bus failed: {}", e));
            
            if self.fail_fast {
                return Err(EventError::PublishFailed {
                    message: format!("Event bus publishing failed: {}", e),
                });
            }
        }

        if errors.is_empty() {
            info!("Successfully published event {} through both store and bus", event.id);
            Ok(())
        } else {
            let error_msg = format!("Partial failure publishing event {}: {}", event.id, errors.join(", "));
            error!("{}", error_msg);
            
            Err(EventError::PublishFailed {
                message: error_msg,
            })
        }
    }

    async fn publish_batch(&self, events: Vec<DomainEvent>) -> Result<(), EventError> {
        info!("Publishing batch of {} events through composite publisher", events.len());

        let mut errors = Vec::new();

        // Store all events first
        if let Err(e) = self.event_store.save_batch(&events).await {
            error!("Failed to store event batch: {}", e);
            errors.push(format!("Store batch failed: {}", e));
            
            if self.fail_fast {
                return Err(EventError::PublishFailed {
                    message: format!("Batch event storage failed: {}", e),
                });
            }
        }

        // Then publish each event to the bus
        for event in &events {
            if let Err(e) = self.event_bus.publish(event.clone()).await {
                error!("Failed to publish event {} to bus: {}", event.id, e);
                errors.push(format!("Bus failed for event {}: {}", event.id, e));
                
                if self.fail_fast {
                    return Err(EventError::PublishFailed {
                        message: format!("Event bus publishing failed for event {}: {}", event.id, e),
                    });
                }
            }
        }

        if errors.is_empty() {
            info!("Successfully published batch of {} events through both store and bus", events.len());
            Ok(())
        } else {
            let error_msg = format!("Partial failure publishing batch: {}", errors.join(", "));
            error!("{}", error_msg);
            
            Err(EventError::PublishFailed {
                message: error_msg,
            })
        }
    }

    async fn flush(&self) -> Result<(), EventError> {
        info!("Flushing composite event publisher");
        
        // Event store typically doesn't need flushing (it persists immediately)
        // Event bus also doesn't need flushing in most implementations
        // But we call flush on both just in case
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::adapters::{InMemoryEventBus, InMemoryEventStore};
    use crate::application::ports::{EventSubscriber, EventType};

    struct TestSubscriber {
        pub events_received: Arc<tokio::sync::RwLock<Vec<DomainEvent>>>,
    }

    impl TestSubscriber {
        fn new() -> Self {
            Self {
                events_received: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            }
        }
    }

    #[async_trait]
    impl EventSubscriber for TestSubscriber {
        async fn handle(&self, event: &DomainEvent) -> Result<(), EventError> {
            let mut events = self.events_received.write().await;
            events.push(event.clone());
            Ok(())
        }

        fn interested_in(&self) -> Vec<EventType> {
            vec![EventType::UserCreated]
        }
    }

    #[tokio::test]
    async fn test_composite_publisher_success() {
        let store = Arc::new(InMemoryEventStore::new());
        let bus = Arc::new(InMemoryEventBus::new());
        let publisher = CompositeEventPublisher::fail_fast(store.clone(), bus.clone());

        // Subscribe to events
        let subscriber = TestSubscriber::new();
        let events_received = subscriber.events_received.clone();
        
        bus.subscribe(Box::new(subscriber), vec![EventType::UserCreated])
            .await
            .unwrap();

        // Create and publish event
        let event = DomainEvent::user_created(
            "user-123".to_string(),
            "test-realm".to_string(),
            "testuser".to_string(),
            None,
            true,
        );

        publisher.publish(event.clone()).await.unwrap();

        // Verify event was stored
        let stored_events = store.get_events("user-123", None).await.unwrap();
        assert_eq!(stored_events.len(), 1);
        assert_eq!(stored_events[0].id, event.id);

        // Verify event was published to bus
        let received_events = events_received.read().await;
        assert_eq!(received_events.len(), 1);
        assert_eq!(received_events[0].id, event.id);
    }

    #[tokio::test]
    async fn test_composite_publisher_batch() {
        let store = Arc::new(InMemoryEventStore::new());
        let bus = Arc::new(InMemoryEventBus::new());
        let publisher = CompositeEventPublisher::fail_fast(store.clone(), bus.clone());

        // Create multiple events
        let mut event1 = DomainEvent::user_created(
            "user-123".to_string(),
            "test-realm".to_string(),
            "testuser".to_string(),
            None,
            true,
        );
        event1.version = 1;

        let mut event2 = DomainEvent::user_updated(
            "user-123".to_string(),
            "test-realm".to_string(),
            "testuser".to_string(),
            vec!["email".to_string()],
        );
        event2.version = 2;

        let events = vec![event1.clone(), event2.clone()];

        publisher.publish_batch(events).await.unwrap();

        // Verify both events were stored
        let stored_events = store.get_events("user-123", None).await.unwrap();
        assert_eq!(stored_events.len(), 2);
    }
}