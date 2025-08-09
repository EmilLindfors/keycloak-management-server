use crate::application::ports::{DomainEvent, EventBus, EventError, EventSubscriber, EventType};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uuid::Uuid;

/// In-memory event bus for routing events to subscribers
pub struct InMemoryEventBus {
    subscribers: Arc<RwLock<HashMap<String, SubscriberRegistration>>>,
}

struct SubscriberRegistration {
    id: String,
    subscriber: Box<dyn EventSubscriber>,
    event_types: Vec<EventType>,
}

impl InMemoryEventBus {
    pub fn new() -> Self {
        Self {
            subscribers: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for InMemoryEventBus {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EventBus for InMemoryEventBus {
    async fn subscribe(
        &self,
        subscriber: Box<dyn EventSubscriber>,
        event_types: Vec<EventType>,
    ) -> Result<(), EventError> {
        let subscriber_id = Uuid::new_v4().to_string();
        
        info!(
            "Registering subscriber {} for event types: {:?}",
            subscriber_id, event_types
        );

        let registration = SubscriberRegistration {
            id: subscriber_id.clone(),
            subscriber,
            event_types,
        };

        let mut subscribers = self.subscribers.write().await;
        subscribers.insert(subscriber_id, registration);

        Ok(())
    }

    async fn unsubscribe(&self, subscriber_id: &str) -> Result<(), EventError> {
        info!("Unsubscribing subscriber: {}", subscriber_id);

        let mut subscribers = self.subscribers.write().await;
        match subscribers.remove(subscriber_id) {
            Some(_) => {
                info!("Successfully unsubscribed: {}", subscriber_id);
                Ok(())
            }
            None => {
                warn!("Subscriber not found: {}", subscriber_id);
                Err(EventError::ValidationFailed {
                    message: format!("Subscriber not found: {}", subscriber_id),
                })
            }
        }
    }

    async fn publish(&self, event: DomainEvent) -> Result<(), EventError> {
        info!(
            "Publishing event {} for aggregate {} (type: {})",
            event.id, event.aggregate_id, event.event_type
        );

        let subscribers = self.subscribers.read().await;
        let mut interested_subscribers = Vec::new();

        // Find all subscribers interested in this event type
        for registration in subscribers.values() {
            if registration.event_types.contains(&event.event_type) {
                interested_subscribers.push(&registration.subscriber);
            }
        }

        info!(
            "Found {} subscribers interested in event type {}",
            interested_subscribers.len(),
            event.event_type
        );

        // Notify all interested subscribers
        let mut errors = Vec::new();
        for subscriber in interested_subscribers {
            if let Err(e) = subscriber.handle(&event).await {
                error!(
                    "Subscriber failed to handle event {}: {}",
                    event.id, e
                );
                errors.push(e);
            }
        }

        // If any subscribers failed, report the errors but don't fail the entire publish
        if !errors.is_empty() {
            warn!(
                "Event {} published with {} subscriber errors",
                event.id,
                errors.len()
            );
        }

        Ok(())
    }

    async fn subscriber_count(&self, event_type: &EventType) -> usize {
        let subscribers = self.subscribers.read().await;
        subscribers
            .values()
            .filter(|reg| reg.event_types.contains(event_type))
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::ports::{AggregateType, EventData};

    struct TestSubscriber {
        pub events_received: Arc<RwLock<Vec<DomainEvent>>>,
    }

    impl TestSubscriber {
        fn new() -> Self {
            Self {
                events_received: Arc::new(RwLock::new(Vec::new())),
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
            vec![EventType::UserCreated, EventType::UserUpdated]
        }
    }

    #[tokio::test]
    async fn test_event_bus_subscribe_and_publish() {
        let bus = InMemoryEventBus::new();
        let subscriber = TestSubscriber::new();
        let events_received = subscriber.events_received.clone();

        // Subscribe to user events
        bus.subscribe(
            Box::new(subscriber),
            vec![EventType::UserCreated, EventType::UserUpdated],
        )
        .await
        .unwrap();

        // Verify subscriber count
        assert_eq!(bus.subscriber_count(&EventType::UserCreated).await, 1);
        assert_eq!(bus.subscriber_count(&EventType::RealmCreated).await, 0);

        // Create and publish a user created event
        let event = DomainEvent::user_created(
            "user-123".to_string(),
            "test-realm".to_string(),
            "testuser".to_string(),
            Some("test@example.com".to_string()),
            true,
        );

        bus.publish(event.clone()).await.unwrap();

        // Verify the subscriber received the event
        let received_events = events_received.read().await;
        assert_eq!(received_events.len(), 1);
        assert_eq!(received_events[0].id, event.id);
        assert_eq!(received_events[0].event_type, EventType::UserCreated);
    }

    #[tokio::test]
    async fn test_event_bus_unsubscribe() {
        let bus = InMemoryEventBus::new();
        let subscriber = TestSubscriber::new();

        // Subscribe
        let subscriber_id = "test-subscriber";
        let mut subscribers = bus.subscribers.write().await;
        subscribers.insert(
            subscriber_id.to_string(),
            SubscriberRegistration {
                id: subscriber_id.to_string(),
                subscriber: Box::new(subscriber),
                event_types: vec![EventType::UserCreated],
            },
        );
        drop(subscribers);

        // Verify subscriber exists
        assert_eq!(bus.subscriber_count(&EventType::UserCreated).await, 1);

        // Unsubscribe
        bus.unsubscribe(subscriber_id).await.unwrap();

        // Verify subscriber is removed
        assert_eq!(bus.subscriber_count(&EventType::UserCreated).await, 0);
    }

    #[tokio::test]
    async fn test_event_bus_multiple_subscribers() {
        let bus = InMemoryEventBus::new();
        let subscriber1 = TestSubscriber::new();
        let subscriber2 = TestSubscriber::new();

        let events_received_1 = subscriber1.events_received.clone();
        let events_received_2 = subscriber2.events_received.clone();

        // Subscribe both subscribers
        bus.subscribe(Box::new(subscriber1), vec![EventType::UserCreated])
            .await
            .unwrap();
        bus.subscribe(Box::new(subscriber2), vec![EventType::UserCreated])
            .await
            .unwrap();

        // Verify subscriber count
        assert_eq!(bus.subscriber_count(&EventType::UserCreated).await, 2);

        // Publish an event
        let event = DomainEvent::user_created(
            "user-123".to_string(),
            "test-realm".to_string(),
            "testuser".to_string(),
            None,
            true,
        );

        bus.publish(event).await.unwrap();

        // Both subscribers should have received the event
        assert_eq!(events_received_1.read().await.len(), 1);
        assert_eq!(events_received_2.read().await.len(), 1);
    }
}