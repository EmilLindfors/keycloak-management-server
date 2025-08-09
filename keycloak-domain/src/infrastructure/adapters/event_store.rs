use crate::application::ports::{DomainEvent, EventError, EventStore, EventType};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// In-memory event store implementation for testing and development
pub struct InMemoryEventStore {
    events: Arc<RwLock<Vec<DomainEvent>>>,
    aggregate_versions: Arc<RwLock<HashMap<String, u64>>>,
}

impl InMemoryEventStore {
    pub fn new() -> Self {
        Self {
            events: Arc::new(RwLock::new(Vec::new())),
            aggregate_versions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get all events (for testing purposes)
    pub async fn get_all_events(&self) -> Vec<DomainEvent> {
        self.events.read().await.clone()
    }

    /// Clear all events (for testing purposes)
    pub async fn clear(&self) {
        self.events.write().await.clear();
        self.aggregate_versions.write().await.clear();
    }

    /// Get statistics about stored events
    pub async fn get_stats(&self) -> EventStoreStats {
        let events = self.events.read().await;
        let total_events = events.len();
        
        let mut events_by_type = HashMap::new();
        let mut events_by_aggregate = HashMap::new();
        let mut events_by_realm = HashMap::new();

        for event in events.iter() {
            *events_by_type.entry(event.event_type.clone()).or_insert(0) += 1;
            *events_by_aggregate.entry(event.aggregate_type.clone()).or_insert(0) += 1;
            *events_by_realm.entry(event.realm.clone()).or_insert(0) += 1;
        }

        EventStoreStats {
            total_events,
            events_by_type,
            events_by_aggregate: events_by_aggregate.into_iter().map(|(k, v)| (format!("{:?}", k), v)).collect(),
            events_by_realm,
        }
    }
}

impl Default for InMemoryEventStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EventStore for InMemoryEventStore {
    async fn save(&self, event: &DomainEvent) -> Result<(), EventError> {
        info!(
            "Saving event {} for aggregate {} (version: {})",
            event.id, event.aggregate_id, event.version
        );

        // Check for duplicate events
        let events = self.events.read().await;
        if events.iter().any(|e| e.id == event.id) {
            return Err(EventError::DuplicateEvent {
                event_id: event.id.clone(),
            });
        }
        drop(events);

        // Verify version is sequential for the aggregate
        let mut versions = self.aggregate_versions.write().await;
        let current_version = versions.get(&event.aggregate_id).unwrap_or(&0);
        
        if event.version != current_version + 1 {
            return Err(EventError::ValidationFailed {
                message: format!(
                    "Invalid version for aggregate {}: expected {}, got {}",
                    event.aggregate_id,
                    current_version + 1,
                    event.version
                ),
            });
        }

        // Update version and save event
        versions.insert(event.aggregate_id.clone(), event.version);
        drop(versions);

        let mut events = self.events.write().await;
        events.push(event.clone());

        info!("Event {} saved successfully", event.id);
        Ok(())
    }

    async fn save_batch(&self, events: &[DomainEvent]) -> Result<(), EventError> {
        info!("Saving batch of {} events", events.len());

        // Validate all events first
        let events_lock = self.events.read().await;
        for event in events {
            if events_lock.iter().any(|e| e.id == event.id) {
                return Err(EventError::DuplicateEvent {
                    event_id: event.id.clone(),
                });
            }
        }
        drop(events_lock);

        // Check versions for each aggregate
        let mut versions = self.aggregate_versions.write().await;
        let mut aggregate_versions_in_batch = HashMap::new();

        for event in events {
            let current_version = versions.get(&event.aggregate_id)
                .or_else(|| aggregate_versions_in_batch.get(&event.aggregate_id))
                .unwrap_or(&0);
            
            if event.version != current_version + 1 {
                return Err(EventError::ValidationFailed {
                    message: format!(
                        "Invalid version for aggregate {}: expected {}, got {}",
                        event.aggregate_id,
                        current_version + 1,
                        event.version
                    ),
                });
            }

            aggregate_versions_in_batch.insert(event.aggregate_id.clone(), event.version);
        }

        // Update versions and save all events
        for (aggregate_id, version) in aggregate_versions_in_batch {
            versions.insert(aggregate_id, version);
        }
        drop(versions);

        let mut events_store = self.events.write().await;
        events_store.extend(events.iter().cloned());

        info!("Successfully saved batch of {} events", events.len());
        Ok(())
    }

    async fn get_events(
        &self,
        aggregate_id: &str,
        from_version: Option<u64>,
    ) -> Result<Vec<DomainEvent>, EventError> {
        let events = self.events.read().await;
        let from_version = from_version.unwrap_or(0);

        let filtered_events: Vec<DomainEvent> = events
            .iter()
            .filter(|event| {
                event.aggregate_id == aggregate_id && event.version > from_version
            })
            .cloned()
            .collect();

        info!(
            "Found {} events for aggregate {} from version {}",
            filtered_events.len(),
            aggregate_id,
            from_version
        );

        Ok(filtered_events)
    }

    async fn get_events_by_type(
        &self,
        event_type: &EventType,
        from_timestamp: Option<DateTime<Utc>>,
        limit: Option<usize>,
    ) -> Result<Vec<DomainEvent>, EventError> {
        let events = self.events.read().await;
        let from_timestamp = from_timestamp.unwrap_or_else(|| DateTime::from_timestamp(0, 0).unwrap());

        let mut filtered_events: Vec<DomainEvent> = events
            .iter()
            .filter(|event| {
                event.event_type == *event_type && event.timestamp >= from_timestamp
            })
            .cloned()
            .collect();

        // Sort by timestamp
        filtered_events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        // Apply limit if specified
        if let Some(limit) = limit {
            filtered_events.truncate(limit);
        }

        info!(
            "Found {} events of type {} from timestamp {}",
            filtered_events.len(),
            event_type,
            from_timestamp
        );

        Ok(filtered_events)
    }

    async fn get_realm_events(
        &self,
        realm: &str,
        from_timestamp: Option<DateTime<Utc>>,
        limit: Option<usize>,
    ) -> Result<Vec<DomainEvent>, EventError> {
        let events = self.events.read().await;
        let from_timestamp = from_timestamp.unwrap_or_else(|| DateTime::from_timestamp(0, 0).unwrap());

        let mut filtered_events: Vec<DomainEvent> = events
            .iter()
            .filter(|event| {
                event.realm == realm && event.timestamp >= from_timestamp
            })
            .cloned()
            .collect();

        // Sort by timestamp
        filtered_events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        // Apply limit if specified
        if let Some(limit) = limit {
            filtered_events.truncate(limit);
        }

        info!(
            "Found {} events for realm {} from timestamp {}",
            filtered_events.len(),
            realm,
            from_timestamp
        );

        Ok(filtered_events)
    }

    async fn exists(&self, event_id: &str) -> Result<bool, EventError> {
        let events = self.events.read().await;
        let exists = events.iter().any(|event| event.id == event_id);
        Ok(exists)
    }

    async fn get_latest_version(&self, aggregate_id: &str) -> Result<Option<u64>, EventError> {
        let versions = self.aggregate_versions.read().await;
        Ok(versions.get(aggregate_id).copied())
    }
}

/// Statistics about events in the store
#[derive(Debug, Clone)]
pub struct EventStoreStats {
    pub total_events: usize,
    pub events_by_type: HashMap<EventType, usize>,
    pub events_by_aggregate: HashMap<String, usize>,
    pub events_by_realm: HashMap<String, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::ports::{AggregateType, EventData};

    #[tokio::test]
    async fn test_save_and_retrieve_events() {
        let store = InMemoryEventStore::new();

        // Create test event
        let event = DomainEvent::user_created(
            "user-123".to_string(),
            "test-realm".to_string(),
            "testuser".to_string(),
            Some("test@example.com".to_string()),
            true,
        );

        // Save event
        store.save(&event).await.unwrap();

        // Verify event exists
        assert!(store.exists(&event.id).await.unwrap());

        // Retrieve events for aggregate
        let events = store.get_events("user-123", None).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, event.id);

        // Check latest version
        let version = store.get_latest_version("user-123").await.unwrap();
        assert_eq!(version, Some(1));
    }

    #[tokio::test]
    async fn test_save_duplicate_event_fails() {
        let store = InMemoryEventStore::new();

        let event = DomainEvent::user_created(
            "user-123".to_string(),
            "test-realm".to_string(),
            "testuser".to_string(),
            None,
            true,
        );

        // Save first time - should succeed
        store.save(&event).await.unwrap();

        // Save again - should fail
        let result = store.save(&event).await;
        assert!(matches!(result, Err(EventError::DuplicateEvent { .. })));
    }

    #[tokio::test]
    async fn test_save_invalid_version_fails() {
        let store = InMemoryEventStore::new();

        // Create event with version 2 (should start with 1)
        let mut event = DomainEvent::user_created(
            "user-123".to_string(),
            "test-realm".to_string(),
            "testuser".to_string(),
            None,
            true,
        );
        event.version = 2;

        // Should fail due to invalid version
        let result = store.save(&event).await;
        assert!(matches!(result, Err(EventError::ValidationFailed { .. })));
    }

    #[tokio::test]
    async fn test_get_events_by_type() {
        let store = InMemoryEventStore::new();

        // Create different types of events
        let user_event = DomainEvent::user_created(
            "user-123".to_string(),
            "test-realm".to_string(),
            "testuser".to_string(),
            None,
            true,
        );

        let realm_event = DomainEvent::realm_created(
            "realm-456".to_string(),
            "test-realm".to_string(),
            true,
        );

        store.save(&user_event).await.unwrap();
        store.save(&realm_event).await.unwrap();

        // Get only user events
        let user_events = store
            .get_events_by_type(&EventType::UserCreated, None, None)
            .await
            .unwrap();

        assert_eq!(user_events.len(), 1);
        assert_eq!(user_events[0].event_type, EventType::UserCreated);

        // Get only realm events
        let realm_events = store
            .get_events_by_type(&EventType::RealmCreated, None, None)
            .await
            .unwrap();

        assert_eq!(realm_events.len(), 1);
        assert_eq!(realm_events[0].event_type, EventType::RealmCreated);
    }

    #[tokio::test]
    async fn test_get_realm_events() {
        let store = InMemoryEventStore::new();

        // Create events for different realms
        let event1 = DomainEvent::user_created(
            "user-123".to_string(),
            "realm1".to_string(),
            "testuser1".to_string(),
            None,
            true,
        );

        let event2 = DomainEvent::user_created(
            "user-456".to_string(),
            "realm2".to_string(),
            "testuser2".to_string(),
            None,
            true,
        );

        store.save(&event1).await.unwrap();
        store.save(&event2).await.unwrap();

        // Get events for realm1
        let realm1_events = store.get_realm_events("realm1", None, None).await.unwrap();
        assert_eq!(realm1_events.len(), 1);
        assert_eq!(realm1_events[0].realm, "realm1");

        // Get events for realm2
        let realm2_events = store.get_realm_events("realm2", None, None).await.unwrap();
        assert_eq!(realm2_events.len(), 1);
        assert_eq!(realm2_events[0].realm, "realm2");
    }

    #[tokio::test]
    async fn test_save_batch() {
        let store = InMemoryEventStore::new();

        // Create multiple events for the same aggregate with sequential versions
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

        // Save batch
        store.save_batch(&[event1, event2]).await.unwrap();

        // Verify both events were saved
        let events = store.get_events("user-123", None).await.unwrap();
        assert_eq!(events.len(), 2);

        // Verify latest version
        let version = store.get_latest_version("user-123").await.unwrap();
        assert_eq!(version, Some(2));
    }
}