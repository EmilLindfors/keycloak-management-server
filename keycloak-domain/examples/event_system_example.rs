use keycloak_domain::{
    application::ports::*,
    infrastructure::adapters::*,
};
use std::sync::Arc;
use uuid::Uuid;

/// Example event subscriber that logs all user-related events
struct UserEventLogger {
    name: String,
}

impl UserEventLogger {
    fn new(name: String) -> Self {
        Self { name }
    }
}

#[async_trait::async_trait]
impl EventSubscriber for UserEventLogger {
    async fn handle(&self, event: &DomainEvent) -> Result<(), EventError> {
        match &event.data {
            EventData::UserCreated { username, email, enabled } => {
                println!(
                    "[{}] User '{}' created in realm '{}' - email: {:?}, enabled: {}",
                    self.name, username, event.realm, email, enabled
                );
            }
            EventData::UserUpdated { username, changes } => {
                println!(
                    "[{}] User '{}' updated in realm '{}' - changes: {:?}",
                    self.name, username, event.realm, changes
                );
            }
            EventData::UserDeleted { username } => {
                println!(
                    "[{}] User '{}' deleted from realm '{}'",
                    self.name, username, event.realm
                );
            }
            _ => {
                println!(
                    "[{}] Received event: {} for aggregate {}",
                    self.name, event.event_type, event.aggregate_id
                );
            }
        }
        Ok(())
    }

    fn interested_in(&self) -> Vec<EventType> {
        vec![
            EventType::UserCreated,
            EventType::UserUpdated,
            EventType::UserDeleted,
            EventType::UserEnabled,
            EventType::UserDisabled,
        ]
    }
}

/// Example event subscriber that handles security-related events
struct SecurityEventHandler;

#[async_trait::async_trait]
impl EventSubscriber for SecurityEventHandler {
    async fn handle(&self, event: &DomainEvent) -> Result<(), EventError> {
        match event.event_type {
            EventType::UserPasswordReset => {
                println!("🔒 SECURITY: Password reset for user {}", event.aggregate_id);
                // In a real system, this might trigger additional security checks
                // or notify security teams
            }
            EventType::AdminLoginFailed => {
                println!("⚠️  SECURITY: Failed admin login attempt!");
                // In a real system, this might trigger rate limiting,
                // IP blocking, or alert security teams
            }
            EventType::RealmSecurityConfigured => {
                println!("🔧 SECURITY: Realm security settings changed for realm {}", event.realm);
                // In a real system, this might trigger compliance audits
                // or configuration validation
            }
            _ => {
                println!("🔍 SECURITY: Monitoring event: {}", event.event_type);
            }
        }
        Ok(())
    }

    fn interested_in(&self) -> Vec<EventType> {
        vec![
            EventType::UserPasswordReset,
            EventType::AdminLoginFailed,
            EventType::AdminLoginSuccessful,
            EventType::RealmSecurityConfigured,
            EventType::SystemError,
        ]
    }
}

/// Example of how to set up and use the event system
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Keycloak Domain Event System Example");
    println!("=========================================\n");

    // 1. Create event infrastructure components
    println!("📦 Setting up event infrastructure...");
    let event_store = Arc::new(InMemoryEventStore::new());
    let event_bus = Arc::new(InMemoryEventBus::new());
    
    // Create a composite publisher that stores events and publishes to subscribers
    let composite_publisher = Arc::new(CompositeEventPublisher::fail_fast(
        event_store.clone(),
        event_bus.clone(),
    ));

    // 2. Register event subscribers
    println!("📝 Registering event subscribers...");
    
    let user_logger = UserEventLogger::new("UserLogger".to_string());
    event_bus
        .subscribe(
            Box::new(user_logger),
            vec![
                EventType::UserCreated,
                EventType::UserUpdated,
                EventType::UserDeleted,
                EventType::UserEnabled,
                EventType::UserDisabled,
            ],
        )
        .await?;

    let security_handler = SecurityEventHandler;
    event_bus
        .subscribe(
            Box::new(security_handler),
            vec![
                EventType::UserPasswordReset,
                EventType::AdminLoginFailed,
                EventType::AdminLoginSuccessful,
                EventType::RealmSecurityConfigured,
                EventType::SystemError,
            ],
        )
        .await?;

    println!(
        "✅ Registered {} subscribers for user events",
        event_bus.subscriber_count(&EventType::UserCreated).await
    );
    println!(
        "✅ Registered {} subscribers for security events",
        event_bus.subscriber_count(&EventType::AdminLoginFailed).await
    );

    // 3. Simulate domain events
    println!("\n🎭 Simulating domain events...\n");

    // User lifecycle events
    let mut user_created_event = DomainEvent::user_created(
        "user-123".to_string(),
        "example-realm".to_string(),
        "john_doe".to_string(),
        Some("john@example.com".to_string()),
        true,
    )
    .with_metadata(
        EventMetadata::new()
            .with_user_id("admin-user".to_string())
            .with_correlation_id(Uuid::new_v4().to_string())
            .with_request_id("req-001".to_string())
    );
    user_created_event.version = 1; // Ensure proper version

    composite_publisher.publish(user_created_event).await?;

    // User update event
    let mut user_updated_event = DomainEvent::user_updated(
        "user-123".to_string(),
        "example-realm".to_string(),
        "john_doe".to_string(),
        vec!["email".to_string(), "first_name".to_string()],
    )
    .with_metadata(
        EventMetadata::new()
            .with_user_id("admin-user".to_string())
            .with_correlation_id(Uuid::new_v4().to_string())
    );
    user_updated_event.version = 2; // Sequential version

    composite_publisher.publish(user_updated_event).await?;

    // Security events
    let admin_login_event = DomainEvent::admin_login_successful(
        "admin-456".to_string(),
        "admin".to_string(),
        "example-realm".to_string(),
    )
    .with_metadata(
        EventMetadata::new()
            .with_client_id("admin-cli".to_string())
            .add_additional("ip_address".to_string(), "192.168.1.1".to_string())
    );

    composite_publisher.publish(admin_login_event).await?;

    let system_error_event = DomainEvent::system_error(
        "KEYCLOAK_API_ERROR".to_string(),
        "Failed to connect to external user store".to_string(),
        "UserFederationService".to_string(),
    );

    composite_publisher.publish(system_error_event).await?;

    // Batch events example
    let mut batch_events = Vec::new();
    for i in 1..=3 {
        let mut event = DomainEvent::realm_created(
            format!("realm-{}", i),
            format!("test-realm-{}", i),
            true,
        );
        event.version = 1; // Each realm starts with version 1
        batch_events.push(event);
    }

    println!("📦 Publishing batch of {} realm events...", batch_events.len());
    composite_publisher.publish_batch(batch_events).await?;

    // Allow some time for async event processing
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // 4. Query the event store
    println!("\n📊 Event Store Statistics:");
    println!("==========================");
    
    let stats = event_store.get_stats().await;
    println!("Total events stored: {}", stats.total_events);
    
    println!("\nEvents by type:");
    for (event_type, count) in &stats.events_by_type {
        println!("  {} → {}", event_type, count);
    }
    
    println!("\nEvents by realm:");
    for (realm, count) in &stats.events_by_realm {
        println!("  {} → {}", realm, count);
    }

    // Query specific events
    println!("\n🔍 Querying Events:");
    println!("===================");

    let user_events = event_store
        .get_events("user-123", None)
        .await?;
    println!("Found {} events for user-123", user_events.len());

    let security_events = event_store
        .get_events_by_type(&EventType::AdminLoginSuccessful, None, None)
        .await?;
    println!("Found {} admin login events", security_events.len());

    let realm_events = event_store
        .get_realm_events("example-realm", None, None)
        .await?;
    println!("Found {} events for example-realm", realm_events.len());

    // 5. Demonstrate event filtering
    println!("\n🔎 Event Filtering Demo:");
    println!("========================");

    let recent_events = event_store
        .get_events_by_type(
            &EventType::RealmCreated,
            Some(chrono::Utc::now() - chrono::Duration::seconds(10)),
            Some(2), // Limit to 2 events
        )
        .await?;
    println!("Found {} recent realm creation events (limited to 2)", recent_events.len());

    println!("\n✨ Event system demonstration complete!");
    println!("\nKey Features Demonstrated:");
    println!("- ✅ Event publishing (single and batch)");
    println!("- ✅ Multiple subscribers with different interests");
    println!("- ✅ Event storage and persistence");
    println!("- ✅ Event querying and filtering");
    println!("- ✅ Rich event metadata");
    println!("- ✅ Type-safe event data");
    println!("- ✅ Composite publishing (store + bus)");

    Ok(())
}