use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Event publisher port for domain events
#[async_trait]
pub trait EventPublisher: Send + Sync {
    /// Publish a single domain event
    async fn publish(&self, event: DomainEvent) -> Result<(), EventError>;

    /// Publish multiple domain events
    async fn publish_batch(&self, events: Vec<DomainEvent>) -> Result<(), EventError>;

    /// Flush any pending events
    async fn flush(&self) -> Result<(), EventError>;
}

/// Event subscriber port for handling domain events
#[async_trait]
pub trait EventSubscriber: Send + Sync {
    /// Handle a domain event
    async fn handle(&self, event: &DomainEvent) -> Result<(), EventError>;

    /// Get the event types this subscriber is interested in
    fn interested_in(&self) -> Vec<EventType>;
}

/// Domain event that represents something that happened in the domain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainEvent {
    pub id: String,
    pub event_type: EventType,
    pub aggregate_id: String,
    pub aggregate_type: AggregateType,
    pub realm: String,
    pub version: u64,
    pub timestamp: DateTime<Utc>,
    pub metadata: EventMetadata,
    pub data: EventData,
}

impl DomainEvent {
    pub fn new(
        event_type: EventType,
        aggregate_id: String,
        aggregate_type: AggregateType,
        realm: String,
        data: EventData,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            event_type,
            aggregate_id,
            aggregate_type,
            realm,
            version: 1,
            timestamp: Utc::now(),
            metadata: EventMetadata::default(),
            data,
        }
    }

    pub fn with_metadata(mut self, metadata: EventMetadata) -> Self {
        self.metadata = metadata;
        self
    }

    pub fn with_version(mut self, version: u64) -> Self {
        self.version = version;
        self
    }
}

/// Types of domain events
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EventType {
    // User events
    UserCreated,
    UserUpdated,
    UserDeleted,
    UserEnabled,
    UserDisabled,
    UserPasswordReset,
    UserEmailVerified,
    UserAttributesUpdated,
    UserAddedToGroup,
    UserRemovedFromGroup,
    UserRolesAdded,
    UserRolesRemoved,

    // Realm events
    RealmCreated,
    RealmUpdated,
    RealmDeleted,
    RealmEnabled,
    RealmDisabled,
    RealmSecurityConfigured,
    RealmImported,
    RealmExported,

    // Client events
    ClientCreated,
    ClientUpdated,
    ClientDeleted,
    ClientSecretRegenerated,
    ClientScopesUpdated,

    // Group events
    GroupCreated,
    GroupUpdated,
    GroupDeleted,
    GroupMembershipChanged,

    // Role events
    RoleCreated,
    RoleUpdated,
    RoleDeleted,
    RoleMappingAdded,
    RoleMappingRemoved,

    // Authentication events
    AdminLoginSuccessful,
    AdminLoginFailed,
    TokenRefreshed,
    SessionExpired,

    // System events
    SystemError,
    ConfigurationChanged,
}

impl std::fmt::Display for EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            EventType::UserCreated => "UserCreated",
            EventType::UserUpdated => "UserUpdated",
            EventType::UserDeleted => "UserDeleted",
            EventType::UserEnabled => "UserEnabled",
            EventType::UserDisabled => "UserDisabled",
            EventType::UserPasswordReset => "UserPasswordReset",
            EventType::UserEmailVerified => "UserEmailVerified",
            EventType::UserAttributesUpdated => "UserAttributesUpdated",
            EventType::UserAddedToGroup => "UserAddedToGroup",
            EventType::UserRemovedFromGroup => "UserRemovedFromGroup",
            EventType::UserRolesAdded => "UserRolesAdded",
            EventType::UserRolesRemoved => "UserRolesRemoved",
            EventType::RealmCreated => "RealmCreated",
            EventType::RealmUpdated => "RealmUpdated",
            EventType::RealmDeleted => "RealmDeleted",
            EventType::RealmEnabled => "RealmEnabled",
            EventType::RealmDisabled => "RealmDisabled",
            EventType::RealmSecurityConfigured => "RealmSecurityConfigured",
            EventType::RealmImported => "RealmImported",
            EventType::RealmExported => "RealmExported",
            EventType::ClientCreated => "ClientCreated",
            EventType::ClientUpdated => "ClientUpdated",
            EventType::ClientDeleted => "ClientDeleted",
            EventType::ClientSecretRegenerated => "ClientSecretRegenerated",
            EventType::ClientScopesUpdated => "ClientScopesUpdated",
            EventType::GroupCreated => "GroupCreated",
            EventType::GroupUpdated => "GroupUpdated",
            EventType::GroupDeleted => "GroupDeleted",
            EventType::GroupMembershipChanged => "GroupMembershipChanged",
            EventType::RoleCreated => "RoleCreated",
            EventType::RoleUpdated => "RoleUpdated",
            EventType::RoleDeleted => "RoleDeleted",
            EventType::RoleMappingAdded => "RoleMappingAdded",
            EventType::RoleMappingRemoved => "RoleMappingRemoved",
            EventType::AdminLoginSuccessful => "AdminLoginSuccessful",
            EventType::AdminLoginFailed => "AdminLoginFailed",
            EventType::TokenRefreshed => "TokenRefreshed",
            EventType::SessionExpired => "SessionExpired",
            EventType::SystemError => "SystemError",
            EventType::ConfigurationChanged => "ConfigurationChanged",
        };
        write!(f, "{name}")
    }
}

/// Aggregate types that can emit events
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AggregateType {
    User,
    Realm,
    Client,
    Group,
    Role,
    Session,
    System,
}

/// Event metadata containing contextual information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct EventMetadata {
    pub correlation_id: Option<String>,
    pub causation_id: Option<String>,
    pub user_id: Option<String>,
    pub client_id: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
    pub session_id: Option<String>,
    pub additional: std::collections::HashMap<String, String>,
}


impl EventMetadata {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_correlation_id(mut self, correlation_id: String) -> Self {
        self.correlation_id = Some(correlation_id);
        self
    }

    pub fn with_user_id(mut self, user_id: String) -> Self {
        self.user_id = Some(user_id);
        self
    }

    pub fn with_client_id(mut self, client_id: String) -> Self {
        self.client_id = Some(client_id);
        self
    }

    pub fn with_request_id(mut self, request_id: String) -> Self {
        self.request_id = Some(request_id);
        self
    }

    pub fn add_additional(mut self, key: String, value: String) -> Self {
        self.additional.insert(key, value);
        self
    }
}

/// Event data containing the actual event payload
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum EventData {
    UserCreated {
        username: String,
        email: Option<String>,
        enabled: bool,
    },
    UserUpdated {
        username: String,
        changes: Vec<String>,
    },
    UserDeleted {
        username: String,
    },
    UserPasswordReset {
        username: String,
        temporary: bool,
    },
    UserEmailVerified {
        username: String,
        email: String,
    },
    UserAttributesUpdated {
        username: String,
        attributes: std::collections::HashMap<String, Vec<String>>,
    },
    UserAddedToGroup {
        username: String,
        group_path: String,
    },
    UserRemovedFromGroup {
        username: String,
        group_path: String,
    },
    UserRolesAdded {
        username: String,
        roles: Vec<String>,
    },
    UserRolesRemoved {
        username: String,
        roles: Vec<String>,
    },
    RealmCreated {
        realm_name: String,
        enabled: bool,
    },
    RealmUpdated {
        realm_name: String,
        changes: Vec<String>,
    },
    RealmDeleted {
        realm_name: String,
    },
    RealmEnabled {
        realm_name: String,
    },
    RealmDisabled {
        realm_name: String,
    },
    RealmSecurityConfigured {
        realm_name: String,
        settings: Vec<String>,
    },
    RealmImported {
        realm_name: String,
    },
    RealmExported {
        realm_name: String,
    },
    ClientCreated {
        client_id: String,
        public_client: bool,
    },
    ClientUpdated {
        client_id: String,
        changes: Vec<String>,
    },
    ClientDeleted {
        client_id: String,
    },
    ClientSecretRegenerated {
        client_id: String,
    },
    GroupCreated {
        group_name: String,
        group_path: String,
    },
    GroupUpdated {
        group_name: String,
        changes: Vec<String>,
    },
    GroupDeleted {
        group_name: String,
        group_path: String,
    },
    RoleCreated {
        role_name: String,
        client_role: bool,
        container_id: String,
    },
    RoleUpdated {
        role_name: String,
        changes: Vec<String>,
    },
    RoleDeleted {
        role_name: String,
        client_role: bool,
    },
    AdminLoginSuccessful {
        username: String,
        realm: String,
    },
    AdminLoginFailed {
        username: String,
        realm: String,
        reason: String,
    },
    TokenRefreshed {
        username: String,
        realm: String,
    },
    SystemError {
        error_type: String,
        message: String,
        component: String,
    },
    ConfigurationChanged {
        component: String,
        changes: Vec<String>,
    },
    // Generic event data for custom events
    Generic {
        data: serde_json::Value,
    },
}

/// Event processing errors
#[derive(Debug, thiserror::Error)]
pub enum EventError {
    #[error("Event serialization failed: {message}")]
    SerializationFailed { message: String },

    #[error("Event publishing failed: {message}")]
    PublishFailed { message: String },

    #[error("Event handling failed: {message}")]
    HandlingFailed { message: String },

    #[error("Event store connection failed: {message}")]
    ConnectionFailed { message: String },

    #[error("Event store timeout")]
    Timeout,

    #[error("Event validation failed: {message}")]
    ValidationFailed { message: String },

    #[error("Duplicate event: {event_id}")]
    DuplicateEvent { event_id: String },

    #[error("Event not found: {event_id}")]
    EventNotFound { event_id: String },
}

/// Event store port for persisting events
#[async_trait]
pub trait EventStore: Send + Sync {
    /// Save a single event
    async fn save(&self, event: &DomainEvent) -> Result<(), EventError>;

    /// Save multiple events atomically
    async fn save_batch(&self, events: &[DomainEvent]) -> Result<(), EventError>;

    /// Get events for a specific aggregate
    async fn get_events(
        &self,
        aggregate_id: &str,
        from_version: Option<u64>,
    ) -> Result<Vec<DomainEvent>, EventError>;

    /// Get events by type
    async fn get_events_by_type(
        &self,
        event_type: &EventType,
        from_timestamp: Option<DateTime<Utc>>,
        limit: Option<usize>,
    ) -> Result<Vec<DomainEvent>, EventError>;

    /// Get events for a realm
    async fn get_realm_events(
        &self,
        realm: &str,
        from_timestamp: Option<DateTime<Utc>>,
        limit: Option<usize>,
    ) -> Result<Vec<DomainEvent>, EventError>;

    /// Check if event exists
    async fn exists(&self, event_id: &str) -> Result<bool, EventError>;

    /// Get the latest version for an aggregate
    async fn get_latest_version(&self, aggregate_id: &str) -> Result<Option<u64>, EventError>;
}

/// Event bus for routing events to subscribers
#[async_trait]
pub trait EventBus: Send + Sync {
    /// Register a subscriber for specific event types
    async fn subscribe(
        &self,
        subscriber: Box<dyn EventSubscriber>,
        event_types: Vec<EventType>,
    ) -> Result<(), EventError>;

    /// Unsubscribe a subscriber
    async fn unsubscribe(&self, subscriber_id: &str) -> Result<(), EventError>;

    /// Publish an event to all interested subscribers
    async fn publish(&self, event: DomainEvent) -> Result<(), EventError>;

    /// Get the number of subscribers for an event type
    async fn subscriber_count(&self, event_type: &EventType) -> usize;
}

/// Helper functions for creating common events
impl DomainEvent {
    pub fn user_created(
        user_id: String,
        realm: String,
        username: String,
        email: Option<String>,
        enabled: bool,
    ) -> Self {
        Self::new(
            EventType::UserCreated,
            user_id,
            AggregateType::User,
            realm,
            EventData::UserCreated {
                username,
                email,
                enabled,
            },
        )
    }

    pub fn user_updated(
        user_id: String,
        realm: String,
        username: String,
        changes: Vec<String>,
    ) -> Self {
        Self::new(
            EventType::UserUpdated,
            user_id,
            AggregateType::User,
            realm,
            EventData::UserUpdated { username, changes },
        )
    }

    pub fn user_deleted(user_id: String, realm: String, username: String) -> Self {
        Self::new(
            EventType::UserDeleted,
            user_id,
            AggregateType::User,
            realm,
            EventData::UserDeleted { username },
        )
    }

    pub fn realm_created(realm_id: String, realm_name: String, enabled: bool) -> Self {
        Self::new(
            EventType::RealmCreated,
            realm_id,
            AggregateType::Realm,
            realm_name.clone(),
            EventData::RealmCreated {
                realm_name,
                enabled,
            },
        )
    }

    pub fn realm_updated(realm_id: String, realm_name: String, changes: Vec<String>) -> Self {
        Self::new(
            EventType::RealmUpdated,
            realm_id,
            AggregateType::Realm,
            realm_name.clone(),
            EventData::RealmUpdated {
                realm_name,
                changes,
            },
        )
    }

    pub fn realm_deleted(realm_id: String, realm_name: String) -> Self {
        Self::new(
            EventType::RealmDeleted,
            realm_id,
            AggregateType::Realm,
            realm_name.clone(),
            EventData::RealmDeleted { realm_name },
        )
    }

    pub fn realm_enabled(realm_id: String, realm_name: String) -> Self {
        Self::new(
            EventType::RealmEnabled,
            realm_id,
            AggregateType::Realm,
            realm_name.clone(),
            EventData::RealmEnabled { realm_name },
        )
    }

    pub fn realm_disabled(realm_id: String, realm_name: String) -> Self {
        Self::new(
            EventType::RealmDisabled,
            realm_id,
            AggregateType::Realm,
            realm_name.clone(),
            EventData::RealmDisabled { realm_name },
        )
    }

    pub fn realm_security_configured(
        realm_id: String,
        realm_name: String,
        settings: Vec<String>,
    ) -> Self {
        Self::new(
            EventType::RealmSecurityConfigured,
            realm_id,
            AggregateType::Realm,
            realm_name.clone(),
            EventData::RealmSecurityConfigured {
                realm_name,
                settings,
            },
        )
    }

    pub fn realm_imported(realm_id: String, realm_name: String) -> Self {
        Self::new(
            EventType::RealmImported,
            realm_id,
            AggregateType::Realm,
            realm_name.clone(),
            EventData::RealmImported { realm_name },
        )
    }

    pub fn realm_exported(realm_id: String, realm_name: String) -> Self {
        Self::new(
            EventType::RealmExported,
            realm_id,
            AggregateType::Realm,
            realm_name.clone(),
            EventData::RealmExported { realm_name },
        )
    }

    pub fn client_created(
        client_id: String,
        realm: String,
        client_identifier: String,
        public_client: bool,
    ) -> Self {
        Self::new(
            EventType::ClientCreated,
            client_id.clone(),
            AggregateType::Client,
            realm,
            EventData::ClientCreated {
                client_id: client_identifier,
                public_client,
            },
        )
    }

    pub fn admin_login_successful(user_id: String, username: String, realm: String) -> Self {
        Self::new(
            EventType::AdminLoginSuccessful,
            user_id,
            AggregateType::Session,
            realm.clone(),
            EventData::AdminLoginSuccessful { username, realm },
        )
    }

    pub fn system_error(error_type: String, message: String, component: String) -> Self {
        Self::new(
            EventType::SystemError,
            Uuid::new_v4().to_string(),
            AggregateType::System,
            "system".to_string(),
            EventData::SystemError {
                error_type,
                message,
                component,
            },
        )
    }
}
