/*!
# Keycloak Domain

Shared domain layer for Keycloak integration using hexagonal architecture principles.

This crate provides:
- Rich domain models for Keycloak entities (User, Realm, Client, etc.)
- Port definitions for external dependencies
- Application services implementing business use cases
- Infrastructure adapters for concrete implementations

## Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│                    Primary Adapters                        │
├─────────────────────┬───────────────────────────────────────┤
│   HTTP Server       │         MCP Server                    │
│   (Axum Handlers)   │    (MCP Tool Handlers)               │
└─────────────────────┴───────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                Application Layer                            │
├─────────────────────────────────────────────────────────────┤
│  • UserManagementService    • RealmManagementService       │
│  • ClientManagementService  • AuthenticationService        │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                 Domain Layer (Ports)                       │
├─────────────────────────────────────────────────────────────┤
│  • KeycloakRepository       • AuthenticationPort           │
│  • ConfigurationPort        • AuthorizationService         │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│              Infrastructure Layer (Adapters)               │
├─────────────────────────────────────────────────────────────┤
│  • KeycloakRestAdapter      • EnvConfigurationAdapter      │
│  • TokenManagerImpl         • AuthorizationServiceImpl     │
└─────────────────────────────────────────────────────────────┘
```

## Features

- `mcp`: Enable MCP server integration utilities
- `testing`: Enable mock implementations for testing

## Usage

```rust
use keycloak_domain::{
    application::services::UserManagementService,
    infrastructure::adapters::KeycloakRestAdapter,
    domain::entities::User,
};

// Create service with dependency injection
let user_service = UserManagementService::new(
    Arc::new(KeycloakRestAdapter::new(config)),
);

// Use business operations
let users = user_service.list_users("my-realm", &filter).await?;
```
*/

pub mod application;
pub mod domain;
pub mod infrastructure;

// Re-export commonly used types
pub use application::ports::*;
pub use application::services::*;
pub use domain::entities::*;
pub use domain::errors::*;

// #[cfg(feature = "mcp")]
// pub mod mcp; // TODO: Implement MCP module when needed

// #[cfg(feature = "testing")]
// pub mod testing; // TODO: Implement testing utilities when needed
