# CLAUDE.md - Rust-Optimized Development Guidelines

## 🦀 Rust-First Philosophy

### Zero-Compromise Type Safety
- **Leverage the Borrow Checker** - Let Rust prevent bugs at compile time, don't fight it
- **Explicit Over Implicit** - Use `Result<T, E>` everywhere, never unwrap without justification
- **Type-Driven Design** - Make invalid states unrepresentable with the type system
- **No Runtime Surprises** - If it compiles, it should work correctly

### Never Take Shortcuts
- **No `.unwrap()` without documentation** - Always explain why it's safe or use `expect()` with context
- **No `unsafe` without thorough review** - Document all invariants and safety requirements
- **No `todo!()` in committed code** - Use typed placeholders or feature gates instead
- **No silencing warnings** - Fix the root cause, don't `#[allow()]` unless absolutely necessary

## 🏗️ Idiomatic Rust Code

### Modern Rust Language Features (Edition 2024)
```rust
// Use if-let chaining (Rust 1.65+)
if let Some(user) = users.get(&user_id) 
    && let Ok(profile) = user.load_profile().await 
    && profile.is_verified() {
    // Handle verified user with profile
    process_verified_user(user, profile).await?;
}

// Pattern matching with guards
match authentication_result {
    Ok(token) if token.is_expired() => {
        warn!("Token expired, requesting refresh");
        refresh_token(&token).await?
    }
    Ok(token) if token.has_required_scopes(&required_scopes) => {
        info!("Authentication successful");
        token
    }
    Ok(_) => return Err(AuthError::InsufficientPermissions),
    Err(e) => return Err(AuthError::AuthenticationFailed(e)),
}

// Use question mark operator with custom error conversion
let user = self.repository
    .find_user(&user_id)?
    .ok_or(DomainError::UserNotFound { user_id })?;

// Destructuring with defaults
let CreateUserRequest {
    username,
    email,
    enabled = true,  // Default value
    attributes = HashMap::new(),  // Default value
    ..  // Ignore other fields
} = request;

// Iterator chains with try_collect (when available)
let user_ids: Result<Vec<_>, _> = users
    .iter()
    .filter(|u| u.is_active())
    .map(|u| u.id())
    .collect();

// Use matches! macro for boolean checks
if matches!(user.status(), UserStatus::Verified | UserStatus::PendingVerification) {
    send_notification(&user).await?;
}
```

### Advanced Type System Usage

### Newtype Pattern for Domain Safety
```rust
// ALWAYS prefer domain-specific types over primitives
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct UserId(uuid::Uuid);

#[derive(Debug, Clone, PartialEq, Eq)]  
pub struct RealmName(String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Email(String);

impl Email {
    pub fn new(email: String) -> Result<Self, ValidationError> {
        // Validate email format using modern Rust patterns
        let email = email.trim();
        
        if email.is_empty() {
            return Err(ValidationError::EmptyEmail);
        }
        
        // Use if-let for validation chain
        if let Some((local, domain)) = email.split_once('@')
            && !local.is_empty()
            && !domain.is_empty()
            && domain.contains('.') {
            Ok(Email(email.to_owned()))
        } else {
            Err(ValidationError::InvalidEmailFormat)
        }
    }
    
    pub fn domain(&self) -> Option<&str> {
        self.0.split_once('@').map(|(_, domain)| domain)
    }
}
```

### Type States for Complex Workflows
```rust
use std::marker::PhantomData;

// Use phantom types to enforce state transitions at compile time
pub struct User<State = Unverified> {
    pub id: UserId,
    pub email: Email,
    pub created_at: chrono::DateTime<chrono::Utc>,
    _state: PhantomData<State>,
}

pub struct Unverified;
pub struct Verified;
pub struct Disabled;

impl User<Unverified> {
    pub fn verify(self, verification_token: &str) -> Result<User<Verified>, ValidationError> {
        // Validate token logic here
        if verification_token.len() < 32 {
            return Err(ValidationError::InvalidVerificationToken);
        }
        
        Ok(User {
            id: self.id,
            email: self.email,
            created_at: self.created_at,
            _state: PhantomData,
        })
    }
}

impl User<Verified> {
    pub fn disable(self, reason: DisableReason) -> User<Disabled> {
        User {
            id: self.id,
            email: self.email,
            created_at: self.created_at,
            _state: PhantomData,
        }
    }
    
    pub fn can_login(&self) -> bool { true }
}

impl User<Disabled> {
    pub fn can_login(&self) -> bool { false }
}
```

### Smart Constructors with Validation
```rust
#[derive(Debug, Clone)]
pub struct PasswordHash {
    hash: String,
    algorithm: HashAlgorithm,
}

impl PasswordHash {
    // Private field, public constructor ensures validation
    pub fn new(plaintext: &str) -> Result<Self, ValidationError> {
        use zeroize::Zeroize;
        
        let mut plaintext = plaintext.to_owned();
        
        // Use defer pattern for cleanup
        defer! {
            plaintext.zeroize();
        }
        
        // Modern validation pattern
        match plaintext.len() {
            0 => Err(ValidationError::EmptyPassword),
            1..=7 => Err(ValidationError::PasswordTooShort),
            8.. => {
                let hash = bcrypt::hash(&plaintext, bcrypt::DEFAULT_COST)
                    .map_err(ValidationError::HashingFailed)?;
                    
                Ok(PasswordHash {
                    hash,
                    algorithm: HashAlgorithm::BCrypt,
                })
            }
        }
    }
    
    pub fn verify(&self, plaintext: &str) -> Result<bool, ValidationError> {
        bcrypt::verify(plaintext, &self.hash)
            .map_err(ValidationError::VerificationFailed)
    }
}
```

### Error Handling with Context
```rust
#[derive(Debug, thiserror::Error)]
pub enum DomainError {
    #[error("User not found: {user_id}")]
    UserNotFound { user_id: UserId },
    
    #[error("Invalid email format: {email}")]
    InvalidEmail { email: String },
    
    #[error("Authentication failed for realm '{realm}': {reason}")]
    AuthenticationFailed { realm: String, reason: String },
    
    #[error("Validation error: {field} - {message}")]
    Validation { field: String, message: String },
    
    #[error("Keycloak API error")]
    KeycloakApi(#[from] keycloak::Error),
    
    #[error("Network error")]
    Network(#[from] reqwest::Error),
    
    #[error("Serialization error")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

// Extension trait for adding context to Results
trait ResultExt<T, E> {
    fn with_context<F>(self, f: F) -> Result<T, DomainError>
    where
        F: FnOnce() -> String;
}

impl<T, E> ResultExt<T, E> for Result<T, E>
where
    E: Into<DomainError>,
{
    fn with_context<F>(self, f: F) -> Result<T, DomainError>
    where
        F: FnOnce() -> String,
    {
        self.map_err(|e| {
            let base_error = e.into();
            let context = f();
            DomainError::Internal(anyhow::anyhow!("{}: {}", context, base_error))
        })
    }
}
```

## 🧪 Comprehensive Testing Strategy

### Test Organization Hierarchy
```rust
// tests/
//   ├── unit/           # Fast, isolated tests
//   ├── integration/    # Cross-module, in-process tests  
//   ├── contract/       # API contract tests
//   └── e2e/           # Full system tests with TestContainers
```

### Modern Testing Patterns
```rust
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::test]
async fn test_user_creation_with_modern_patterns() {
    // Use Arc<RwLock<>> for shared mutable state in tests
    let state = Arc::new(RwLock::new(HashMap::new()));
    
    // Test with proper error handling
    let email = Email::new("test@example.com".to_string())
        .expect("Valid email should parse");
    
    let user = User::new(UserId::new(), email)
        .expect("User creation should succeed");
    
    // Use pattern matching for assertions
    match user.state() {
        UserState::Unverified => {
            // Expected state
        }
        other => panic!("Expected Unverified state, got {:?}", other),
    }
}

// Property-based testing with modern syntax
#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn email_roundtrip_property(
            email in r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        ) {
            if let Ok(parsed) = Email::new(email.clone()) {
                prop_assert_eq!(parsed.as_str(), &email);
            }
        }

        #[test]
        fn user_id_uniqueness_property(ids in prop::collection::vec(any::<u128>(), 1..100)) {
            let user_ids: Vec<UserId> = ids.into_iter().map(UserId::from).collect();
            let unique_count = user_ids.iter().collect::<std::collections::HashSet<_>>().len();
            prop_assert_eq!(unique_count, user_ids.len());
        }
    }
}
```

### Integration Testing with TestContainers
```rust
use testcontainers::{clients::Cli, images::generic::GenericImage};

#[tokio::test]
async fn test_full_user_lifecycle() {
    let docker = Cli::default();
    let keycloak_image = GenericImage::new("quay.io/keycloak/keycloak", "latest")
        .with_exposed_port(8080)
        .with_env_var("KEYCLOAK_ADMIN", "admin")
        .with_env_var("KEYCLOAK_ADMIN_PASSWORD", "admin");
        
    let container = docker.run(keycloak_image);
    let port = container.get_host_port_ipv4(8080);
    let base_url = format!("http://localhost:{}", port);
    
    // Wait for Keycloak to be ready using modern async patterns
    wait_for_service_ready(&base_url).await
        .expect("Keycloak should start within timeout");
    
    let client = KeycloakClient::new(&base_url, "admin", "admin").await
        .expect("Should connect to Keycloak");
    
    // Test the full user lifecycle
    let create_request = CreateUserRequest {
        username: "testuser".to_owned(),
        email: Email::new("test@example.com".to_owned())?,
        enabled: true,
        ..Default::default()
    };
    
    let user_id = client.create_user("master", &create_request).await?;
    
    // Verify creation
    let user = client.get_user("master", &user_id).await?;
    assert_eq!(user.username, "testuser");
    
    // Update user
    let update = UpdateUserRequest {
        enabled: Some(false),
        ..Default::default()
    };
    
    client.update_user("master", &user_id, &update).await?;
    
    // Verify update
    let updated_user = client.get_user("master", &user_id).await?;
    assert!(!updated_user.enabled);
    
    // Clean up
    client.delete_user("master", &user_id).await?;
}

async fn wait_for_service_ready(base_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let health_url = format!("{}/health/ready", base_url);
    
    for attempt in 1..=30 {
        if let Ok(response) = client.get(&health_url).send().await {
            if response.status().is_success() {
                return Ok(());
            }
        }
        
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    }
    
    Err("Service did not become ready within timeout".into())
}
```

## 🔧 Workspace-Specific Development

### Cross-Crate Feature Management
```toml
# keycloak-domain/Cargo.toml
[features]
default = []
mcp = ["rmcp"]
testing = ["mockall", "proptest"] 
testcontainers = ["testcontainers", "testing"]
integration-tests = ["testcontainers", "tokio-test"]

# keycloak-management-api/Cargo.toml  
[features]
default = ["keycloak-domain/default"]
mcp = ["keycloak-domain/mcp", "rmcp"]
testing = ["keycloak-domain/testing"]
full-integration = ["keycloak-domain/testcontainers", "testing"]
```

### Build and Test Commands
```bash
# Test entire workspace with all features
cargo test --workspace --all-features

# Test specific crate with integration tests
cargo test -p keycloak-domain --features integration-tests

# Test with property-based testing
cargo test --workspace --features testing

# Run only fast tests (exclude integration)
cargo test --workspace --lib

# Build with specific feature combinations
cargo build --workspace --features "mcp,testing"

# Check all feature combinations (requires cargo-hack)
cargo hack check --feature-powerset --workspace

# Format code with nightly features
cargo +nightly fmt

# Run Clippy with all features
cargo clippy --workspace --all-targets --all-features -- -D warnings

# ALWAYS use ripgrep instead of grep for searching
rg "pattern" path/                    # Instead of grep -r "pattern" path/
rg -t rust "fn main"                  # Search only Rust files
rg -A 3 -B 3 "error"                 # Context lines around matches
rg --files-with-matches "TODO"       # Just file names with matches
```

### Dependency Coherence Across Crates
```toml
# Root Cargo.toml workspace dependencies
[workspace.dependencies]
# Ensure consistent versions across all crates
async-trait = "0.1.83"
tokio = { version = "1.40", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
thiserror = "1.0"
anyhow = "1.0"
uuid = { version = "1.0", features = ["v4", "serde"] }
chrono = { version = "0.4", features = ["serde"] }

# Testing dependencies
mockall = "0.12"
proptest = "1.4" 
testcontainers = "0.24"
tokio-test = "0.4"

# Feature-specific dependencies
rmcp = { path = "rust-sdk/crates/rmcp", optional = true }
```

## 🔍 Modern Rust Debugging and Diagnostics

### Structured Logging with Tracing
```rust
use tracing::{info, warn, error, instrument, Span};

impl UserService {
    #[instrument(
        skip(self, users),
        fields(
            realm = %realm,
            user_count = users.len(),
            created_count = tracing::field::Empty,
            failed_count = tracing::field::Empty
        )
    )]
    pub async fn bulk_create_users(
        &self, 
        realm: &str, 
        users: Vec<CreateUserRequest>
    ) -> Result<BulkCreateResult, DomainError> {
        let total_count = users.len();
        info!(total_count, "Starting bulk user creation");
        
        let mut created_users = Vec::new();
        let mut failures = Vec::new();
        
        // Use modern async iteration patterns
        let results = futures::stream::iter(users.into_iter().enumerate())
            .map(|(index, user_request)| async move {
                let span = tracing::info_span!("create_single_user", 
                    user_index = index, 
                    username = %user_request.username
                );
                
                async move {
                    self.create_user(realm, user_request).await
                        .map(|user_id| (index, user_id))
                        .map_err(|e| (index, e))
                }.instrument(span).await
            })
            .buffer_unordered(10) // Process up to 10 concurrently
            .collect::<Vec<_>>()
            .await;
        
        // Process results with modern pattern matching
        for result in results {
            match result {
                Ok((index, user_id)) => {
                    created_users.push(user_id);
                    info!(user_index = index, "User created successfully");
                }
                Err((index, error)) => {
                    failures.push((index, error));
                    warn!(user_index = index, error = %error, "User creation failed");
                }
            }
        }
        
        // Update tracing fields
        Span::current().record("created_count", created_users.len());
        Span::current().record("failed_count", failures.len());
        
        if failures.is_empty() {
            info!("All users created successfully");
        } else {
            warn!(
                created = created_users.len(), 
                failed = failures.len(), 
                "Bulk creation completed with some failures"
            );
        }
        
        Ok(BulkCreateResult {
            created_users,
            failures,
        })
    }
}
```

### Debug-Friendly Types with Custom Formatting
```rust
use std::fmt;

#[derive(Clone, PartialEq, Eq)]
pub struct User {
    pub id: UserId,
    pub email: Email,
    pub password_hash: Option<PasswordHash>,
    pub attributes: HashMap<String, Vec<String>>,
}

// Custom Debug implementation to avoid exposing sensitive data
impl fmt::Debug for User {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("User")
            .field("id", &self.id)
            .field("email", &format_args!("Email(***@{})", 
                self.email.domain().unwrap_or("unknown")))
            .field("password_hash", &self.password_hash.as_ref().map(|_| "***"))
            .field("attribute_count", &self.attributes.len())
            .finish()
    }
}

// Implement Display for user-friendly output
impl fmt::Display for User {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "User {} ({})", self.id, self.email.domain().unwrap_or("unknown"))
    }
}
```

## 🎯 Current Project Context

### Keycloak Domain Architecture Status
- **Domain Layer**: ✅ Complete with full type safety using modern Rust patterns
- **Repository Pattern**: ✅ Implemented with proper error handling and async/await
- **Services Layer**: ✅ All CRUD operations with comprehensive testing
- **Testing**: ✅ Unit tests passing, integration tests with TestContainers ready

### Build System (Rust Edition 2024)
```bash
# Quick development cycle
cargo check --workspace                    # Fast syntax check
cargo test --workspace --lib               # Unit tests only  
cargo test --workspace --all-features      # Full test suite
cargo build --workspace                    # Full build

# Feature-specific builds
cargo build --features "mcp,testing"
cargo test --features "testcontainers" -- --ignored

# Modern Rust tooling
cargo +nightly fmt                         # Latest formatting
cargo clippy --all-targets --all-features  # All lints
cargo doc --open                           # Generate and view docs
```

### Known Technical Debt
1. **Handler Compilation**: Method signatures need updates for Keycloak API changes
2. **MCP Tool Router**: Compilation errors in macro expansion  
3. **Modern Rust Migration**: Update to use latest if-let chaining and pattern matching

### Next Development Priorities
1. **Zero-regression policy**: All new code must compile and pass tests
2. **Idiomatic Rust**: Use edition 2024 features and modern patterns
3. **Comprehensive error handling**: Rich context in all error paths
4. **Documentation**: Every public API needs comprehensive docs and examples

## 🔧 Development Workflow Standards

### Search Tools
- **ALWAYS use ripgrep (`rg`) instead of `grep`** - It's faster, has better defaults, and respects .gitignore
- **Never use `find` + `grep` chains** - Use `rg` with appropriate flags instead
- **Search examples**:
  ```bash
  rg "TODO|FIXME|HACK" --type rust          # Find technical debt in Rust files
  rg -A 5 -B 5 "struct User"                # Context around struct definitions
  rg --files-with-matches "async fn"        # Files containing async functions
  rg -v "test" --type rust "fn "            # Non-test functions only
  ```

### Git Workflow Standards

#### Commit Message Format
```
<type>(<scope>): <description>

<body>

<footer>
```

**Types**: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

**Examples**:
- `feat(auth): add JWT token validation with proper error handling`
- `fix(user-service): handle edge case when user email domain is missing`  
- `refactor(domain): extract email validation into newtype with smart constructor`
- `test(integration): add TestContainers-based user lifecycle tests`

#### Pull Request Standards
1. **Title**: Use conventional commit format
2. **Description template**:
   ```markdown
   ## Summary
   - Concise bullet points describing changes
   - Focus on the "why" not just the "what"
   
   ## Type Safety Improvements
   - List any new types or validation added
   - Highlight prevented runtime errors
   
   ## Testing
   - [ ] Unit tests added/updated
   - [ ] Integration tests passing
   - [ ] Property-based tests where appropriate
   
   ## Breaking Changes
   - List any API breaking changes
   
   ## Performance Impact
   - Note any performance considerations
   ```

3. **Before creating PR**:
   ```bash
   # Run full validation suite
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets --all-features -- -D warnings
   cargo test --workspace --all-features
   cargo check --workspace --all-targets --all-features
   ```

#### Branch Naming Convention
- `feat/user-authentication-jwt` - New features
- `fix/email-validation-edge-case` - Bug fixes  
- `refactor/extract-domain-types` - Code restructuring
- `test/add-integration-coverage` - Test additions
- `docs/update-api-examples` - Documentation updates

### Code Review Standards
- **Focus on type safety**: Does this prevent runtime errors?
- **Check error handling**: Are all error paths handled with proper context?
- **Verify testing**: Are there tests for both happy path and error cases?
- **Assess idiomaticity**: Does this feel natural to experienced Rust developers?
- **Performance considerations**: Any unnecessary allocations or blocking calls?

---

**Remember**: Write Rust code that feels natural to experienced Rust developers. Use the type system to prevent bugs, embrace pattern matching, leverage the iterator ecosystem, and always handle errors explicitly. Modern Rust features like if-let chaining make code more readable - use them!

Always use `rg` for searching, follow conventional commits, and create thorough pull requests that explain both the technical changes and business value.