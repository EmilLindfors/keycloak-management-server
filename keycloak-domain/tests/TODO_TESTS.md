# TODO: Comprehensive Domain Layer Testing with Mocks

## 🎯 Overview

This document outlines the roadmap for creating comprehensive mock-based tests for the keycloak-domain crate using hexagonal architecture principles. Since we have proper separation between domain logic and infrastructure, mocking the ports should provide excellent test coverage without external dependencies.

## 📋 Current Status

### ✅ Completed
- [x] **Basic integration tests** - 8/8 passing with mock data
- [x] **TestContainers infrastructure** - Ready for Docker environments
- [x] **Domain entities** - All entities have proper validation and business logic
- [x] **Repository pattern** - Clean abstraction over Keycloak API
- [x] **Service layer** - Complete business logic implementation

### 🚧 In Progress
- [x] **Mock infrastructure started** - `tests/mocks/mod.rs` partially implemented
- [x] **Test structure defined** - `tests/domain_service_tests.rs` with test framework
- [ ] **API compatibility fixes** - Need to align mocks with actual domain interfaces

### ❌ TODO
- [ ] **Complete mock implementations**
- [ ] **Comprehensive service tests** 
- [ ] **Error scenario testing**
- [ ] **Performance testing**
- [ ] **Integration test suite**

## 🔧 Phase 1: Fix Mock Infrastructure

### Step 1.1: Analyze Current Domain APIs
**Priority: High**

Before fixing mocks, need to understand the actual interfaces:

```bash
# Examine the actual repository trait
rg "trait KeycloakRepository" -A 50 src/application/ports/repository.rs

# Check service constructors and methods
rg "impl.*Service" -A 10 src/application/services/

# Understand error types
rg "enum DomainError" -A 20 src/domain/errors.rs

# Check entity structures
rg "pub struct.*\{" -A 5 src/domain/entities/
```

### Step 1.2: Fix Mock Repository Implementation
**File: `tests/mocks/repository_mock.rs`**

**Issues to Fix:**
- ✅ Import `AuthorizationContext` from correct location
- ✅ Use actual `DomainError` variants (not guessed ones)
- ✅ Implement only methods that exist in `KeycloakRepository` trait
- ✅ Use correct parameter types (`&str` vs `&EntityId`)
- ✅ Fix return types to match actual service expectations

**Action Items:**
```rust
// 1. Fix imports
use keycloak_domain::AuthorizationContext; // Not from domain::entities::common

// 2. Match exact DomainError variants
DomainError::UserNotFound { user_id, realm } // Not EntityNotFound
DomainError::ExternalService { service, message } // Not ExternalServiceError

// 3. Implement only actual trait methods
// Remove: assign_realm_role_to_user, remove_realm_role_from_user, etc.
// Keep only methods defined in repository.rs
```

### Step 1.3: Fix Service Mock Dependencies
**Files: `tests/mocks/event_publisher_mock.rs`, `tests/mocks/auth_service_mock.rs`**

**Issues to Fix:**
- ✅ Check if `DomainEvent` exists or if we need different event types
- ✅ Verify `EventPublisher` and `AuthorizationService` trait signatures
- ✅ Use actual `Permission` types if they exist

**Action Items:**
```bash
# Check what event types actually exist
rg "struct.*Event" src/domain/
rg "enum.*Event" src/domain/

# Verify service traits
rg "trait EventPublisher" -A 10 src/application/ports/
rg "trait AuthorizationService" -A 10 src/application/ports/
```

## 🧪 Phase 2: Service Layer Testing

### Step 2.1: UserManagementService Tests
**File: `tests/user_service_tests.rs`**

**Test Categories:**
```rust
mod user_service_tests {
    // ✅ Happy path tests
    test_create_user_success()
    test_get_user_success() 
    test_list_users_with_filters()
    test_update_user_success()
    test_delete_user_success()
    
    // ✅ Authorization tests
    test_create_user_insufficient_permissions()
    test_update_user_wrong_realm_permissions()
    test_delete_user_unauthorized()
    
    // ✅ Validation tests
    test_create_user_invalid_username()
    test_create_user_invalid_email()
    test_update_user_invalid_data()
    
    // ✅ Error handling tests
    test_create_user_repository_failure()
    test_get_user_not_found()
    test_event_publishing_failure()
    
    // ✅ Edge cases
    test_create_duplicate_user()
    test_list_users_empty_result()
    test_update_nonexistent_user()
}
```

**Key Testing Patterns:**
```rust
// 1. Arrange - Set up mocks with expected behavior
let repository = Arc::new(MockKeycloakRepository::new());
let auth_service = Arc::new(MockAuthorizationService::new());
auth_service.allow_permission("users:create");

// 2. Act - Call service method
let result = user_service.create_user(realm, &request, &context).await;

// 3. Assert - Verify results and mock interactions
assert!(result.is_ok());
assert_eq!(repository.get_call_count("create_user"), 1);
assert_eq!(auth_service.get_checked_permissions(), vec!["users:create"]);
```

### Step 2.2: RealmManagementService Tests
**File: `tests/realm_service_tests.rs`**

**Test Categories:**
```rust
mod realm_service_tests {
    // ✅ CRUD operations
    test_create_realm_success()
    test_get_realm_success()
    test_list_realms()
    test_update_realm_success()
    test_delete_realm_success()
    
    // ✅ Business logic
    test_create_realm_with_default_settings()
    test_realm_name_validation()
    test_realm_settings_validation()
    
    // ✅ Error scenarios
    test_create_duplicate_realm()
    test_get_nonexistent_realm()
    test_delete_master_realm_forbidden()
}
```

### Step 2.3: ClientManagementService Tests
**File: `tests/client_service_tests.rs`**

**Test Categories:**
```rust
mod client_service_tests {
    // ✅ Client lifecycle
    test_create_client_success()
    test_get_client_by_id()
    test_get_client_by_client_id()
    test_update_client_settings()
    test_delete_client()
    
    // ✅ Client secrets
    test_get_client_secret()
    test_regenerate_client_secret()
    
    // ✅ Client validation
    test_create_client_invalid_redirect_uri()
    test_client_id_uniqueness()
    test_client_protocol_validation()
}
```

## 🚨 Phase 3: Error Scenario Testing

### Step 3.1: Comprehensive Error Coverage
**File: `tests/error_scenario_tests.rs`**

**Test Categories:**
```rust
mod error_scenarios {
    // ✅ Repository failures
    test_repository_connection_failure()
    test_repository_timeout()
    test_repository_authentication_failure()
    
    // ✅ Authorization failures
    test_insufficient_permissions()
    test_expired_token()
    test_wrong_realm_access()
    
    // ✅ Validation failures
    test_malformed_input_data()
    test_constraint_violations()
    test_business_rule_violations()
    
    // ✅ External service failures
    test_event_publisher_unavailable()
    test_audit_service_failure()
    test_downstream_service_errors()
}
```

### Step 3.2: Error Recovery Testing
```rust
mod error_recovery {
    // ✅ Retry mechanisms
    test_transient_failure_retry()
    test_circuit_breaker_behavior()
    test_graceful_degradation()
    
    // ✅ Compensation actions
    test_rollback_on_partial_failure()
    test_cleanup_on_error()
    test_audit_trail_on_failure()
}
```

## 📊 Phase 4: Advanced Testing

### Step 4.1: Performance Testing
**File: `tests/performance_tests.rs`**

```rust
mod performance_tests {
    // ✅ Load testing
    test_concurrent_user_creation()
    test_bulk_operations_performance()
    test_large_result_set_handling()
    
    // ✅ Memory usage
    test_memory_usage_under_load()
    test_connection_pool_efficiency()
    test_garbage_collection_impact()
}
```

### Step 4.2: Integration Test Suite
**File: `tests/integration_test_suite.rs`**

```rust
mod integration_tests {
    // ✅ End-to-end workflows
    test_complete_user_lifecycle()
    test_realm_setup_and_configuration()
    test_client_registration_flow()
    
    // ✅ Cross-service interactions
    test_user_group_role_assignment()
    test_client_service_account_setup()
    test_realm_import_export()
}
```

## 🛠️ Implementation Strategy

### Quick Wins (Week 1)
1. **Fix mock compilation errors**
   - Update imports and error types
   - Match actual service method signatures
   - Remove non-existent methods from mocks

2. **Create basic happy path tests**
   - One test per service for create/read operations
   - Simple assertions to verify functionality
   - Basic mock verification

3. **Add authorization tests**
   - Test permission checking works
   - Verify unauthorized access is blocked
   - Check context propagation

### Medium Term (Week 2-3)
4. **Comprehensive service testing**
   - Full CRUD operations for all services
   - All error scenarios covered
   - Edge case handling verified

5. **Advanced mock features**
   - Call counting and verification
   - State mutation tracking
   - Realistic failure simulation

6. **Performance benchmarking**
   - Baseline performance metrics
   - Concurrent access testing
   - Memory usage profiling

### Long Term (Month 2)
7. **Property-based testing**
   - Generate random valid inputs
   - Verify invariants hold
   - Stress test edge cases

8. **Mutation testing**
   - Verify test quality
   - Find untested code paths
   - Improve test coverage

## 📈 Success Metrics

### Code Coverage
- **Target: 90%+ line coverage**
- **Focus areas**: Service layer business logic
- **Tools**: `cargo tarpaulin` or similar

### Test Performance
- **Target: All tests run in <30 seconds**
- **Parallel execution**: Tests should be independent
- **Resource usage**: Minimal memory footprint

### Test Quality
- **Maintainability**: Easy to update when code changes
- **Clarity**: Tests document expected behavior
- **Reliability**: No flaky tests, deterministic results

## 🔧 Tools and Setup

### Required Dependencies
```toml
[dev-dependencies]
tokio-test = "0.4"
proptest = "1.0"  # For property-based testing
criterion = "0.5"  # For benchmarking
```

### Test Organization
```
tests/
├── mocks/
│   ├── mod.rs
│   ├── repository_mock.rs
│   ├── event_publisher_mock.rs
│   └── auth_service_mock.rs
├── services/
│   ├── user_service_tests.rs
│   ├── realm_service_tests.rs
│   └── client_service_tests.rs
├── integration/
│   ├── error_scenarios.rs
│   ├── performance_tests.rs
│   └── end_to_end_tests.rs
└── TODO_TESTS.md  # This file
```

### Running Tests
```bash
# Run all tests
cargo test

# Run specific test module
cargo test user_service_tests

# Run with coverage
cargo tarpaulin --all-features

# Run performance tests
cargo test --release performance_tests

# Run in parallel
cargo test -- --test-threads=4
```

## 🎯 Next Actions

### Immediate (High Priority)
1. **Fix compilation errors** in `tests/mocks/mod.rs`
   - Check actual trait definitions
   - Update error types and imports
   - Remove non-existent methods

2. **Create one working test** for UserManagementService
   - Start with `test_create_user_success`
   - Verify mock interactions work
   - Establish testing patterns

3. **Document patterns** for future tests  
   - Standard test structure
   - Mock setup procedures
   - Assertion strategies

### Next Steps (Medium Priority)
4. **Expand test coverage** to all services
5. **Add error scenario testing**
6. **Implement performance tests**
7. **Create integration test suite**

---

**Key Insight**: With proper hexagonal architecture, comprehensive testing through mocks is not only possible but preferred. It provides faster, more reliable, and more focused testing than external integration tests while still providing high confidence in the domain logic.

**Success Criteria**: When complete, we should be able to run `cargo test` and have high confidence that all domain business logic works correctly, without needing any external services like Docker or real Keycloak instances.