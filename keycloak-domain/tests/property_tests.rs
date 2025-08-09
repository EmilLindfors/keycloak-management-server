use proptest::prelude::*;
use proptest::option;
use keycloak_domain::{
    domain::{
        entities::{
            user::{User, CreateUserRequest},
            realm::Realm,
            client::Client,
            group::Group,
            role::Role,
            common::{EntityId, Attributes, Access},
        },
        errors::DomainError,
    },
};

/// Property-based tests for Keycloak domain entities
/// These tests verify that our domain invariants hold under all possible inputs

mod user_properties {
    use super::*;

    proptest! {
        /// Property: Valid usernames should always pass validation
        #[test]
        fn valid_usernames_always_validate(
            username in "[a-zA-Z0-9._-]{2,100}"
        ) {
            let result = User::validate_username(&username);
            prop_assert!(result.is_ok(), "Valid username should pass validation: {}", username);
        }

        /// Property: Empty usernames should always fail validation
        #[test]
        fn empty_usernames_always_fail(
            _dummy in any::<bool>()
        ) {
            let result = User::validate_username("");
            prop_assert!(result.is_err(), "Empty username should fail validation");
            
            if let Err(DomainError::InvalidUsername { reason }) = result {
                prop_assert!(reason.contains("empty"), "Error should mention empty username");
            } else {
                return Err(TestCaseError::fail("Expected InvalidUsername error"));
            }
        }

        /// Property: Valid email formats should pass validation
        #[test]
        fn valid_emails_validate(
            local in r"[a-zA-Z0-9._%+-]{1,64}",
            domain in r"[a-zA-Z0-9.-]{2,63}",
            tld in r"[a-zA-Z]{2,6}"
        ) {
            let email = format!("{}@{}.{}", local, domain, tld);
            let result = User::validate_email(&email);
            prop_assert!(result.is_ok(), "Valid email should pass validation: {}", email);
        }

        /// Property: Invalid email formats should fail validation
        #[test]
        fn invalid_emails_fail(
            invalid_email in r"[a-zA-Z0-9._%-]+[^@]*[a-zA-Z0-9._%-]+"
        ) {
            // Generate strings that don't contain @ or have invalid format
            if !invalid_email.contains('@') {
                let result = User::validate_email(&invalid_email);
                prop_assert!(result.is_err(), "Invalid email should fail validation: {}", invalid_email);
            }
        }

        /// Property: User creation request with valid username always validates
        #[test]
        fn create_user_request_validates_with_valid_data(
            username in "[a-zA-Z0-9._-]{2,100}",
            first_name in option::of("[a-zA-Z ]{1,100}"),
            last_name in option::of("[a-zA-Z ]{1,100}"),
            enabled in any::<Option<bool>>()
        ) {
            let request = CreateUserRequest {
                username,
                email: None, // Skip email validation for this test
                first_name,
                last_name,
                enabled,
                temporary_password: None,
                require_password_update: None,
                attributes: None,
            };
            
            let result = request.validate();
            prop_assert!(result.is_ok(), "Valid create request should validate");
        }

        /// Property: User creation with email includes proper email validation
        #[test]
        fn create_user_request_validates_email(
            username in "[a-zA-Z0-9._-]{2,100}",
            local in r"[a-zA-Z0-9._%+-]{1,64}",
            domain in r"[a-zA-Z0-9.-]{2,63}",
            tld in r"[a-zA-Z]{2,6}"
        ) {
            let email = format!("{}@{}.{}", local, domain, tld);
            let request = CreateUserRequest {
                username,
                email: Some(email.clone()),
                first_name: None,
                last_name: None,
                enabled: Some(true),
                temporary_password: None,
                require_password_update: None,
                attributes: None,
            };
            
            let result = request.validate();
            prop_assert!(result.is_ok(), "Valid create request with email should validate: {}", email);
        }

        /// Property: User display name generation is consistent
        #[test]
        fn user_display_name_consistency(
            username in "[a-zA-Z0-9._@-]{1,50}",
            first_name in option::of("[a-zA-Z ]{1,50}"),
            last_name in option::of("[a-zA-Z ]{1,50}")
        ) {
            let user = User {
                id: Some(EntityId::new()),
                username: username.clone(),
                email: None,
                first_name: first_name.clone(),
                last_name: last_name.clone(),
                enabled: true,
                email_verified: false,
                attributes: Attributes::new(),
                required_actions: vec![],
                access: Access::default(),
                federated_identities: vec![],
                timestamps: Default::default(),
            };

            let display_name = user.display_name();
            
            // Test invariants about display name
            match (&first_name, &last_name) {
                (Some(first), Some(last)) => {
                    prop_assert_eq!(display_name, format!("{} {}", first, last));
                },
                (Some(first), None) => {
                    prop_assert_eq!(display_name, first.clone());
                },
                (None, Some(last)) => {
                    prop_assert_eq!(display_name, last.clone());
                },
                (None, None) => {
                    prop_assert_eq!(display_name, username);
                }
            }
        }
    }
}

mod realm_properties {
    use super::*;

    proptest! {
        /// Property: Valid realm names should pass validation
        #[test]
        fn valid_realm_names_validate(
            realm_name in "[a-zA-Z0-9_-]{2,36}"
        ) {
            // Skip reserved names for this test
            if realm_name != "master" && realm_name != "admin" {
                let result = Realm::validate_realm_name(&realm_name);
                prop_assert!(result.is_ok(), "Valid realm name should validate: {}", realm_name);
            }
        }

        /// Property: Empty realm names always fail validation
        #[test]
        fn empty_realm_names_fail(
            _dummy in any::<bool>()
        ) {
            let result = Realm::validate_realm_name("");
            prop_assert!(result.is_err(), "Empty realm name should fail validation");
        }

        /// Property: Reserved realm names should fail validation
        #[test]
        fn reserved_realm_names_fail(
            reserved_name in prop::sample::select(vec!["master".to_string(), "admin".to_string()])
        ) {
            let result = Realm::validate_realm_name(&reserved_name);
            prop_assert!(result.is_err(), "Reserved realm name should fail validation: {}", reserved_name);
        }

        /// Property: Realm creation should maintain invariants
        #[test]
        fn realm_creation_maintains_invariants(
            realm_name in "[a-zA-Z0-9._-]{1,100}"
        ) {
            // Skip reserved names
            if realm_name != "master" && realm_name != "admin" {
                if let Ok(realm) = Realm::new(realm_name.clone()) {
                    prop_assert_eq!(realm.realm, realm_name);
                    prop_assert!(realm.enabled, "Realm should be enabled by default");
                    // Realm doesn't have a validate method, creation validates automatically
                }
            }
        }
    }
}

mod client_properties {
    use super::*;

    proptest! {
        /// Property: Valid client IDs should pass validation
        #[test]
        fn valid_client_ids_validate(
            client_id in "[a-zA-Z0-9._@-]{2,255}"
        ) {
            let result = Client::validate_client_id(&client_id);
            prop_assert!(result.is_ok(), "Valid client ID should validate: {}", client_id);
        }

        /// Property: Empty client IDs should fail validation
        #[test]
        fn empty_client_ids_fail(
            _dummy in any::<bool>()
        ) {
            let result = Client::validate_client_id("");
            prop_assert!(result.is_err(), "Empty client ID should fail validation");
        }

        /// Property: Valid redirect URIs should pass validation
        #[test]
        fn valid_redirect_uris_validate(
            scheme in prop::sample::select(vec!["http".to_string(), "https".to_string()]),
            host in "[a-zA-Z0-9.-]{1,253}",
            path in option::of("/[a-zA-Z0-9._/%-]*")
        ) {
            let uri = match path {
                Some(p) => format!("{}://{}{}", scheme, host, p),
                None => format!("{}://{}", scheme, host),
            };
            
            let result = Client::validate_redirect_uri(&uri);
            prop_assert!(result.is_ok(), "Valid redirect URI should validate: {}", uri);
        }

        /// Property: Client creation maintains invariants
        #[test]
        fn client_creation_maintains_invariants(
            client_id in "[a-zA-Z0-9._@-]{1,100}"
        ) {
            if let Ok(client) = Client::new(client_id.clone()) {
                prop_assert_eq!(client.client_id, client_id);
                prop_assert!(client.enabled, "Client should be enabled by default");
                prop_assert!(!client.public_client, "Client should not be public by default");
            }
        }
    }
}

mod group_properties {
    use super::*;

    proptest! {
        /// Property: Valid group names should pass validation
        #[test]
        fn valid_group_names_validate(
            group_name in "[a-zA-Z0-9._@-]{2,255}"
        ) {
            let result = Group::validate_group_name(&group_name);
            prop_assert!(result.is_ok(), "Valid group name should validate: {}", group_name);
        }

        /// Property: Empty group names should fail validation
        #[test]
        fn empty_group_names_fail(
            _dummy in any::<bool>()
        ) {
            let result = Group::validate_group_name("");
            prop_assert!(result.is_err(), "Empty group name should fail validation");
        }

        /// Property: Valid group paths should pass validation
        #[test]
        fn valid_group_paths_validate(
            path_components in prop::collection::vec("[a-zA-Z0-9._-]{1,50}", 1..=5)
        ) {
            let path = format!("/{}", path_components.join("/"));
            let result = Group::validate_group_path(&path);
            prop_assert!(result.is_ok(), "Valid group path should validate: {}", path);
        }

        /// Property: Group creation maintains invariants
        #[test]
        fn group_creation_maintains_invariants(
            group_name in "[a-zA-Z0-9._@/-]{1,100}"
        ) {
            if let Ok(group) = Group::new(group_name.clone(), None) {
                prop_assert_eq!(group.name, group_name.clone());
                prop_assert_eq!(group.path, format!("/{}", group_name));
            }
        }
    }
}

mod role_properties {
    use super::*;

    proptest! {
        /// Property: Valid role names should pass validation
        #[test]
        fn valid_role_names_validate(
            role_name in "[a-zA-Z0-9._:-]{2,255}"
        ) {
            let result = Role::validate_role_name(&role_name);
            prop_assert!(result.is_ok(), "Valid role name should validate: {}", role_name);
        }

        /// Property: Empty role names should fail validation
        #[test]
        fn empty_role_names_fail(
            _dummy in any::<bool>()
        ) {
            let result = Role::validate_role_name("");
            prop_assert!(result.is_err(), "Empty role name should fail validation");
        }

        /// Property: Role creation maintains invariants
        #[test]
        fn role_creation_maintains_invariants(
            role_name in "[a-zA-Z0-9._@-]{1,100}"
        ) {
            if let Ok(role) = Role::new_realm_role(role_name.clone(), "test-realm".to_string()) {
                prop_assert_eq!(role.name, role_name);
                prop_assert_eq!(role.container_id, "test-realm");
            }
        }
    }
}

mod entity_id_properties {
    use super::*;

    proptest! {
        /// Property: EntityId creation and conversion is consistent
        #[test]
        fn entity_id_roundtrip_consistency(
            id_string in "[a-zA-Z0-9-]{1,255}"
        ) {
            let entity_id = EntityId::from(id_string.clone());
            prop_assert_eq!(entity_id.as_str(), &id_string);
            prop_assert_eq!(entity_id.to_string(), id_string);
        }

        /// Property: EntityId new() generates valid UUIDs
        #[test]
        fn entity_id_new_generates_valid_uuids(
            _dummy in any::<bool>()
        ) {
            let entity_id = EntityId::new();
            let id_str = entity_id.as_str();
            
            // Should be a valid UUID format
            prop_assert!(id_str.len() == 36, "UUID should be 36 characters");
            prop_assert!(id_str.chars().filter(|c| *c == '-').count() == 4, "UUID should have 4 dashes");
            
            // Should parse as valid UUID
            let uuid_result = uuid::Uuid::parse_str(id_str);
            prop_assert!(uuid_result.is_ok(), "Should be valid UUID: {}", id_str);
        }

        /// Property: Two EntityId::new() calls generate different IDs
        #[test]
        fn entity_id_new_generates_unique_ids(
            _dummy in any::<bool>()
        ) {
            let id1 = EntityId::new();
            let id2 = EntityId::new();
            prop_assert!(id1 != id2, "Different EntityId::new() calls should generate different IDs");
        }
    }
}

mod validation_properties {
    use super::*;

    proptest! {
        /// Property: Validation errors contain meaningful messages
        #[test]
        fn validation_errors_are_meaningful(
            field_name in "[a-zA-Z_]{1,50}",
            error_message in "[a-zA-Z ]{1,200}"
        ) {
            let error = DomainError::Validation {
                field: field_name.clone(),
                message: error_message.clone(),
            };
            
            let error_string = error.to_string();
            prop_assert!(error_string.contains(&field_name), "Error should contain field name");
            prop_assert!(error_string.contains(&error_message), "Error should contain error message");
        }

        /// Property: Username validation is consistent across all contexts
        #[test]
        fn username_validation_consistency(
            username in any::<String>()
        ) {
            let direct_validation = User::validate_username(&username);
            
            let user_request = CreateUserRequest {
                username: username.clone(),
                email: None,
                first_name: None,
                last_name: None,
                enabled: Some(true),
                temporary_password: None,
                require_password_update: None,
                attributes: None,
            };
            let request_validation = user_request.validate();
            
            // Both validations should have the same success/failure outcome
            prop_assert_eq!(
                direct_validation.is_ok(),
                request_validation.is_ok(),
                "Username validation should be consistent: direct={:?}, request={:?}, username='{}'",
                direct_validation,
                request_validation,
                username
            );
        }
    }
}

mod integration_properties {
    use super::*;

    proptest! {
        /// Property: Valid entity combinations maintain overall system invariants
        #[test]
        fn valid_entity_combinations_maintain_invariants(
            realm_name in "[a-zA-Z0-9._-]{1,50}",
            username in "[a-zA-Z0-9._@-]{1,50}",
            client_id in "[a-zA-Z0-9._@-]{1,50}",
            group_name in "[a-zA-Z0-9._@-]{1,50}",
            role_name in "[a-zA-Z0-9._@-]{1,50}"
        ) {
            // Skip reserved names
            if realm_name != "master" && realm_name != "admin" {
                // Create all entities
                let realm_result = Realm::new(realm_name.clone());
                let user = User::new(username.clone());
                let client = Client::new(client_id.clone());
                let group = Group::new(group_name.clone(), None);
                let role = Role::new_realm_role(role_name.clone(), realm_name.clone());
                
                if let (Ok(realm), Ok(user), Ok(client), Ok(group), Ok(role)) = 
                    (&realm_result, &user, &client, &group, &role) {
                    
                    // Entity names should match input
                    prop_assert_eq!(&realm.realm, &realm_name);
                    prop_assert_eq!(&user.username, &username);
                    prop_assert_eq!(&client.client_id, &client_id);
                    prop_assert_eq!(&group.name, &group_name);
                    prop_assert_eq!(&role.name, &role_name);
                }
            }
        }

        /// Property: Serialization/deserialization preserves entity integrity
        #[test]
        fn serialization_preserves_integrity(
            username in "[a-zA-Z0-9._@-]{1,50}",
            email in option::of(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}"),
            enabled in any::<bool>()
        ) {
            let original_user = User {
                id: Some(EntityId::new()),
                username: username.clone(),
                email: email.clone(),
                first_name: Some("Test".to_string()),
                last_name: Some("User".to_string()),
                enabled,
                email_verified: false,
                attributes: Attributes::new(),
                required_actions: vec![],
                access: Access::default(),
                federated_identities: vec![],
                timestamps: Default::default(),
            };
            
            // Serialize to JSON
            let json = serde_json::to_string(&original_user);
            prop_assert!(json.is_ok(), "User should serialize to JSON");
            
            if let Ok(json_str) = json {
                // Deserialize back
                let deserialized: Result<User, _> = serde_json::from_str(&json_str);
                prop_assert!(deserialized.is_ok(), "User should deserialize from JSON");
                
                if let Ok(deserialized_user) = deserialized {
                    // Core properties should be preserved
                    prop_assert_eq!(deserialized_user.username, original_user.username);
                    prop_assert_eq!(deserialized_user.email, original_user.email);
                    prop_assert_eq!(deserialized_user.enabled, original_user.enabled);
                    prop_assert_eq!(deserialized_user.first_name, original_user.first_name);
                    prop_assert_eq!(deserialized_user.last_name, original_user.last_name);
                    
                    // User entities don't have validate methods - validation happens during creation/modification
                }
            }
        }
    }
}