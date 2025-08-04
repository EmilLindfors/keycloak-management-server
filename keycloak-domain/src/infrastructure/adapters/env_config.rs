use crate::application::ports::{
    AppConfig, AuthConfig, ConfigurationPort, HttpConfig, KeycloakConfig, LoggingConfig,
};
use crate::domain::errors::DomainResult;
use async_trait::async_trait;

/// Environment-based configuration adapter
pub struct EnvConfigurationAdapter {
    config: AppConfig,
}

impl EnvConfigurationAdapter {
    pub fn new() -> DomainResult<Self> {
        let config = AppConfig::from_env()?;
        Ok(Self { config })
    }
}

#[async_trait]
impl ConfigurationPort for EnvConfigurationAdapter {
    fn get_keycloak_config(&self) -> &KeycloakConfig {
        &self.config.keycloak
    }

    fn get_auth_config(&self) -> &AuthConfig {
        &self.config.auth
    }

    fn get_http_config(&self) -> &HttpConfig {
        &self.config.http
    }

    fn get_logging_config(&self) -> &LoggingConfig {
        &self.config.logging
    }

    fn validate(&self) -> DomainResult<()> {
        self.config.validate()
    }

    fn is_development(&self) -> bool {
        self.config.is_development()
    }

    fn is_test(&self) -> bool {
        self.config.is_test()
    }
}
