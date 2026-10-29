package com.example.keycloak;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

public class IpAllowlistAuthenticatorFactory
        implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "ip-allowlist";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "IP Allowlist";
    }

    @Override
    public String getHelpText() {
        return "Allows authentication only from a configured IP address.";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new IpAllowlistAuthenticator();
    }

    @Override
    public AuthenticationExecutionModel.Requirement[]
            getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[] {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
        };
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of();
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }
}
