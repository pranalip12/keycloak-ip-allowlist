package com.example.keycloak;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class IpAllowlistAuthenticator implements Authenticator {

    private static final Path CONFIG_FILE =
        Path.of("/opt/keycloak/config/ip-allowlist.yml");

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        String clientIp = context.getConnection().getRemoteAddr();

        try (InputStream input = Files.newInputStream(CONFIG_FILE)) {
            Yaml yaml = new Yaml(
                    new SafeConstructor(new LoaderOptions())
            );

            Map<String, Object> config = yaml.load(input);

            if (config == null
                    || !(config.get("allowed-ips") instanceof List<?> ips)) {
                throw new IllegalArgumentException(
                        "Missing or invalid 'allowed-ips' configuration"
                );
            }

            Set<String> allowedIps = ips.stream()
                    .filter(String.class::isInstance)
                    .map(String.class::cast)
                    .map(String::trim)
                    .filter(ip -> !ip.isEmpty())
                    .collect(Collectors.toSet());

            System.out.println("[IP-ALLOWLIST] CLIENT IP = " + clientIp);

            if (allowedIps.contains(clientIp)) {
                System.out.println("[IP-ALLOWLIST] ALLOWED");
                context.success();
            } else {
                System.out.println("[IP-ALLOWLIST] DENIED");
                context.failure(AuthenticationFlowError.ACCESS_DENIED);
            }

        } catch (IOException | RuntimeException e) {
            System.err.println(
                    "[IP-ALLOWLIST] Cannot read or parse config: "
                            + e.getMessage()
            );

            context.failure(AuthenticationFlowError.INTERNAL_ERROR);
        }
    }
    @Override
    public void action(AuthenticationFlowContext context) {
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(
            KeycloakSession session,
            RealmModel realm,
            UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(
            KeycloakSession session,
            RealmModel realm,
            UserModel user) {
    }

    @Override
    public void close() {
    }
}
