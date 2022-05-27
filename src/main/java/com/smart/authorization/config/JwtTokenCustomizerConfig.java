package com.smart.authorization.config;

import com.smart.authorization.domain.User;
import com.smart.authorization.dto.LoggedUser;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Configuration
public class JwtTokenCustomizerConfig {

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return (context) -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                JwtClaimsSet.Builder claims = context.getClaims();
                OAuth2Authorization authorization = context.get(OAuth2Authorization.class);
                RegisteredClient registeredClient = context.get(RegisteredClient.class);

                claims.claim("client_id", registeredClient.getClientId());
                Authentication principal = context.getPrincipal();

                if (principal.getPrincipal() instanceof LoggedUser) {
                    LoggedUser loggedUser = (LoggedUser) principal.getPrincipal();
                    claims.claim("user_name", loggedUser.getUsername());
                    Map<String, Object> data = new LinkedHashMap<>();
                    User user = loggedUser.getUser();
                    Map<String, Object> info = new LinkedHashMap<>();
                    info.put("id", user.getId());
                    info.put("email", user.getEmail());
                    info.put("timezone", user.getTimezone());
                    data.put("user", info);
                    claims.claim("context", data);
                    Set<String> authorities = loggedUser.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet());
                    claims.claim("authorities", authorities);
                }
            }
        };
    }
}
