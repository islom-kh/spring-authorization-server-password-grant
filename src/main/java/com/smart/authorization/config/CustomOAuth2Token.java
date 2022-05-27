//package com.smart.authorization.config;
//
//import com.smart.authorization.domain.User;
//import com.smart.authorization.dto.LoggedUser;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.GrantedAuthority;
//import org.springframework.security.oauth2.jwt.JwtClaimsSet;
//import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
//import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
//import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
//import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
//
//import java.util.LinkedHashMap;
//import java.util.Map;
//import java.util.Set;
//import java.util.stream.Collectors;
//
//@Slf4j
//public class CustomOAuth2Token implements OAuth2TokenCustomizer<JwtEncodingContext> {
//
//    @Override
//    public void customize(JwtEncodingContext context) {
//        JwtClaimsSet.Builder claims = context.getClaims();
//        OAuth2Authorization authorization = context.get(OAuth2Authorization.class);
//        RegisteredClient registeredClient = context.get(RegisteredClient.class);
//
//        claims.claim("client_id", registeredClient.getClientId());
//        Authentication principal = context.getPrincipal();
//
//        if (principal.getPrincipal() instanceof LoggedUser) {
//            LoggedUser loggedUser = (LoggedUser) principal.getPrincipal();
//            claims.claim("user_name", loggedUser.getUsername());
//            Map<String, Object> data = new LinkedHashMap<>();
//            User user = loggedUser.getUser();
//            Map<String, Object> info = new LinkedHashMap<>();
//            info.put("id", user.getId());
//            info.put("email", user.getEmail());
//            info.put("timezone", user.getTimezone());
//            data.put("user", info);
//            claims.claim("context", data);
//            Set<String> authorities = loggedUser.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet());
//            claims.claim("authorities", authorities);
//        }
//    }
//}
