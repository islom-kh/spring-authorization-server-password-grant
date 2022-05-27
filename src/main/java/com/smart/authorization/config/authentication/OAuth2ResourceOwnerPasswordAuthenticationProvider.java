package com.smart.authorization.config.authentication;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.ProviderContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.security.Principal;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class OAuth2ResourceOwnerPasswordAuthenticationProvider implements AuthenticationProvider {

    private static final Logger LOGGER = LogManager.getLogger(OAuth2ResourceOwnerPasswordAuthenticationProvider.class);

    private final AuthenticationManager authenticationManager;
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

    /**
     * Constructs an {@code OAuth2ClientCredentialsAuthenticationProvider} using the provided parameters.
     *
     * @param authorizationService the authorization service
     * @param tokenGenerator
     */
    public OAuth2ResourceOwnerPasswordAuthenticationProvider(AuthenticationManager authenticationManager, OAuth2AuthorizationService authorizationService,
                                                             OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) {
        this.tokenGenerator = tokenGenerator;
        Assert.notNull(authorizationService, "authorizationService cannot be null");
        this.authenticationManager = authenticationManager;
        this.authorizationService = authorizationService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        OAuth2ResourceOwnerPasswordAuthenticationToken resourceOwnerPasswordAuthentication = (OAuth2ResourceOwnerPasswordAuthenticationToken) authentication;

        OAuth2ClientAuthenticationToken clientPrincipal = getAuthenticatedClientElseThrowInvalidClient(resourceOwnerPasswordAuthentication);

        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

        if (!registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.PASSWORD)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }
        Map<String, Object> additionalParameters = resourceOwnerPasswordAuthentication.getAdditionalParameters();
        String username = (String) additionalParameters.get(OAuth2ParameterNames.USERNAME);
        String password = (String) additionalParameters.get(OAuth2ParameterNames.PASSWORD);

        try {
            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(username, password);
            LOGGER.debug("got usernamePasswordAuthenticationToken=" + usernamePasswordAuthenticationToken);

            Authentication usernamePasswordAuthentication = authenticationManager.authenticate(usernamePasswordAuthenticationToken);
            Set<String> authorizedScopes = registeredClient.getScopes();        // Default to configured scopes

            if (!CollectionUtils.isEmpty(resourceOwnerPasswordAuthentication.getScopes())) {
                Set<String> unauthorizedScopes = resourceOwnerPasswordAuthentication.getScopes().stream()
                        .filter(requestedScope -> !registeredClient.getScopes().contains(requestedScope))
                        .collect(Collectors.toSet());
                if (!CollectionUtils.isEmpty(unauthorizedScopes)) {
                    throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
                }

                authorizedScopes = new LinkedHashSet<>(resourceOwnerPasswordAuthentication.getScopes());
            }

            OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                    .principalName(usernamePasswordAuthentication.getName())
                    .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                    .attribute(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME, authorizedScopes)
                    .attribute(Principal.class.getName(), usernamePasswordAuthentication);

            DefaultOAuth2TokenContext.Builder tokenContextBuilder = (DefaultOAuth2TokenContext.Builder) ((DefaultOAuth2TokenContext.Builder)
                    ((DefaultOAuth2TokenContext.Builder) ((DefaultOAuth2TokenContext.Builder) ((DefaultOAuth2TokenContext.Builder)
                            ((DefaultOAuth2TokenContext.Builder) ((DefaultOAuth2TokenContext.Builder) DefaultOAuth2TokenContext.builder()
                                    .registeredClient(registeredClient)).principal((Authentication) usernamePasswordAuthentication)) //authorization.getAttribute(Principal.class.getName())
                                    .providerContext(ProviderContextHolder.getProviderContext())))   //.authorization((OAuth2Authorization) usernamePasswordAuthentication)
                            .authorizedScopes(authorizedScopes))
                            .authorizationGrantType(AuthorizationGrantType.PASSWORD)).authorizationGrant(resourceOwnerPasswordAuthentication);

            OAuth2TokenContext tokenContext = ((DefaultOAuth2TokenContext.Builder) tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN)).build();
            OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);


            if (generatedAccessToken == null) {
                OAuth2Error error = new OAuth2Error("server_error", "The token generator failed to generate the access token.", "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2");
                throw new OAuth2AuthenticationException(error);
            } else {
                OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, generatedAccessToken.getTokenValue(), generatedAccessToken.getIssuedAt(), generatedAccessToken.getExpiresAt(), tokenContext.getAuthorizedScopes());
                if (generatedAccessToken instanceof ClaimAccessor) {
                    authorizationBuilder.token(accessToken, (metadata) -> {
                        metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, ((ClaimAccessor) generatedAccessToken).getClaims());
                    });
                } else {
                    authorizationBuilder.accessToken(accessToken);
                }

                OAuth2RefreshToken refreshToken = null;
                if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN) && !clientPrincipal.getClientAuthenticationMethod().equals(ClientAuthenticationMethod.NONE)) {
                    tokenContext = ((DefaultOAuth2TokenContext.Builder) tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN)).build();
                    OAuth2Token generatedRefreshToken = this.tokenGenerator.generate(tokenContext);
                    if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
                        OAuth2Error error = new OAuth2Error("server_error", "The token generator failed to generate the refresh token.", "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2");
                        throw new OAuth2AuthenticationException(error);
                    }

                    refreshToken = (OAuth2RefreshToken) generatedRefreshToken;
                    authorizationBuilder.refreshToken(refreshToken);
                }


                OAuth2Authorization authorization = authorizationBuilder.build();
                this.authorizationService.save(authorization);
                Map<String, Object> tokenAdditionalParameters = new HashMap<>();
                return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken, refreshToken, tokenAdditionalParameters);
            }
        } catch (Exception ex) {
            OAuth2EndpointUtils.throwErrorWithMessage(
                    OAuth2ErrorCodes.INVALID_GRANT,
                    "Incorrect username or password",
                    OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
        }
        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        boolean supports = OAuth2ResourceOwnerPasswordAuthenticationToken.class.isAssignableFrom(authentication);
        LOGGER.debug("supports authentication=" + authentication + " returning " + supports);
        return supports;
    }

    private OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(Authentication authentication) {

        OAuth2ClientAuthenticationToken clientPrincipal = null;

        if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
            clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
        }

        if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
            return clientPrincipal;
        }

        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
    }

}
