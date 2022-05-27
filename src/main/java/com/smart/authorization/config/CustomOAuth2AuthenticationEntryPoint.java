package com.smart.authorization.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

public class CustomOAuth2AuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException {
        HttpStatus status = HttpStatus.UNAUTHORIZED;
        Map<String, String> parameters = new LinkedHashMap<>();

        if (e instanceof OAuth2AuthenticationException) {
            OAuth2Error error = ((OAuth2AuthenticationException) e).getError();
            parameters.put("error", error.getErrorCode());
            if (StringUtils.hasText(error.getUri())) {
                parameters.put("error_uri", error.getUri());
            }
            if (error instanceof BearerTokenError) {
                BearerTokenError bearerTokenError = (BearerTokenError) error;
                if (StringUtils.hasText(bearerTokenError.getScope())) {
                    parameters.put("scope", bearerTokenError.getScope());
                }
                status = ((BearerTokenError) error).getHttpStatus();
            }
        } else {
            status = BAD_REQUEST;
            parameters.put("error", OAuth2ErrorCodes.INVALID_GRANT);
            parameters.put("error_description", "Incorrect username or password");
        }
        response.setContentType(APPLICATION_JSON_VALUE);
        response.setStatus(status.value());
        new ObjectMapper().writeValue(response.getOutputStream(), parameters);
    }
}