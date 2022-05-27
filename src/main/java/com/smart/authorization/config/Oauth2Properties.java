package com.smart.authorization.config;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Oauth2Properties {
    private String clientId;
    private String clientSecret;
    private String issuerUri;
    private String redirectUri;
    private String accessTokenExpired;
    private String refreshTokenExpired;
    private String jwksUri;
}
