//package com.smart.authorization.domain;
//
//import lombok.AllArgsConstructor;
//import lombok.Data;
//import lombok.NoArgsConstructor;
//
//import javax.persistence.Column;
//import javax.persistence.Entity;
//import javax.persistence.Id;
//import javax.persistence.Table;
//import java.time.Instant;
//
//@Data
//@NoArgsConstructor
//@AllArgsConstructor
//@Entity
//@Table(name = "oauth2_authorization")
//public class OAuth2Authorization {
//    @Id
//    private String id;
//    private String registeredClientId;
//    private String principalName;
//    private String authorizationGrantType;
//    @Column(length = 4000)
//    private String attributes;
//    @Column(length = 500)
//    private String state;
//
//    @Column(length = 4000)
//    private String authorizationCodeValue;
//    private Instant authorizationCodeIssuedAt;
//    private Instant authorizationCodeExpiresAt;
//    private String authorizationCodeMetadata;
//
//    @Column(length = 4000)
//    private String accessTokenValue;
//    private Instant accessTokenIssuedAt;
//    private Instant accessTokenExpiresAt;
//    @Column(length = 2000)
//    private String accessTokenMetadata;
//    private String accessTokenType;
//    @Column(length = 1000)
//    private String accessTokenScopes;
//
//    @Column(length = 4000)
//    private String refreshTokenValue;
//    private Instant refreshTokenIssuedAt;
//    private Instant refreshTokenExpiresAt;
//    @Column(length = 2000)
//    private String refreshTokenMetadata;
//
//    @Column(length = 4000)
//    private String oidcIdTokenValue;
//    private Instant oidcIdTokenIssuedAt;
//    private Instant oidcIdTokenExpiresAt;
//    @Column(length = 2000)
//    private String oidcIdTokenMetadata;
//    @Column(length = 2000)
//    private String oidcIdTokenClaims;
//
//}
