//package com.smart.authorization.repository;
//
//import com.smart.authorization.domain.OAuth2Authorization;
//import com.smart.authorization.domain.OAuth2Client;
//import org.springframework.data.jpa.repository.JpaRepository;
//import org.springframework.data.jpa.repository.Query;
//import org.springframework.data.repository.query.Param;
//import org.springframework.stereotype.Repository;
//
//import java.util.Optional;
//
//@Repository
//public interface OAuth2AuthorizationRepository extends JpaRepository<OAuth2Authorization, String> {
//    Optional<OAuth2Authorization> findByState(String state);
//
//    Optional<OAuth2Authorization> findByAuthorizationCodeValue(String authorizationCode);
//
//    Optional<OAuth2Authorization> findByAccessTokenValue(String accessToken);
//
//    Optional<OAuth2Authorization> findByRefreshTokenValue(String refreshToken);
//
//    @Query("select a from OAuth2Authorization a where a.state = :token" +
//            " or a.authorizationCodeValue = :token" +
//            " or a.accessTokenValue = :token" +
//            " or a.refreshTokenValue = :token"
//    )
//    Optional<OAuth2Authorization> findByStateOrAuthorizationCodeValueOrAccessTokenValueOrRefreshTokenValue(@Param("token") String token);
//}
