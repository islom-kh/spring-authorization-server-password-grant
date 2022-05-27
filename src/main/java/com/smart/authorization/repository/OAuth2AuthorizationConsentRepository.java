//package com.smart.authorization.repository;
//
//import com.smart.authorization.domain.OAuth2Authorization;
//import com.smart.authorization.domain.OAuth2AuthorizationConsent;
//import org.springframework.data.jpa.repository.JpaRepository;
//import org.springframework.data.jpa.repository.Query;
//import org.springframework.data.repository.query.Param;
//import org.springframework.stereotype.Repository;
//
//import java.util.Optional;
//
//@Repository
//public interface OAuth2AuthorizationConsentRepository extends JpaRepository<OAuth2AuthorizationConsent, String> {
//    Optional<OAuth2AuthorizationConsent> findByRegisteredClientIdAndPrincipalName(String registeredClientId, String principalName);
//
//    void deleteByRegisteredClientIdAndPrincipalName(String registeredClientId, String principalName);
//}
