package com.example.spring_authorization_server_password_grant.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.authentication.ClientSecretAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.token.*;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Configuration(proxyBeanMethods = false)
@Order(1)
public class OauthConfig {

   private static final String UNIQUE_CLIENT_ID = "ec3898c5-7d13-40ec-8f67-24d3d34b891a";
   private static final String AUTHORITIES_CLAIM = "authorities";

   private final AuthProperties authProperties;

   @Autowired
   @SuppressWarnings("unused")
   public OauthConfig(AuthProperties authProperties) {
      this.authProperties = authProperties;
   }

   @Bean
   @SuppressWarnings("unused")
   public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
      RegisteredClient registeredClient = RegisteredClient.withId(UNIQUE_CLIENT_ID)
            .clientId(authProperties.getClientId())
            .clientSecret(passwordEncoder().encode(authProperties.getClientSecret()))
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .redirectUri(authProperties.getRedirectUri())
            .scope(OidcScopes.OPENID)
            .scope("read")
            .scope("write")
            .scope("user_info")
            .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
            .build();

      // Save registered client in db as if in-memory
      JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
      registeredClientRepository.save(registeredClient);

      return registeredClientRepository;
   }

   @Bean
   @SuppressWarnings("unused")
   public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
      return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
   }

   @Bean
   @SuppressWarnings("unused")
   public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
      return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
   }

   @Bean
   @SuppressWarnings("unused")
   public ClientSecretAuthenticationProvider oauthClientAuthProvider(RegisteredClientRepository registeredClientRepository, OAuth2AuthorizationService oAuth2AuthorizationService) {
      ClientSecretAuthenticationProvider clientAuthenticationProvider =
            new ClientSecretAuthenticationProvider(
                  registeredClientRepository,
                  oAuth2AuthorizationService);
      clientAuthenticationProvider.setPasswordEncoder(passwordEncoder());
      return clientAuthenticationProvider;
   }

   @Bean
   @SuppressWarnings("unused")
   public DaoAuthenticationProvider authenticationProvider(UserDetailsService userDetailsService) {
      DaoAuthenticationProvider authProvider
            = new DaoAuthenticationProvider();
      authProvider.setUserDetailsService(userDetailsService);
      authProvider.setPasswordEncoder(passwordEncoder());
      return authProvider;
   }

   @Bean
   @SuppressWarnings("unused")
   OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
      return context -> {
         JwsHeader.Builder headers = context.getHeaders();
         JwtClaimsSet.Builder claims = context.getClaims();
         OAuth2Authorization authorization = context.get(OAuth2Authorization.class);
         RegisteredClient registeredClient = context.get(RegisteredClient.class);
         OAuth2AuthorizationCodeAuthenticationToken authorizationCodeAuthentication =
               context.get(OAuth2AuthorizationCodeAuthenticationToken.class);

         Authentication principal = context.getPrincipal();
         Set<String> authorities = principal.getAuthorities().stream()
               .map(GrantedAuthority::getAuthority)
               .collect(Collectors.toSet());
         context.getClaims().claim(AUTHORITIES_CLAIM, authorities);

         claims.claim("test", "12345");

         Set<String> authorizedScopes = context.getAuthorizedScopes();
         Authentication authentication = context.getAuthorizationGrant();

      };
   }

   @Bean
   @SuppressWarnings("unused")
   public OAuth2TokenGenerator<OAuth2Token> oAuth2TokenGenerator(JwtEncoder jwtEncoder, OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer) {
      JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
      jwtGenerator.setJwtCustomizer(jwtCustomizer);
      OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
//        accessTokenGenerator.setAccessTokenCustomizer(this.accessTokenCustomizer);
      OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
      return new DelegatingOAuth2TokenGenerator(jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
   }

   @Bean
   @SuppressWarnings("unused")
   public JWKSource<SecurityContext> jwkSource() {
      JWKSet jwkSet = new JWKSet(generateRsa());
      return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
   }

   @Bean
   @SuppressWarnings("unused")
   public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
      return new NimbusJwtEncoder(jwkSource);
   }

   @Bean
   @SuppressWarnings("unused")
   public ProviderSettings providerSettings() {
      return ProviderSettings.builder().issuer(authProperties.getIssuerUri()).build();
   }

   private RSAKey generateRsa() {
      KeyPair keyPair = generateRsaKey();
      RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
      RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
      return new RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .keyUse(KeyUse.SIGNATURE)
            .build();
   }

   private KeyPair generateRsaKey() {
      KeyPair keyPair;
      try {
         KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
         keyPairGenerator.initialize(2048);
         keyPair = keyPairGenerator.generateKeyPair();
      } catch (Exception ex) {
         throw new IllegalStateException(ex);
      }
      return keyPair;
   }

   @Bean
   @SuppressWarnings("unused")
   public BCryptPasswordEncoder passwordEncoder() {
      return new BCryptPasswordEncoder();
   }

   @Bean
   @SuppressWarnings("unused")
   public EmbeddedDatabase embeddedDatabase() {
      return new EmbeddedDatabaseBuilder()
            .generateUniqueName(true)
            .setType(EmbeddedDatabaseType.H2)
            .setScriptEncoding("UTF-8")
            .addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql")
            .addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql")
            .addScript("org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql")
            .build();
   }
}
