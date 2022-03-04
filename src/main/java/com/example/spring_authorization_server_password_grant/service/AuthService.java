package com.example.spring_authorization_server_password_grant.service;

import com.example.spring_authorization_server_password_grant.config.AuthProperties;
import com.example.spring_authorization_server_password_grant.model.AppUser;
import com.example.spring_authorization_server_password_grant.model.AppUserPrincipal;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.compress.utils.Sets;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.authentication.*;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.context.ProviderContext;
import org.springframework.security.oauth2.server.authorization.context.ProviderContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Service
@Slf4j
public class AuthService {
   private final AuthenticationManager authenticationManager;
   private final OAuth2ClientAuthenticationProvider oAuth2ClientAuthenticationProvider;
   private final OAuth2AuthorizationCodeRequestAuthenticationProvider oAuth2AuthorizationCodeRequestAuthenticationProvider;
   private final OAuth2AuthorizationCodeAuthenticationProvider oAuth2AuthorizationCodeAuthenticationProvider;
   private final OAuth2AuthorizationService authorizationService;
   private final AuthProperties authProperties;
   private final ObjectMapper objectMapper;

   private final static String FIRST_NAME = "firstName";
   private final static String LAST_NAME = "lastName";
   private static final String LOCAL_AUTHORIZATION_URI = "http://localhost:8080/oauth2/authorize";

   @Autowired
   public AuthService(
         @Lazy AuthenticationManager authenticationManager,
         @Qualifier("oauthClientAuthProvider") OAuth2ClientAuthenticationProvider oAuth2ClientAuthenticationProvider,
         RegisteredClientRepository registeredClientRepository,
         @Lazy OAuth2AuthorizationService authorizationService,
         @Lazy OAuth2AuthorizationConsentService authorizationConsentService,
         OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer,
         JwtEncoder jwtEncoder,
         AuthProperties authProperties) {

      this.authenticationManager = authenticationManager;
      this.oAuth2ClientAuthenticationProvider = oAuth2ClientAuthenticationProvider;
      this.authorizationService = authorizationService;
      this.oAuth2AuthorizationCodeRequestAuthenticationProvider = new OAuth2AuthorizationCodeRequestAuthenticationProvider(registeredClientRepository, authorizationService, authorizationConsentService);
      this.oAuth2AuthorizationCodeAuthenticationProvider = new OAuth2AuthorizationCodeAuthenticationProvider(authorizationService, jwtEncoder);
      oAuth2AuthorizationCodeAuthenticationProvider.setJwtCustomizer(jwtCustomizer);
      this.authProperties = authProperties;
      this.objectMapper = new ObjectMapper();
   }

   public String getAccessTokenForRequest(HttpServletRequest request) {
      String userName = request.getParameter("username");
      String passwordInBase64 = request.getParameter("password");
      Assert.notNull(userName, "Username parameter must not be empty or null");
      Assert.hasText(passwordInBase64, "Password parameter must not be empty or null");
      String password = new String(Base64.getUrlDecoder().decode(passwordInBase64));

      UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(userName, password);
      Authentication principal = authenticationManager.authenticate(authRequest);

      try {
         // from org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationEndpointFilter.doFilterInternal
         // from org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationConverter.convert
         OAuth2AuthorizationCodeRequestAuthenticationToken requestAuthenticationToken =
               OAuth2AuthorizationCodeRequestAuthenticationToken.with(authProperties.getClientId(), principal)
                     .authorizationUri(LOCAL_AUTHORIZATION_URI)
                     .consentRequired(false)
                     .scopes(Sets.newHashSet("openid", "read", "write"))
                     .redirectUri(authProperties.getRedirectUri())
                     .state("STATE").build();

         OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthenticationResult =
               (OAuth2AuthorizationCodeRequestAuthenticationToken) oAuth2AuthorizationCodeRequestAuthenticationProvider.authenticate(requestAuthenticationToken);

         // from org.springframework.security.oauth2.server.authorization.web.OAuth2TokenEndpointFilter.doFilterInternal
         // from org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeAuthenticationConverter.convert
         Map<String, Object> params = new HashMap<>();
         OAuth2AuthorizationCode authorizationCode = authorizationCodeRequestAuthenticationResult.getAuthorizationCode();
         params.put("code", authorizationCode == null ? "EMPTY" : authorizationCodeRequestAuthenticationResult.getAuthorizationCode().getTokenValue());
         params.put("redirect_uri", authProperties.getRedirectUri());
         params.put("grant_type", "authorization_code");
         params.put("client_id", authProperties.getClientId());
         OAuth2ClientAuthenticationToken clientAuthenticationToken = new OAuth2ClientAuthenticationToken(authProperties.getClientId(),
               ClientAuthenticationMethod.CLIENT_SECRET_BASIC, authProperties.getClientSecret(), params);

         Authentication clientAuthenticationResult = oAuth2ClientAuthenticationProvider.authenticate(clientAuthenticationToken);

         OAuth2AuthorizationCodeAuthenticationToken codeToken = new OAuth2AuthorizationCodeAuthenticationToken(
               authorizationCodeRequestAuthenticationResult.getAuthorizationCode().getTokenValue(), clientAuthenticationResult,
               authProperties.getRedirectUri(), new LinkedHashMap<>());

         ProviderSettings providerSettings = ProviderSettings.builder().issuer(authProperties.getIssuerUri()).build();
         ProviderContextHolder.setProviderContext(new ProviderContext(providerSettings, null));

         OAuth2AccessTokenAuthenticationToken accessTokenAuthentication =
               (OAuth2AccessTokenAuthenticationToken) oAuth2AuthorizationCodeAuthenticationProvider.authenticate(codeToken);

         // from org.springframework.security.oauth2.server.authorization.web.OAuth2TokenEndpointFilter.sendAccessTokenResponse
         OAuth2AccessToken accessToken = accessTokenAuthentication.getAccessToken();
         OAuth2RefreshToken refreshToken = accessTokenAuthentication.getRefreshToken();
         Map<String, Object> additionalParameters = accessTokenAuthentication.getAdditionalParameters();

         if (principal.getPrincipal() instanceof AppUserPrincipal) {
            AppUserPrincipal appUserPrincipal = ((AppUserPrincipal) principal.getPrincipal());
            AppUser user = appUserPrincipal.getUser();
            additionalParameters.put(FIRST_NAME, user.getFirstName());
            additionalParameters.put(LAST_NAME, user.getLastName());
         }

         OAuth2AccessTokenResponse.Builder builder =
               OAuth2AccessTokenResponse.withToken(accessToken.getTokenValue())
                     .tokenType(accessToken.getTokenType())
                     .scopes(accessToken.getScopes());
         if (accessToken.getIssuedAt() != null && accessToken.getExpiresAt() != null) {
            builder.expiresIn(ChronoUnit.SECONDS.between(accessToken.getIssuedAt(), accessToken.getExpiresAt()));
         }
         if (refreshToken != null) {
            builder.refreshToken(refreshToken.getTokenValue());
         }
         if (!CollectionUtils.isEmpty(additionalParameters)) {
            builder.additionalParameters(additionalParameters);
         }
         OAuth2AccessTokenResponse accessTokenResponse = builder.build();
         Map<String, Object> accessTokenResponseMap = convert(accessTokenResponse);

         return objectMapper.writeValueAsString(accessTokenResponseMap);
      } catch (Exception ex) {
         log.error("error in get token >>>", ex);
         throw new RuntimeException(ex); // TODO security
      }
   }

   public Map<String, Object> convert(OAuth2AccessTokenResponse tokenResponse) {
      Map<String, Object> parameters = new HashMap<>();
      parameters.put(OAuth2ParameterNames.ACCESS_TOKEN, tokenResponse.getAccessToken().getTokenValue());
      parameters.put(OAuth2ParameterNames.TOKEN_TYPE, tokenResponse.getAccessToken().getTokenType().getValue());
      parameters.put(OAuth2ParameterNames.EXPIRES_IN, getExpiresIn(tokenResponse));
      if (!CollectionUtils.isEmpty(tokenResponse.getAccessToken().getScopes())) {
         parameters.put(OAuth2ParameterNames.SCOPE,
               StringUtils.collectionToDelimitedString(tokenResponse.getAccessToken().getScopes(), " "));
      }
      if (tokenResponse.getRefreshToken() != null) {
         parameters.put(OAuth2ParameterNames.REFRESH_TOKEN, tokenResponse.getRefreshToken().getTokenValue());
      }
      if (!CollectionUtils.isEmpty(tokenResponse.getAdditionalParameters())) {
         parameters.putAll(tokenResponse.getAdditionalParameters());
      }
      return parameters;
   }

   private long getExpiresIn(OAuth2AccessTokenResponse tokenResponse) {
      if (tokenResponse.getAccessToken().getExpiresAt() != null) {
         return ChronoUnit.SECONDS.between(Instant.now(), tokenResponse.getAccessToken().getExpiresAt());
      }
      return -1;
   }
}

