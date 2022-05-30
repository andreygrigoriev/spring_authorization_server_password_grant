package com.example.spring_authorization_server_password_grant.config;

import java.util.function.Function;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {

   private final PasswordGrantFilter passwordGrantFilter;

   @Autowired
   @SuppressWarnings("unused")
   public AuthorizationServerConfig(PasswordGrantFilter passwordGrantFilter) {
      this.passwordGrantFilter = passwordGrantFilter;
   }

   @Bean
   @Order(2)
   @SuppressWarnings("unused")
   public SecurityFilterChain authSecurityFilterChain(HttpSecurity http) throws Exception {
      OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
            new OAuth2AuthorizationServerConfigurer<>();
      RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();
      RequestMatcher passwordGrantEndPointMatcher = new AntPathRequestMatcher("/oauth/token");

      // Custom User Info Mapper that retrieves claims from a signed JWT
      Function<OidcUserInfoAuthenticationContext, OidcUserInfo> userInfoMapper = context -> {
         OidcUserInfoAuthenticationToken authentication = context.getAuthentication();
         JwtAuthenticationToken principal = (JwtAuthenticationToken) authentication.getPrincipal();
         return new OidcUserInfo(principal.getToken().getClaims());
      };

      http
            .requestMatchers().requestMatchers(endpointsMatcher, passwordGrantEndPointMatcher).and()
            .authorizeRequests()
            .antMatchers("/oauth/token").permitAll()
            .anyRequest().authenticated()
            .and()
            .csrf().disable()
            .apply(authorizationServerConfigurer)
            .oidc(oidc -> oidc
                  .clientRegistrationEndpoint(Customizer.withDefaults())
                  .userInfoEndpoint(userInfo -> userInfo.userInfoMapper(userInfoMapper))
            )
            .and()
            .addFilterBefore(passwordGrantFilter, AbstractPreAuthenticatedProcessingFilter.class)
            .exceptionHandling(exceptions ->
                  exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
            );

      return http.build();
   }

   @Bean
   @SuppressWarnings("unused")
   public AuthenticationManager authenticationManagerBean(AuthenticationConfiguration authenticationConfiguration) throws Exception {
      return authenticationConfiguration.getAuthenticationManager();
   }

}