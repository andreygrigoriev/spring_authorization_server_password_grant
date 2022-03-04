package com.example.spring_authorization_server_password_grant.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "auth")
@Data
public class AuthProperties {
   private boolean localServer;
   private long accessTokenValidity;
   private long refreshTokenValidity;
   private String issuerUri;
   private String clientId;
   private String clientSecret;
   private String redirectUri;
}