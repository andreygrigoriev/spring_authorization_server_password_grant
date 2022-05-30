package com.example.spring_authorization_server_password_grant.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Slf4j
@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class DefaultSecurityConfig {

   @Bean
   @Order(3)
   public SecurityFilterChain defaultFilterChain(HttpSecurity http) throws Exception {
      return http
            .csrf().disable()
            .authorizeRequests(authorizeRequests ->
                  authorizeRequests.anyRequest().authenticated()
            )
            .formLogin(withDefaults()).build();
   }

   @Bean
   @SuppressWarnings("unused")
   public UserDetailsService users(PasswordEncoder passwordEncoder) {
      UserDetails user = User.builder()
            .passwordEncoder(passwordEncoder::encode)
            .username("admin")
            .password("password")
            .roles("USER")
            .build();
      return new InMemoryUserDetailsManager(user);
   }

}