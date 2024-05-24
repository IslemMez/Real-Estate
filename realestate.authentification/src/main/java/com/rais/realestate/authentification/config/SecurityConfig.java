package com.rais.realestate.authentification.config;

import org.keycloak.adapters.springboot.KeycloakSpringBootConfigResolver;
import org.keycloak.adapters.springsecurity.KeycloakConfiguration;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.keycloak.adapters.springsecurity.filter.KeycloakAuthenticationProcessingFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;


// Defines all annotations that are needed to integrate Keycloak in Spring Security
@KeycloakConfiguration
public class SecurityConfig implements ,  {

    @Autowired
    RestAccessDeniedHandler restAccessDeniedHandler;

    @Autowired
    CustomKeycloakAuthenticationHandler customKeycloakAuthenticationHandler;

    @Override
    public void configure(HttpSecurity http) throws Exception {
        super.configure(http);
        http
                .authorizeHttpRequests((requests) -> requests
                        .requestMatchers("/login", "/random").permitAll()
                        .requestMatchers("/visitor").hasRole("visitor")
                        .requestMatchers("/admin").hasRole("admin")
                        .anyRequest().authenticated()
                )
                .exceptionHandling((exceptions) -> exceptions
                        .accessDeniedHandler(restAccessDeniedHandler)
                );
    }

    // Disable default role prefix ROLE_
    @Autowired
    public void configureGlobal( AuthenticationManagerBuilder auth) throws Exception {
        KeycloakAuthenticationProvider keycloakAuthenticationProvider = keycloakAuthenticationProvider();
        keycloakAuthenticationProvider.setGrantedAuthoritiesMapper(new SimpleAuthorityMapper());
        auth.authenticationProvider(keycloakAuthenticationProvider);
    }

    // Use Spring Boot property files instead of default keycloak.json
    @Bean
    public KeycloakSpringBootConfigResolver KeycloakConfigResolver() {
        return new KeycloakSpringBootConfigResolver();
    }

    // Register authentication strategy for public or confidential applications
    @Bean
    @Override
    protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
    }

    //Keycloak auth exception handler
    @Bean
    @Override
    protected KeycloakAuthenticationProcessingFilter keycloakAuthenticationProcessingFilter()
            throws Exception {
        KeycloakAuthenticationProcessingFilter filter =
                new KeycloakAuthenticationProcessingFilter(authentication -> {
                    throw new RuntimeException("Authentication is not supported: " + authentication);
                });
        filter.setSessionAuthenticationStrategy(this.sessionAuthenticationStrategy());
        filter.setAuthenticationFailureHandler(customKeycloakAuthenticationHandler);
        return filter;
    }

    @Override
    public void init(SecurityBuilder builder) throws Exception {

    }

    @Override
    public void configure(SecurityBuilder builder) throws Exception {

    }
}