package com.agenttrust.control;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.oauth2.client.endpoint.RestClientAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestTemplate;

/** Explicit IAM endpoints avoid ambient discovery and bind every server call to enterprise mTLS. */
@Configuration
public class IamSecurityConfiguration {
    @Bean
    ClientRegistrationRepository clientRegistrationRepository(
        ControlProperties properties,
        @Value("${AGENT_TRUST_CONSOLE_OIDC_CLIENT_ID}") String clientId,
        @Value("${AGENT_TRUST_CONSOLE_OIDC_CLIENT_SECRET}") String clientSecret
    ) {
        if (clientId.isBlank() || clientId.length() > 256
            || clientSecret.length() < 16 || clientSecret.length() > 4096) {
            throw new IllegalArgumentException("CONTROL_OIDC_CLIENT_INVALID");
        }
        ClientRegistration registration = ClientRegistration.withRegistrationId("agenttrust")
            .clientId(clientId)
            .clientSecret(clientSecret)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
            .scope("openid", "profile")
            .authorizationUri(properties.iamAuthorizationEndpoint().toString())
            .tokenUri(properties.iamTokenEndpoint().toString())
            .userInfoUri(properties.iamUserInfoEndpoint().toString())
            .userInfoAuthenticationMethod(AuthenticationMethod.HEADER)
            .userNameAttributeName("sub")
            .jwkSetUri(properties.jwksEndpoint().toString())
            .issuerUri(properties.iamIssuer().toString())
            .clientName("Agent Trust")
            .build();
        return new InMemoryClientRegistrationRepository(registration);
    }

    @Bean
    JwtDecoder jwtDecoder(ControlProperties properties, SecureRestClientFactory clients) {
        return decoder(properties, clients, properties.iamAudience());
    }

    @Bean
    JwtDecoderFactory<ClientRegistration> oidcIdTokenDecoderFactory(
        ControlProperties properties, SecureRestClientFactory clients
    ) {
        // The registration is fixed and discovery-free, so the same bounded mTLS decoder can be
        // rebuilt per login/key miss while preserving issuer and audience validation.
        return registration -> decoder(properties, clients, registration.getClientId());
    }

    @Bean
    RestClientAuthorizationCodeTokenResponseClient authorizationCodeTokenResponseClient(
        SecureRestClientFactory clients
    ) {
        var result = new RestClientAuthorizationCodeTokenResponseClient();
        var tokenClient = RestClient.builder()
            .requestFactory(clients.rotatingRequestFactory())
            .messageConverters(converters -> {
                converters.clear();
                converters.add(new FormHttpMessageConverter());
                converters.add(new OAuth2AccessTokenResponseHttpMessageConverter());
            })
            .defaultStatusHandler(
                new org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler())
            .build();
        result.setRestClient(tokenClient);
        return result;
    }

    @Bean
    OidcUserService oidcUserService(SecureRestClientFactory clients) {
        var oauth = new DefaultOAuth2UserService();
        oauth.setRestOperations(new RestTemplate(clients.rotatingRequestFactory()));
        var oidc = new OidcUserService();
        oidc.setOauth2UserService(oauth);
        return oidc;
    }

    private static JwtDecoder decoder(ControlProperties properties,
                                      SecureRestClientFactory clients, String audienceValue) {
        var decoder = NimbusJwtDecoder.withJwkSetUri(properties.jwksEndpoint().toString())
            .restOperations(new RestTemplate(clients.rotatingRequestFactory()))
            .build();
        OAuth2TokenValidator<Jwt> audience = jwt -> jwt.getAudience().contains(audienceValue)
                ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token",
                    "required audience is absent", null));
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
            JwtValidators.createDefaultWithIssuer(properties.iamIssuer().toString()), audience));
        return decoder;
    }
}
