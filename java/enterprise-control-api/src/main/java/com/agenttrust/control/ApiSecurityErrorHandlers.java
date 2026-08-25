package com.agenttrust.control;

import java.util.Objects;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;

/** Keeps JSON API failures isolated from interactive OAuth2 browser entry points. */
final class ApiSecurityErrorHandlers {
    private final RequestMatcher apiRequests;
    private final SafeApiErrorWriter writer;

    ApiSecurityErrorHandlers(RequestMatcher apiRequests, SafeApiErrorWriter writer) {
        this.apiRequests = Objects.requireNonNull(apiRequests, "apiRequests");
        this.writer = Objects.requireNonNull(writer, "writer");
    }

    AuthenticationEntryPoint authenticationEntryPoint(AuthenticationEntryPoint fallback) {
        Objects.requireNonNull(fallback, "fallback");
        return (request, response, error) -> {
            if (apiRequests.matches(request)) {
                writer.commence(request, response, error);
            } else {
                fallback.commence(request, response, error);
            }
        };
    }

    AccessDeniedHandler accessDeniedHandler(AccessDeniedHandler fallback) {
        Objects.requireNonNull(fallback, "fallback");
        return (request, response, error) -> {
            if (apiRequests.matches(request)) {
                writer.handle(request, response, error);
            } else {
                fallback.handle(request, response, error);
            }
        };
    }
}
