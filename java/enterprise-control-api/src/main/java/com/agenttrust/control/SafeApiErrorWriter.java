package com.agenttrust.control;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Supplier;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

/** Writes the exact public JSON error contract for failures raised before MVC dispatch. */
@Component
final class SafeApiErrorWriter implements AuthenticationEntryPoint, AccessDeniedHandler {
    static final String AUTHENTICATION_REQUIRED = "CONTROL_AUTHENTICATION_REQUIRED";
    static final String ACCESS_DENIED = "CONTROL_ACCESS_DENIED";
    private final ObjectMapper mapper;
    private final Clock clock;
    private final Supplier<UUID> traceIds;

    SafeApiErrorWriter(ObjectMapper mapper) {
        this(mapper, Clock.systemUTC(), UUID::randomUUID);
    }

    SafeApiErrorWriter(ObjectMapper mapper, Clock clock, Supplier<UUID> traceIds) {
        this.mapper = Objects.requireNonNull(mapper, "mapper");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.traceIds = Objects.requireNonNull(traceIds, "traceIds");
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException error) throws IOException {
        write(response, HttpStatus.UNAUTHORIZED, AUTHENTICATION_REQUIRED, true);
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException error) throws IOException {
        write(response, HttpStatus.FORBIDDEN, ACCESS_DENIED);
    }

    void write(HttpServletResponse response, HttpStatus status, String code) throws IOException {
        write(response, status, code, false);
    }

    private void write(HttpServletResponse response, HttpStatus status, String code,
                       boolean bearerChallenge) throws IOException {
        Objects.requireNonNull(response, "response");
        Objects.requireNonNull(status, "status");
        if (!status.isError() || !SafeErrorBody.validCode(code)) {
            throw new IllegalArgumentException("CONTROL_SAFE_ERROR_CONTRACT_INVALID");
        }
        String traceId = Objects.requireNonNull(traceIds.get(), "traceId").toString();
        byte[] body = mapper.writeValueAsBytes(new SafeErrorBody(
            SafeErrorBody.SCHEMA_VERSION, code, traceId, Instant.now(clock).toString()));

        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        response.setHeader("X-Trace-Id", traceId);
        if (bearerChallenge) {
            response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
        }
        response.setContentLength(body.length);
        response.getOutputStream().write(body);
    }
}
