package com.agenttrust.control;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;

class SafeApiErrorWriterTest {
    private static final Instant NOW = Instant.parse("2030-01-02T03:04:05Z");
    private static final UUID TRACE_ID =
        UUID.fromString("01900000-0000-7000-8000-000000000001");
    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void authenticationFailureIsExactSafeJsonWithBearerChallenge() throws Exception {
        var capture = new SafeErrorTestSupport.ResponseCapture();
        writer().commence(SafeErrorTestSupport.request("/v1/session", 0, null),
            capture.response(), new BadCredentialsException("secret diagnostic"));

        assertSafeError(capture, 401, SafeApiErrorWriter.AUTHENTICATION_REQUIRED);
        assertEquals("Bearer", capture.header(HttpHeaders.WWW_AUTHENTICATE));
        assertFalse(capture.bodyText().contains("secret diagnostic"));
    }

    @Test
    void accessDeniedFailureIsExactSafeJsonWithoutAuthenticationDetails() throws Exception {
        var capture = new SafeErrorTestSupport.ResponseCapture();
        writer().handle(SafeErrorTestSupport.request("/v1/approvals", 0, null),
            capture.response(), new AccessDeniedException("policy internals"));

        assertSafeError(capture, 403, SafeApiErrorWriter.ACCESS_DENIED);
        assertNull(capture.header(HttpHeaders.WWW_AUTHENTICATE));
        assertFalse(capture.bodyText().contains("policy internals"));
    }

    @Test
    void interactiveOauthRequestUsesItsOriginalEntryPoint() throws Exception {
        var fallbackCalled = new AtomicBoolean();
        var capture = new SafeErrorTestSupport.ResponseCapture();
        var handlers = new ApiSecurityErrorHandlers(
            request -> request.getRequestURI().startsWith("/v1/"), writer());
        var entryPoint = handlers.authenticationEntryPoint((request, response, error) -> {
            fallbackCalled.set(true);
            response.setStatus(302);
            response.setHeader(HttpHeaders.LOCATION, "/oauth2/authorization/agenttrust");
        });

        entryPoint.commence(
            SafeErrorTestSupport.request("/oauth2/authorization/agenttrust", 0, null),
            capture.response(), new BadCredentialsException("interactive"));

        assertTrue(fallbackCalled.get());
        assertEquals(302, capture.status());
        assertEquals("/oauth2/authorization/agenttrust", capture.header(HttpHeaders.LOCATION));
        assertEquals(0, capture.body().length);
    }

    @Test
    void apiRequestDoesNotFallThroughToBrowserEntryPoint() throws Exception {
        var fallbackCalled = new AtomicBoolean();
        var capture = new SafeErrorTestSupport.ResponseCapture();
        var handlers = new ApiSecurityErrorHandlers(
            request -> request.getRequestURI().startsWith("/v1/"), writer());
        var entryPoint = handlers.authenticationEntryPoint((request, response, error) ->
            fallbackCalled.set(true));

        entryPoint.commence(SafeErrorTestSupport.request("/v1/tasks", 0, null),
            capture.response(), new BadCredentialsException("api"));

        assertFalse(fallbackCalled.get());
        assertSafeError(capture, 401, SafeApiErrorWriter.AUTHENTICATION_REQUIRED);
    }

    @Test
    void nonApiAccessDeniedUsesItsOriginalBrowserHandler() throws Exception {
        var fallbackCalled = new AtomicBoolean();
        var capture = new SafeErrorTestSupport.ResponseCapture();
        var handlers = new ApiSecurityErrorHandlers(
            request -> request.getRequestURI().startsWith("/v1/"), writer());
        var deniedHandler = handlers.accessDeniedHandler((request, response, error) -> {
            fallbackCalled.set(true);
            response.setStatus(403);
        });

        deniedHandler.handle(SafeErrorTestSupport.request("/login/oauth2/code/agenttrust", 0, null),
            capture.response(), new AccessDeniedException("interactive"));

        assertTrue(fallbackCalled.get());
        assertEquals(403, capture.status());
        assertEquals(0, capture.body().length);
    }

    @Test
    void mvcUnsupportedContentTypeUsesTheSameSafeContract() throws Exception {
        var response = new ApiErrors().unsupportedMediaType(null);

        assertEquals(HttpStatus.UNSUPPORTED_MEDIA_TYPE, response.getStatusCode());
        assertEquals(MediaType.APPLICATION_JSON, response.getHeaders().getContentType());
        assertEquals("no-store", response.getHeaders().getCacheControl());
        SafeErrorBody value = response.getBody();
        assertTrue(value != null);
        assertEquals("CONTROL_UNSUPPORTED_MEDIA_TYPE", value.code());
        assertEquals(value.traceId(), response.getHeaders().getFirst("X-Trace-Id"));
        JsonNode body = mapper.valueToTree(value);
        var fields = new HashSet<String>();
        body.fieldNames().forEachRemaining(fields::add);
        assertEquals(Set.of("schema_version", "code", "trace_id", "occurred_at"), fields);
    }

    @Test
    void mvcExceptionMessagesCannotEscapeTheSafeCodeAllowlist() throws Exception {
        var response = new ApiErrors().denied(new ControlDeniedException(
            "raw policy diagnostic with secret"));

        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
        assertEquals("CONTROL_INTERNAL_ERROR", response.getBody().code());
        assertFalse(mapper.writeValueAsString(response.getBody()).contains("secret"));
    }

    private SafeApiErrorWriter writer() {
        return new SafeApiErrorWriter(mapper, Clock.fixed(NOW, ZoneOffset.UTC), () -> TRACE_ID);
    }

    private void assertSafeError(SafeErrorTestSupport.ResponseCapture capture,
                                 int status, String code) throws Exception {
        assertEquals(status, capture.status());
        assertEquals("application/json", capture.contentType());
        assertEquals("no-store", capture.header(HttpHeaders.CACHE_CONTROL));
        assertEquals(TRACE_ID.toString(), capture.header("X-Trace-Id"));
        assertEquals(capture.body().length, capture.contentLength());
        JsonNode body = mapper.readTree(capture.body());
        var fields = new HashSet<String>();
        body.fieldNames().forEachRemaining(fields::add);
        assertEquals(Set.of("schema_version", "code", "trace_id", "occurred_at"), fields);
        assertEquals(SafeErrorBody.SCHEMA_VERSION, body.path("schema_version").textValue());
        assertEquals(code, body.path("code").textValue());
        assertEquals(TRACE_ID.toString(), body.path("trace_id").textValue());
        assertEquals(NOW.toString(), body.path("occurred_at").textValue());
    }
}
