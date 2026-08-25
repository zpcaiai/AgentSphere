package com.agenttrust.control;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import jakarta.servlet.ServletInputStream;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;

class RequestBodyLimitFilterTest {
    @Test
    void chunkedStyleStreamFailsOnFirstByteBeyondLimit() throws IOException {
        byte[] body = new byte[(int) RequestBodyLimitFilter.MAXIMUM_REQUEST_BODY_BYTES + 1];
        ServletInputStream source = input(body);
        var bounded = new RequestBodyLimitFilter.BoundedInputStream(source);
        byte[] buffer = new byte[8192];
        long read = 0;
        while (read < RequestBodyLimitFilter.MAXIMUM_REQUEST_BODY_BYTES) {
            read += bounded.read(buffer, 0, (int) Math.min(buffer.length,
                RequestBodyLimitFilter.MAXIMUM_REQUEST_BODY_BYTES - read));
        }
        assertEquals(RequestBodyLimitFilter.MAXIMUM_REQUEST_BODY_BYTES, read);
        assertThrows(RequestBodyLimitFilter.RequestBodyTooLargeException.class, bounded::read);
    }

    @Test
    void declaredOversizeBodyReturnsExactSafe413WithoutCallingChain() throws Exception {
        assertRejected(RequestBodyLimitFilter.MAXIMUM_REQUEST_BODY_BYTES + 1, null, 413,
            "CONTROL_REQUEST_BODY_TOO_LARGE");
    }

    @Test
    void compressedBodyReturnsExactSafe415WithoutCallingChain() throws Exception {
        assertRejected(128, "gzip", 415, "CONTROL_CONTENT_ENCODING_UNSUPPORTED");
    }

    private static void assertRejected(long contentLength, String contentEncoding,
                                       int status, String code) throws Exception {
        Instant now = Instant.parse("2030-01-02T03:04:05Z");
        UUID traceId = UUID.fromString("01900000-0000-7000-8000-000000000002");
        ObjectMapper mapper = new ObjectMapper();
        var writer = new SafeApiErrorWriter(mapper,
            Clock.fixed(now, ZoneOffset.UTC), () -> traceId);
        var filter = new RequestBodyLimitFilter(writer);
        var capture = new SafeErrorTestSupport.ResponseCapture();
        boolean[] chainCalled = {false};

        filter.doFilterInternal(
            SafeErrorTestSupport.request("/v1/tasks", contentLength, contentEncoding),
            capture.response(), (request, response) -> chainCalled[0] = true);

        assertFalse(chainCalled[0]);
        assertEquals(status, capture.status());
        assertEquals("application/json", capture.contentType());
        assertEquals("no-store", capture.header(HttpHeaders.CACHE_CONTROL));
        assertEquals(traceId.toString(), capture.header("X-Trace-Id"));
        JsonNode body = mapper.readTree(capture.body());
        var fields = new HashSet<String>();
        body.fieldNames().forEachRemaining(fields::add);
        assertEquals(Set.of("schema_version", "code", "trace_id", "occurred_at"), fields);
        assertEquals(SafeErrorBody.SCHEMA_VERSION, body.path("schema_version").textValue());
        assertEquals(code, body.path("code").textValue());
        assertEquals(traceId.toString(), body.path("trace_id").textValue());
        assertEquals(now.toString(), body.path("occurred_at").textValue());
    }

    private static ServletInputStream input(byte[] body) {
        return SafeErrorTestSupport.input(body);
    }
}
