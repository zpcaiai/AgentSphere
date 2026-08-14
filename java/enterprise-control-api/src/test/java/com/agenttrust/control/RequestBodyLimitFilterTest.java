package com.agenttrust.control;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import org.junit.jupiter.api.Test;

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

    private static ServletInputStream input(byte[] body) {
        var bytes = new ByteArrayInputStream(body);
        return new ServletInputStream() {
            @Override public int read() { return bytes.read(); }
            @Override public boolean isFinished() { return bytes.available() == 0; }
            @Override public boolean isReady() { return true; }
            @Override public void setReadListener(ReadListener listener) { /* synchronous test */ }
        };
    }
}
