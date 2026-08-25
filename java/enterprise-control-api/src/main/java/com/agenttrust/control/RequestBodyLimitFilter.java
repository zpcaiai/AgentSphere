package com.agenttrust.control;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import org.springframework.http.HttpStatus;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/** Enforces a streaming cap before Jackson can allocate an unbounded chunked JSON body. */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public final class RequestBodyLimitFilter extends OncePerRequestFilter {
    static final long MAXIMUM_REQUEST_BODY_BYTES = 1024L * 1024L;
    private final SafeApiErrorWriter errorWriter;

    RequestBodyLimitFilter(SafeApiErrorWriter errorWriter) {
        this.errorWriter = Objects.requireNonNull(errorWriter, "errorWriter");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        long declared = request.getContentLengthLong();
        if (declared > MAXIMUM_REQUEST_BODY_BYTES) {
            errorWriter.write(response, HttpStatus.PAYLOAD_TOO_LARGE,
                "CONTROL_REQUEST_BODY_TOO_LARGE");
            return;
        }
        String encoding = request.getHeader("Content-Encoding");
        if (encoding != null && !encoding.isBlank() && !"identity".equalsIgnoreCase(encoding)) {
            errorWriter.write(response, HttpStatus.UNSUPPORTED_MEDIA_TYPE,
                "CONTROL_CONTENT_ENCODING_UNSUPPORTED");
            return;
        }
        chain.doFilter(new BoundedRequest(request), response);
    }

    static final class RequestBodyTooLargeException extends IOException {
        private static final long serialVersionUID = 1L;

        RequestBodyTooLargeException() {
            super("CONTROL_REQUEST_BODY_TOO_LARGE");
        }
    }

    private static final class BoundedRequest extends HttpServletRequestWrapper {
        private ServletInputStream input;
        private BufferedReader reader;

        BoundedRequest(HttpServletRequest request) {
            super(request);
        }

        @Override
        public ServletInputStream getInputStream() throws IOException {
            if (reader != null) {
                throw new IllegalStateException("getReader() has already been called");
            }
            if (input == null) {
                input = new BoundedInputStream(super.getInputStream());
            }
            return input;
        }

        @Override
        public BufferedReader getReader() throws IOException {
            if (input != null) {
                throw new IllegalStateException("getInputStream() has already been called");
            }
            if (reader == null) {
                input = new BoundedInputStream(super.getInputStream());
                reader = new BufferedReader(new InputStreamReader(input,
                    getCharacterEncoding() == null ? StandardCharsets.UTF_8
                        : java.nio.charset.Charset.forName(getCharacterEncoding())));
            }
            return reader;
        }
    }

    static final class BoundedInputStream extends ServletInputStream {
        private final ServletInputStream delegate;
        private long consumed;

        BoundedInputStream(ServletInputStream delegate) {
            this.delegate = delegate;
        }

        @Override
        public int read() throws IOException {
            int value = delegate.read();
            if (value >= 0 && ++consumed > MAXIMUM_REQUEST_BODY_BYTES) {
                throw new RequestBodyTooLargeException();
            }
            return value;
        }

        @Override
        public int read(byte[] buffer, int offset, int length) throws IOException {
            if (length == 0) {
                return 0;
            }
            long permitted = MAXIMUM_REQUEST_BODY_BYTES - consumed + 1;
            int bounded = (int) Math.min(length, Math.max(1L, permitted));
            int count = delegate.read(buffer, offset, bounded);
            if (count > 0 && (consumed += count) > MAXIMUM_REQUEST_BODY_BYTES) {
                throw new RequestBodyTooLargeException();
            }
            return count;
        }

        @Override
        public boolean isFinished() {
            return delegate.isFinished();
        }

        @Override
        public boolean isReady() {
            return delegate.isReady();
        }

        @Override
        public void setReadListener(ReadListener listener) {
            delegate.setReadListener(listener);
        }

        @Override
        public void close() throws IOException {
            delegate.close();
        }
    }
}
