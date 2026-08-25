package com.agenttrust.control;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

final class SafeErrorTestSupport {
    private SafeErrorTestSupport() {}

    static HttpServletRequest request(String path, long contentLength, String contentEncoding) {
        InvocationHandler handler = (proxy, method, arguments) -> switch (method.getName()) {
            case "getRequestURI", "getServletPath" -> path;
            case "getContextPath" -> "";
            case "getMethod" -> "POST";
            case "getContentLengthLong" -> contentLength;
            case "getContentLength" -> contentLength > Integer.MAX_VALUE
                ? -1 : (int) contentLength;
            case "getHeader" -> "Content-Encoding".equals(arguments[0])
                ? contentEncoding : null;
            case "getInputStream" -> input(new byte[0]);
            case "toString" -> "HttpServletRequest[" + path + "]";
            case "hashCode" -> System.identityHashCode(proxy);
            case "equals" -> proxy == arguments[0];
            default -> defaultValue(method.getReturnType());
        };
        return (HttpServletRequest) Proxy.newProxyInstance(
            HttpServletRequest.class.getClassLoader(),
            new Class<?>[] {HttpServletRequest.class}, handler);
    }

    static ServletInputStream input(byte[] body) {
        var bytes = new ByteArrayInputStream(body);
        return new ServletInputStream() {
            @Override public int read() { return bytes.read(); }
            @Override public boolean isFinished() { return bytes.available() == 0; }
            @Override public boolean isReady() { return true; }
            @Override public void setReadListener(ReadListener listener) { /* synchronous */ }
        };
    }

    static final class ResponseCapture implements InvocationHandler {
        private final ByteArrayOutputStream body = new ByteArrayOutputStream();
        private final Map<String, String> headers = new LinkedHashMap<>();
        private final HttpServletResponse response;
        private int status;
        private String contentType;
        private int contentLength = -1;

        ResponseCapture() {
            response = (HttpServletResponse) Proxy.newProxyInstance(
                HttpServletResponse.class.getClassLoader(),
                new Class<?>[] {HttpServletResponse.class}, this);
        }

        HttpServletResponse response() {
            return response;
        }

        int status() {
            return status;
        }

        String contentType() {
            return contentType;
        }

        String header(String name) {
            return headers.get(name);
        }

        int contentLength() {
            return contentLength;
        }

        byte[] body() {
            return body.toByteArray();
        }

        String bodyText() {
            return body.toString(StandardCharsets.UTF_8);
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] arguments) {
            return switch (method.getName()) {
                case "setStatus" -> {
                    status = (int) arguments[0];
                    yield null;
                }
                case "getStatus" -> status;
                case "setContentType" -> {
                    contentType = (String) arguments[0];
                    yield null;
                }
                case "getContentType" -> contentType;
                case "setHeader", "addHeader" -> {
                    headers.put((String) arguments[0], (String) arguments[1]);
                    yield null;
                }
                case "getHeader" -> headers.get((String) arguments[0]);
                case "setContentLength" -> {
                    contentLength = (int) arguments[0];
                    yield null;
                }
                case "getOutputStream" -> output(body);
                case "isCommitted" -> false;
                case "toString" -> "HttpServletResponse[" + status + "]";
                case "hashCode" -> System.identityHashCode(proxy);
                case "equals" -> proxy == arguments[0];
                default -> defaultValue(method.getReturnType());
            };
        }
    }

    private static ServletOutputStream output(ByteArrayOutputStream target) {
        return new ServletOutputStream() {
            @Override public void write(int value) { target.write(value); }
            @Override public boolean isReady() { return true; }
            @Override public void setWriteListener(WriteListener listener) { /* synchronous */ }
        };
    }

    private static Object defaultValue(Class<?> type) {
        if (!type.isPrimitive()) {
            return null;
        }
        if (type == boolean.class) {
            return false;
        }
        if (type == byte.class) {
            return (byte) 0;
        }
        if (type == short.class) {
            return (short) 0;
        }
        if (type == int.class) {
            return 0;
        }
        if (type == long.class) {
            return 0L;
        }
        if (type == float.class) {
            return 0.0F;
        }
        if (type == double.class) {
            return 0.0D;
        }
        if (type == char.class) {
            return '\0';
        }
        throw new IllegalArgumentException("unsupported primitive type");
    }
}
