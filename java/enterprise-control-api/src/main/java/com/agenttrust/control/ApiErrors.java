package com.agenttrust.control;

import java.time.Instant;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingRequestHeaderException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
final class ApiErrors {
    @ExceptionHandler(ControlDeniedException.class)
    ResponseEntity<SafeErrorBody> denied(ControlDeniedException error) {
        return response(HttpStatus.FORBIDDEN, error.getMessage());
    }

    @ExceptionHandler(ConflictException.class)
    ResponseEntity<SafeErrorBody> conflict(ConflictException error) {
        return response(HttpStatus.CONFLICT, error.getMessage());
    }

    @ExceptionHandler(CapacityException.class)
    ResponseEntity<SafeErrorBody> capacity(CapacityException error) {
        return response(HttpStatus.TOO_MANY_REQUESTS, error.getMessage());
    }

    @ExceptionHandler(ControlUnavailableException.class)
    ResponseEntity<SafeErrorBody> unavailable(ControlUnavailableException error) {
        return response(HttpStatus.SERVICE_UNAVAILABLE, error.getMessage());
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    ResponseEntity<SafeErrorBody> unreadable(HttpMessageNotReadableException error) {
        Throwable current = error;
        while (current != null) {
            if (current instanceof RequestBodyLimitFilter.RequestBodyTooLargeException) {
                return response(HttpStatus.PAYLOAD_TOO_LARGE, "CONTROL_REQUEST_BODY_TOO_LARGE");
            }
            current = current.getCause();
        }
        return response(HttpStatus.BAD_REQUEST, "CONTROL_REQUEST_INVALID");
    }

    @ExceptionHandler({MethodArgumentNotValidException.class,
        MissingRequestHeaderException.class, MethodArgumentTypeMismatchException.class})
    ResponseEntity<SafeErrorBody> invalidRequest(Exception ignored) {
        return response(HttpStatus.BAD_REQUEST, "CONTROL_REQUEST_INVALID");
    }

    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    ResponseEntity<SafeErrorBody> unsupportedMediaType(
        HttpMediaTypeNotSupportedException ignored) {
        return response(HttpStatus.UNSUPPORTED_MEDIA_TYPE, "CONTROL_UNSUPPORTED_MEDIA_TYPE");
    }

    @ExceptionHandler(Exception.class)
    ResponseEntity<SafeErrorBody> unexpected(Exception ignored) {
        return response(HttpStatus.INTERNAL_SERVER_ERROR, "CONTROL_INTERNAL_ERROR");
    }

    private static ResponseEntity<SafeErrorBody> response(HttpStatus status, String code) {
        String trace = UUID.randomUUID().toString();
        String safeCode = SafeErrorBody.validCode(code) ? code : "CONTROL_INTERNAL_ERROR";
        return ResponseEntity.status(status).contentType(MediaType.APPLICATION_JSON)
            .header("X-Trace-Id", trace)
            .header("Cache-Control", "no-store")
            .body(new SafeErrorBody(
                SafeErrorBody.SCHEMA_VERSION, safeCode, trace, Instant.now().toString()));
    }
}
