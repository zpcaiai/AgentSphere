package com.agenttrust.control;

import java.time.Instant;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingRequestHeaderException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
final class ApiErrors {
    record ErrorBody(String schemaVersion, String code, String traceId, Instant occurredAt) {}

    @ExceptionHandler(ControlDeniedException.class)
    ResponseEntity<ErrorBody> denied(ControlDeniedException error) {
        return response(HttpStatus.FORBIDDEN, error.getMessage());
    }

    @ExceptionHandler(ConflictException.class)
    ResponseEntity<ErrorBody> conflict(ConflictException error) {
        return response(HttpStatus.CONFLICT, error.getMessage());
    }

    @ExceptionHandler(CapacityException.class)
    ResponseEntity<ErrorBody> capacity(CapacityException error) {
        return response(HttpStatus.TOO_MANY_REQUESTS, error.getMessage());
    }

    @ExceptionHandler(ControlUnavailableException.class)
    ResponseEntity<ErrorBody> unavailable(ControlUnavailableException error) {
        return response(HttpStatus.SERVICE_UNAVAILABLE, error.getMessage());
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    ResponseEntity<ErrorBody> unreadable(HttpMessageNotReadableException error) {
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
    ResponseEntity<ErrorBody> invalidRequest(Exception ignored) {
        return response(HttpStatus.BAD_REQUEST, "CONTROL_REQUEST_INVALID");
    }

    @ExceptionHandler(Exception.class)
    ResponseEntity<ErrorBody> unexpected(Exception ignored) {
        return response(HttpStatus.INTERNAL_SERVER_ERROR, "CONTROL_INTERNAL_ERROR");
    }

    private static ResponseEntity<ErrorBody> response(HttpStatus status, String code) {
        String trace = UUID.randomUUID().toString();
        return ResponseEntity.status(status).header("X-Trace-Id", trace)
            .body(new ErrorBody("agenttrust.safe-error.v1", code, trace, Instant.now()));
    }
}
