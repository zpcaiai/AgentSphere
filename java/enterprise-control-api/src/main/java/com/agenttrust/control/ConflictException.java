package com.agenttrust.control;

final class ConflictException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    ConflictException(String code) {
        super(code);
    }
}
