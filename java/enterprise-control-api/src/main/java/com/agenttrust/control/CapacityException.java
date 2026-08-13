package com.agenttrust.control;

final class CapacityException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    CapacityException(String code) {
        super(code);
    }
}
