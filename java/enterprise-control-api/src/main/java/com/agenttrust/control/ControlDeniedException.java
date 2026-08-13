package com.agenttrust.control;

final class ControlDeniedException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    ControlDeniedException(String code) {
        super(code);
    }

    ControlDeniedException(String code, Throwable cause) {
        super(code, cause);
    }
}
