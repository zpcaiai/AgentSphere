package com.agenttrust.control;

public final class ControlUnavailableException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public ControlUnavailableException(String code) { super(code); }
    public ControlUnavailableException(String code, Throwable cause) { super(code, cause); }
}
