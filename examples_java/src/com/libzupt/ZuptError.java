package com.libzupt;

/**
 * Zupt exception class.
 * Thrown when libzupt encounters an error.
 */
public class ZuptError extends RuntimeException {
    private final int errorCode;

    public ZuptError(int errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public ZuptError(String message) {
        super(message);
        this.errorCode = 0;
    }

    public int getErrorCode() {
        return errorCode;
    }
}