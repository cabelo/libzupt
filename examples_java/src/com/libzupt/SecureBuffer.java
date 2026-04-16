package com.libzupt;

import java.util.Arrays;

/**
 * Secure buffer for sensitive data.
 * The buffer is zeroized when closed or garbage collected.
 */
public class SecureBuffer implements AutoCloseable {
    private byte[] data;

    /**
     * Create a new secure buffer of specified size.
     * @param size the size of the buffer
     */
    public SecureBuffer(int size) {
        this.data = new byte[size];
    }

    /**
     * Create a secure buffer from existing data.
     * The data is copied to prevent external modification.
     * @param data the data to store
     */
    public SecureBuffer(byte[] data) {
        if (data != null) {
            this.data = Arrays.copyOf(data, data.length);
        } else {
            this.data = new byte[0];
        }
    }

    /**
     * Get the buffer size.
     * @return the size in bytes
     */
    public int size() {
        return data != null ? data.length : 0;
    }

    /**
     * Get the buffer content.
     * @return a copy of the buffer data
     */
    public byte[] toBytes() {
        return data != null ? Arrays.copyOf(data, data.length) : new byte[0];
    }

    /**
     * Get the buffer content as string (use with caution for sensitive data).
     * @return string representation
     */
    public String toString() {
        return data != null ? new String(data) : "";
    }

    /**
     * Securely wipe the buffer content.
     */
    public void zeroize() {
        if (data != null) {
            Arrays.fill(data, (byte) 0);
        }
    }

    @Override
    public void close() {
        zeroize();
    }

    //@Override
    //protected void finalize() throws Throwable {
    //    try {
    //        zeroize();
    //    } finally {
    //        super.finalize();
    //    }
    //}
}
