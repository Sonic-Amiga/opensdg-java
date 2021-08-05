package org.opensdg.protocol;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;

// Huge thanks to Stack Overflow for this code
class ByteBufferOutputStream extends OutputStream {
    private ByteBuffer buf;

    public ByteBufferOutputStream(ByteBuffer buf) {
        this.buf = buf;
    }

    @Override
    public void write(int b) throws IOException {
        buf.put((byte) b);
    }

    @Override
    public void write(byte[] bytes, int off, int len) throws IOException {
        buf.put(bytes, off, len);
    }
}
