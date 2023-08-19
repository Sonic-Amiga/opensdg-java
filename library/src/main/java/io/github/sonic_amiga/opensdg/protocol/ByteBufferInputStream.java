package io.github.sonic_amiga.opensdg.protocol;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

//Huge thanks to Stack Overflow for this code
class ByteBufferInputStream extends InputStream {
    private ByteBuffer buf;

    public ByteBufferInputStream(ByteBuffer buf) {
        this.buf = buf;
    }

    @Override
    public int read() throws IOException {
        if (!buf.hasRemaining()) {
            return -1;
        }
        return buf.get() & 0xFF;
    }

    @Override
    public int read(byte[] bytes, int off, int len) throws IOException {
        if (!buf.hasRemaining()) {
            return -1;
        }

        int res = Math.min(len, buf.remaining());

        buf.get(bytes, off, res);
        return res;
    }
}
