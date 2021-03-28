package org.opensdg.protocol;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.concurrent.ExecutionException;

import org.opensdg.java.Connection;
import org.opensdg.java.Connection.ReadResult;

/**
 * This is a base class for all the "raw" socket protocols
 *
 * This particular class deals with receiving raw packets
 *
 * @author Pavel Fedin
 */
public abstract class SocketProtocol {
    protected Connection connection;

    private ByteBuffer receiveBuffer = null;
    private short bytesLeft = 0;
    private int bytesReceived = 0;

    public SocketProtocol(Connection conn) {
        connection = conn;
    }

    /**
     * Synchronously receive a raw packet into buffer
     *
     * Keeps reading synchronously until the full packet has been read
     * or EOF reached
     *
     */
    public ReadResult receiveRawPacket() throws IOException, InterruptedException, ExecutionException {
        ReadResult ret;

        do {
            int size = connection.syncReceive(getBuffer());

            ret = onRawDataReceived(size);
        } while (ret == ReadResult.CONTINUE);

        return ret;
    }

    /**
     * Handle receiving raw data
     *
     * Advances current read buffer pointer, performing reallocation when needed
     *
     * @param size Number of bytes received
     */
    public ReadResult onRawDataReceived(int size) throws IOException, InterruptedException, ExecutionException {
        if (size == -1) {
            return ReadResult.EOF;
        }

        bytesReceived += size;
        bytesLeft -= size;

        if (bytesLeft > 0) {
            return ReadResult.CONTINUE;
        }

        if (bytesReceived == 2) { // Received 2 bytes, length of the buffer
            receiveBuffer.order(ByteOrder.BIG_ENDIAN);
            // Data size is bigendian
            bytesLeft = receiveBuffer.getShort(0);

            // Reallocate our buffer with the new size
            receiveBuffer = ByteBuffer.allocate(2 + bytesLeft);
            receiveBuffer.putShort(bytesLeft);

            return ReadResult.CONTINUE;
        }

        return ReadResult.DONE;
    }

    public ByteBuffer getBuffer() {
        if (receiveBuffer == null) {
            // Start receiving a new packet.
            // Every packet is prefixed with length, read it first
            receiveBuffer = ByteBuffer.allocate(2);
            bytesReceived = 0;
            bytesLeft = 2;
        }

        return receiveBuffer;
    }

    protected ByteBuffer detachBuffer() {
        ByteBuffer buffer = receiveBuffer;

        receiveBuffer = null;
        return buffer;
    }

    public ReadResult establish() throws IOException, InterruptedException, ExecutionException {

        ReadResult ret;

        do {
            ret = receiveRawPacket();

            if (ret != ReadResult.EOF) {
                ret = onPacketReceived();
            }
        } while (ret != ReadResult.DONE);

        return ret;
    }

    public ReadResult onPacketReceived() throws IOException, InterruptedException, ExecutionException {
        return onPacketReceived(detachBuffer());
    }

    /**
     * Parse an incoming raw packet
     *
     * Inteprprets packet's contents and replies when needed.
     * For MESG packet payload will be retrieved and returned.
     *
     * @return Data to be passed over to the client or null if there's no one
     */
    abstract ReadResult onPacketReceived(ByteBuffer data) throws IOException, InterruptedException, ExecutionException;
}
