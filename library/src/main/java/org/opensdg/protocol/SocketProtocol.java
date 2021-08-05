package org.opensdg.protocol;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

import org.opensdg.java.Connection.ReadResult;

/**
 * This is a base class for all the "raw" socket protocols
 *
 * This particular class deals with receiving raw packets
 *
 * @author Pavel Fedin
 */
public abstract class SocketProtocol {
    protected IConnection connection;

    private ByteBuffer receiveBuffer = null;
    private short bytesLeft = 0;
    private int bytesReceived = 0;

    public SocketProtocol(IConnection conn) {
        connection = conn;
    }

    /**
     * Synchronously receive a raw packet into buffer
     *
     * Keeps reading synchronously until the full packet has been read
     * or EOF reached
     *
     * @return Result code
     * @throws IOException if packet decoding fails
     * @throws ExecutionException if the underlying I/O threw an exception
     * @throws InterruptedException if the current thread was interrupted
     * @throws TimeoutException if the operation has timed out
     */
    public ReadResult receiveRawPacket()
            throws IOException, InterruptedException, ExecutionException, TimeoutException {
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
     * @return Result code
     */
    public ReadResult onRawDataReceived(int size) {
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
            receiveBuffer = ByteBuffer.allocateDirect(2 + bytesLeft);
            receiveBuffer.putShort(bytesLeft);

            return ReadResult.CONTINUE;
        }

        return ReadResult.DONE;
    }

    public ByteBuffer getBuffer() {
        if (receiveBuffer == null) {
            // Start receiving a new packet.
            // Every packet is prefixed with length, read it first
            receiveBuffer = ByteBuffer.allocateDirect(2);
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

    /**
     * Synchronously establish this protocol
     *
     * Performs all the necessary handshake until it finishes
     *
     * @return Result code
     * @throws IOException if protocol fails
     * @throws ExecutionException if the underlying I/O threw an exception
     * @throws InterruptedException if the current thread was interrupted
     * @throws TimeoutException if the operation has timed out
     */
    public ReadResult establish() throws IOException, InterruptedException, ExecutionException, TimeoutException {

        ReadResult ret;

        do {
            ret = receiveRawPacket();

            if (ret != ReadResult.EOF) {
                ret = onPacketReceived();
            }
        } while (ret != ReadResult.DONE);

        return ret;
    }

    public ReadResult onPacketReceived()
            throws IOException, InterruptedException, ExecutionException, TimeoutException {
        return onPacketReceived(detachBuffer());
    }

    /**
     * Parse an incoming raw packet
     *
     * Inteprprets packet's contents and replies when needed.
     * For MESG packet payload will be retrieved and returned.
     *
     * @param data Received raw data
     * @return Data to be passed over to the client or null if there's no one
     * @throws IOException if packet deconfing fails
     * @throws ExecutionException if the response write threw an exception
     * @throws InterruptedException if the current thread was interrupted
     * @throws TimeoutException if the operation has timed out
     */
    abstract protected ReadResult onPacketReceived(ByteBuffer data)
            throws IOException, InterruptedException, ExecutionException, TimeoutException;
}
