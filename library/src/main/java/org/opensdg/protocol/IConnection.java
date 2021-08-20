package org.opensdg.protocol;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

/**
 * This class is a glue, whose only purpose is to provide ability to call
 * certain methods of public Connection class from within "protocol"
 * package without making them public
 *
 * @author Pavel Fedin
 */
public abstract class IConnection {
    /**
     * Synchronously send a raw data buffer
     *
     * Keeps writing synchronously until the full packet has been written
     * This is an internal function, not for public use!
     *
     * @param data the data to send
     * @throws ExecutionException if the underlying write operation threw an exception
     * @throws InterruptedException if the current thread was interrupted
     * @throws TimeoutException if the operation has timed out
     * @throws IOException
     *
     */
    protected abstract void doSendRawData(ByteBuffer data)
            throws InterruptedException, ExecutionException, TimeoutException, IOException;

    /**
     * Receive raw data synchronously
     *
     * This is an internal function, not for public use!
     *
     * @param buffer {@link ByteBuffer} to put the data to
     * @return Number of bytes read
     * @throws ExecutionException if the underlying write operation threw an exception
     * @throws InterruptedException if the current thread was interrupted
     * @throws TimeoutException if the operation has timed out
     */
    protected abstract int doSyncReceive(ByteBuffer buffer)
            throws InterruptedException, ExecutionException, TimeoutException;

    /**
     * Handle "Protocol ready" packet
     *
     * This is an internal function, not for public use!
     *
     * @throws IOException if packet decoding fails
     * @throws ExecutionException if the response write operation threw an exception
     * @throws InterruptedException if the current thread was interrupted
     * @throws TimeoutException if the operation has timed out
     */
    protected abstract void onReadyPacket()
            throws IOException, InterruptedException, ExecutionException, TimeoutException;

    /**
     * Handle incoming data packet
     *
     * Internal function, do not use!
     *
     * @param data InputStream, containing the received data
     * @throws IOException if packet decoding fails
     * @throws ExecutionException if the response write operation threw an exception
     * @throws InterruptedException if the current thread was interrupted
     * @throws TimeoutException if the operation has timed out
     */
    protected abstract void onDataPacket(InputStream data)
            throws IOException, InterruptedException, ExecutionException, TimeoutException;

    void sendRawData(ByteBuffer data) throws InterruptedException, ExecutionException, TimeoutException, IOException {
        doSendRawData(data);
    }

    int syncReceive(ByteBuffer buffer) throws InterruptedException, ExecutionException, TimeoutException {
        return doSyncReceive(buffer);
    }

    void handleReadyPacket() throws IOException, InterruptedException, ExecutionException, TimeoutException {
        onReadyPacket();
    }

    void handleDataPacket(InputStream data)
            throws IOException, InterruptedException, ExecutionException, TimeoutException {
        onDataPacket(data);
    }
}
