package org.opensdg.java;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousCloseException;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.util.concurrent.ExecutionException;

import org.eclipse.jdt.annotation.NonNull;
import org.eclipse.jdt.annotation.Nullable;
import org.opensdg.protocol.EncryptedSocket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class represents a single connection over the Grid.
 *
 * A Connection is an encrypted channel, using asymmetric encryption
 * based on public and private keys. A public key is also known as a
 * peer ID; it's used to identify the peer on a network.
 *
 * In order to establish a connection to a remote host over the Grid,
 * you need a {@link PeerConnection} to perform the actual communication
 * and a {@link GridConnection}, representing a particular Grid which the
 * given peer is on.
 *
 * @author Pavel Fedin
 */
public abstract class Connection {
    private final Logger logger = LoggerFactory.getLogger(Connection.class);

    private static class ReadHandler implements CompletionHandler<Integer, Connection> {
        @Override
        public void completed(Integer result, Connection conn) {
            try {
                ReadResult ret = conn.tunnel.onRawDataReceived(result);

                switch (ret) {
                    case EOF:
                        conn.handleError(getEOFException());
                        return;
                    case DONE:
                        conn.tunnel.onPacketReceived();
                        break;
                    case CONTINUE:
                        break;

                }
                // Continue receiving
                conn.asyncReceive();
            } catch (IOException | InterruptedException | ExecutionException e) {
                conn.handleError(e);
            }
        }

        @Override
        public void failed(Throwable exc, Connection conn) {
            conn.handleError(exc);
        }
    }

    public enum State {
        CLOSED,
        CONNECTING,
        CONNECTED
    }

    public enum ReadResult {
        CONTINUE,
        EOF,
        DONE
    }

    protected static EOFException getEOFException() {
        return new EOFException("Connection closed by peer");
    }

    protected State state = State.CLOSED;

    private AsynchronousSocketChannel s;
    protected EncryptedSocket tunnel;

    private CompletionHandler<Integer, Connection> readHandler = new ReadHandler();

    protected void openSocket(String host, int port) throws IOException, InterruptedException, ExecutionException {
        s = AsynchronousSocketChannel.open();
        s.connect(new InetSocketAddress(host, port)).get();
        logger.debug("Connected to {}:{}", host, port);
    }

    /**
     * Close the connection
     *
     * For convenience it's allowed to call close() on an already closed
     * connection, it will do nothing. A closed {@link Connection} object can be reused.
     *
     */
    public void close() throws IOException {
        if (state == State.CLOSED) {
            return;
        }

        AsynchronousSocketChannel ch = s;
        s = null;

        if (ch != null) {
            ch.close();
        }

        state = State.CLOSED;
    }

    /**
     * Synchronously send a raw data buffer
     *
     * Keeps writing synchronously until the full packet has been written
     *
     */
    public synchronized void sendRawData(ByteBuffer data) throws InterruptedException, ExecutionException {
        int size = data.capacity();

        data.position(0);

        while (size > 0) {
            int ret = s.write(data).get();
            size -= ret;
        }
    }

    /**
     * Start asynchronous data receiving
     *
     * Initiates asynchronous data handling on the Connection.
     * {@link handleReadyPacket}, {@link handleDataPacket} or {@link onError} will be called accordingly
     *
     */
    protected void asyncReceive() {
        s.read(tunnel.getBuffer(), this, readHandler);
    }

    /**
     * Receive raw data synchronously
     *
     * Internal function, do not use!
     *
     */
    public int syncReceive(ByteBuffer buffer) throws InterruptedException, ExecutionException {
        return s.read(buffer).get();
    }

    /**
     * Handle "Protocol ready" packet
     *
     * Internal function, do not use!
     *
     */
    public abstract void handleReadyPacket() throws IOException, InterruptedException, ExecutionException;

    /**
     * Handle incoming data packet
     *
     * Internal function, do not use!
     *
     */
    public abstract void handleDataPacket(InputStream data)
            throws IOException, InterruptedException, ExecutionException;

    /**
     * This function is called if internal processing fails.
     * E. g. failed to respond to a packet. It takes care about internal normal events,
     * like asynchronous close.
     *
     */
    protected void handleError(Throwable exc) {
        if (exc instanceof AsynchronousCloseException) {
            // This is not really an error, just someone has called close()
            // during pending read
            logger.debug("Async channel closed");
        } else {
            onError(exc);
        }
    }

    protected void checkState(State required) {
        if (state != required) {
            throw new IllegalStateException(
                    "Bad Connection state " + state + " for the call; required state " + required);
        }
    }

    /**
     * Gets current state of this Connection
     *
     * @return {@link State} value
     */
    public @NonNull State getState() {
        return state;
    }

    /**
     * Called when an error happens during asynchronous reading
     *
     * @param exc an error description
     */
    protected void onError(@NonNull Throwable exc) {
        // It's strongly advised to handle these events, so let's log under error
        // if the developer forgot to do so.
        logger.error("Unhandled async I/O error:", exc);
    }

    /**
     * Gets current peer ID for this connection. PeerID is also known as
     * peer's public key.
     *
     * @return peer ID
     */
    public byte @Nullable [] getPeerId() {
        return tunnel.getPeerId();
    }

    /**
     * Gets our own peer ID (AKA public key) for this connection.
     *
     * For {@link GridConnection} this peer ID is calculated from the private key.
     * For other {@link Connection} types it is inherited from {@link GridConnection}
     * that was used in order to establish it.
     *
     * @return peer ID
     */
    public byte @Nullable [] getMyPeerId() {
        return tunnel.getMyPeerId();
    }
}
