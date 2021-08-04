package org.opensdg.protocol;

import java.io.IOException;
import java.io.InputStream;
import java.net.ProtocolException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

import org.opensdg.java.Connection;

/**
 * This is a base class for socket encryption protocols.
 *
 * It adds identification properties and data I/O functions.
 *
 * @author Pavel Fedin
 */
public abstract class EncryptedSocket extends SocketProtocol {

    public EncryptedSocket(Connection conn) {
        super(conn);
    }

    /**
     * Make another EncryptedSocket, inheriting credentials from this one
     *
     * @param conn a {@link Connection} to service
     * @return a new EncryptedSocket instance
     */
    abstract public EncryptedSocket makePeerTunnel(Connection conn);

    /**
     * Send data over the encrypted channel
     *
     * @param data Data to send
     * @throws IOException if protocol fails
     * @throws ExecutionException if the underlying I/O threw an exception
     * @throws InterruptedException if the current thread was interrupted
     * @throws TimeoutException if the operation has timed out
     */
    abstract public void sendData(byte[] data)
            throws IOException, InterruptedException, ExecutionException, TimeoutException;

    /**
     * Get received data
     *
     * @return Decrypted received data
     * @throws ProtocolException if data decryption fails
     */
    abstract public InputStream getData() throws ProtocolException;

    // These may be not appropriate for different protocols, but i don't know
    // what to do with these yet. Let them stick here this way for now.
    public byte[] getPeerId() {
        return null;
    }

    public byte[] getMyPeerId() {
        return null;
    }

    public byte[] getBeforeNm() {
        return null;
    }
}
