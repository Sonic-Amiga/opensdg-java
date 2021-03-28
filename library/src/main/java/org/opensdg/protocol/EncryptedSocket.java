package org.opensdg.protocol;

import java.io.IOException;
import java.io.InputStream;
import java.net.ProtocolException;
import java.util.concurrent.ExecutionException;

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

    @Override
    abstract public EncryptedSocket makePeerTunnel(Connection conn);

    abstract public void sendData(byte[] data)
            throws ProtocolException, IOException, InterruptedException, ExecutionException;

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
