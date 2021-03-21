package org.opensdg.java;

import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.ExecutionException;

import org.opensdg.protocol.Tunnel.REDYPacket;

public abstract class DataHandler {
    protected Connection connection;

    protected DataHandler(Connection conn) {
        connection = conn;
    }

    abstract void handleREDY(REDYPacket pkt) throws IOException, InterruptedException, ExecutionException;

    abstract void handleMESG(InputStream pkt) throws IOException, InterruptedException, ExecutionException;

    ForwardRequest connectToPeer(byte[] peerId, String protocol) {
        throw new IllegalArgumentException("Connection is not a Grid");
    }

    void handleClose() {
        // Nothing to do by default
    }
}
