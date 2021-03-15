package org.opensdg.java;

import java.io.IOException;
import java.util.concurrent.ExecutionException;

import org.opensdg.protocol.Tunnel.MESGPacket;
import org.opensdg.protocol.Tunnel.REDYPacket;

public abstract class DataHandler {
    protected Connection connection;

    protected DataHandler(Connection conn) {
        connection = conn;
    }

    abstract int handleREDY(REDYPacket pkt) throws IOException, InterruptedException, ExecutionException;

    abstract int handleMESG(MESGPacket pkt) throws IOException, InterruptedException, ExecutionException;
}
