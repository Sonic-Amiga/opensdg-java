package org.opensdg.java;

import java.io.IOException;

import org.opensdg.protocol.Tunnel.MESGPacket;
import org.opensdg.protocol.Tunnel.REDYPacket;

public abstract class DataHandler {
    protected Connection connection;

    protected DataHandler(Connection conn) {
        connection = conn;
    }

    abstract int handleREDY(REDYPacket pkt) throws IOException;

    abstract int handleMESG(MESGPacket pkt) throws IOException;
}
