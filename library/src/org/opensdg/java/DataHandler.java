package org.opensdg.java;

import org.opensdg.protocol.Tunnel.MESGPacket;
import org.opensdg.protocol.Tunnel.REDYPacket;

public abstract class DataHandler {
    protected Connection connection;

    protected DataHandler(Connection conn) {
        connection = conn;
    }

    abstract int handleREDY(REDYPacket pkt);

    abstract int handleMESG(MESGPacket pkt);
}
