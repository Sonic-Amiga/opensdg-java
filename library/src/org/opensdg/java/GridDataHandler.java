package org.opensdg.java;

import org.opensdg.protocol.Tunnel.MESGPacket;
import org.opensdg.protocol.Tunnel.REDYPacket;

public class GridDataHandler extends DataHandler {
    GridDataHandler(Connection conn) {
        super(conn);
    }

    @Override
    int handleREDY(REDYPacket pkt) {
        // REDY payload from DEVISmart cloud is empty, nothing to do with it
        return 1;
    }

    @Override
    int handleMESG(MESGPacket pkt) {
        // TODO Auto-generated method stub
        return 0;
    }

}
