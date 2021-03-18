package org.opensdg.java;

import java.io.IOException;
import java.util.concurrent.ExecutionException;

import org.opensdg.protocol.Tunnel.MESGPacket;
import org.opensdg.protocol.Tunnel.REDYPacket;

public class PeerDataHandler extends DataHandler {

    private int discardFirstBytes = 0;

    protected PeerDataHandler(Connection conn, String protocol) {
        super(conn);

        /*
         * DEVISmart thermostat has a quirk: very first packet is prefixed with
         * a garbage byte, which has to be skipped.
         * Apparently this is some buffering bug, which seems to have become a
         * part of the protocol spec ;) The original DEVISmart app implements
         * exactly this king of a logic in order to discard this byte: just remember
         * the fact that the connection is new.
         * Icon uses the same protocol with the same name and the same quirk, so it's
         * not even application-specific.
         * Here we are generalizing this solution to "discard first N bytes", just
         * in case. If there are more susceptible peers, they need to be listed here
         * in order to prevent application writers from implementing the workaround
         * over and over again.
         */
        if (protocol.equals("dominion-1.0")) {
            discardFirstBytes = 1;
        }
    }

    @Override
    int handleREDY(REDYPacket pkt) throws IOException, InterruptedException, ExecutionException {
        // TODO Auto-generated method stub
        return 0;
    }

    @Override
    int handleMESG(MESGPacket pkt) throws IOException, InterruptedException, ExecutionException {
        // TODO Auto-generated method stub
        return 0;
    }

}
