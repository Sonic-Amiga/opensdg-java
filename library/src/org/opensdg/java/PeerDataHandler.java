package org.opensdg.java;

import static org.opensdg.protocol.Forward.*;

import java.io.IOException;
import java.io.InputStream;
import java.net.ProtocolException;
import java.nio.ByteBuffer;
import java.rmi.RemoteException;
import java.util.concurrent.ExecutionException;

import org.opensdg.java.Connection.ReadResult;
import org.opensdg.protocol.Forward.ForwardError;
import org.opensdg.protocol.Forward.ForwardReply;
import org.opensdg.protocol.Tunnel.REDYPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PeerDataHandler extends DataHandler {
    private final Logger logger = LoggerFactory.getLogger(PeerDataHandler.class);

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

    ReadResult handleFwdPacket(ByteBuffer buffer) throws IOException {
        // Forwarding protocol isn't encapsulated, handle it first
        byte cmd = buffer.get(2);

        switch (cmd) {
            case MSG_FORWARD_HOLD:
                // Sometimes before MSG_FORWARD_REPLY a three byte packet arrives,
                // containing MSG_FORWARD_HOLD command. Ignore it. I don't know what this
                // is for; the name comes from LUA source code for old version of mdglib
                // found in DanfossLink application by Christian Christiansen. Huge
                // thanks for his reverse engineering effort!!!
                logger.trace("Received packet: FORWARD_HOLD");
                return ReadResult.CONTINUE;

            case MSG_FORWARD_REPLY:
                ForwardReply reply = new ForwardReply(buffer);
                logger.trace("Received packet: {}", reply);
                return ReadResult.DONE;

            case MSG_FORWARD_ERROR:
                ForwardError fwdErr = new ForwardError(buffer);
                logger.trace("Received packet: {}", fwdErr);
                throw new RemoteException("Connection refused by peer: " + fwdErr.getCode());

            default:
                throw new ProtocolException("Unknown forwarding packet received: " + cmd);
        }
    }

    @Override
    void handleREDY(REDYPacket pkt) throws IOException, InterruptedException, ExecutionException {
        // REDY packet from a device contains its built-in license key
        // in the same format as in VOCH packet, sent by us.
        // Being an opensource project we simply don't care about it.
        connection.setState(Connection.State.CONNECTED);
    }

    @Override
    void handleMESG(InputStream data) throws IOException, InterruptedException, ExecutionException {
        // TODO Auto-generated method stub
        logger.info("Async read: {} bytes", data.available());
    }

}
