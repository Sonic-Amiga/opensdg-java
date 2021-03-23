package org.opensdg.java;

import static org.opensdg.protocol.Forward.*;

import java.io.IOException;
import java.io.InputStream;
import java.net.ProtocolException;
import java.nio.ByteBuffer;
import java.rmi.RemoteException;
import java.util.concurrent.ExecutionException;

import javax.xml.bind.DatatypeConverter;

import org.eclipse.jdt.annotation.Nullable;
import org.opensdg.protocol.Forward;
import org.opensdg.protocol.Forward.ForwardError;
import org.opensdg.protocol.Forward.ForwardReply;
import org.opensdg.protocol.Forward.ForwardRequest;
import org.opensdg.protocol.Tunnel.MESGPacket;
import org.opensdg.protocol.Tunnel.REDYPacket;
import org.opensdg.protocol.generated.ControlProtocol.PeerInfo;
import org.opensdg.protocol.generated.ControlProtocol.PeerReply;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.protobuf.ByteString;

/**
 * A {@link Connection} to be used to connect to a remote peer over the Grid cloud
 *
 * @author Pavel Fedin
 */
public class PeerConnection extends Connection {
    private final Logger logger = LoggerFactory.getLogger(PeerConnection.class);

    private int discardFirstBytes;

    /**
     * Connects to a remote peer
     *
     * @param grid master connection to use
     * @param peerId ID (AKA public key) of the peer to call
     * @param protocol application-specific protocol ID
     */
    public void connectToRemote(GridConnection grid, byte[] peerId, String protocol)
            throws IOException, InterruptedException, ExecutionException {
        checkState(State.CLOSED);
        state = State.CONNECTING;
        // Copy client keys from the grid connection.
        clientPubkey = grid.clientPubkey;
        clientPrivkey = grid.clientPrivkey;

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
        } else {
            discardFirstBytes = 0;
        }

        // First ask our grid to make tunnel for us
        // DatatypeConverter produces upper case, but the Grid wants only lower
        String peerStr = DatatypeConverter.printHexBinary(peerId).toLowerCase();
        PeerReply reply = grid.connectToPeer(peerStr, protocol).get();

        startForwarding(reply);
    }

    protected void startForwarding(PeerReply reply) throws IOException, InterruptedException, ExecutionException {
        if (reply.getResult() != 0) {
            // This may happen if e. g. there's no such peer ID on the Grid.
            // It seems that error code would always be 1, but we report it just in case
            throw new RemoteException("Connection refused by grid: " + reply.getResult());
        }

        PeerInfo info = reply.getPeer();
        PeerInfo.Endpoint host = info.getServer();
        ByteString tunnelId = info.getTunnelId();

        logger.debug("ForwardRequest #{}: created tunnel {}", reply.getId(), new Hexdump(tunnelId.toByteArray()));

        openSocket(host.getHost(), host.getPort());
        // We're now connected to one of grid servers, ask it to forward us to our peer
        sendPacket(new ForwardRequest(tunnelId));

        ReadResult ret;
        do {
            ret = receiveRawPacket();

            if (ret == ReadResult.EOF) {
                throw getEOFException();
            }

            ret = handleFwdPacket(detachBuffer());
        } while (ret == ReadResult.CONTINUE);

        startTunnel();
    }

    private void sendPacket(Forward.Packet pkt) throws IOException, InterruptedException, ExecutionException {
        logger.trace("Sending packet: {}", pkt);
        sendRawData(pkt.getData());
    }

    @Override
    void handleREDY(REDYPacket pkt) throws IOException, InterruptedException, ExecutionException {
        // REDY packet from a device contains its built-in license key
        // in the same format as in VOCH packet, sent by us.
        // Being an opensource project we simply don't care about it.
        state = State.CONNECTED;
    }

    @Override
    protected void handleMESG(MESGPacket pkt) throws IOException, InterruptedException, ExecutionException {
        // Pass the data over to the client
        onDataReceived(getPayload(pkt));
    }

    /**
     * A wrapper around {@link MESGPacket.getPayload} for handling discardFirstBytes
     *
     */
    private InputStream getPayload(MESGPacket pkt) {
        InputStream data = pkt.getPayload(discardFirstBytes);

        // Data is discarded only once
        discardFirstBytes = 0;
        return data;
    }

    private ReadResult handleFwdPacket(ByteBuffer buffer) throws IOException {
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

    /**
     * Called when a data packet has been read asynchronously
     *
     * @param data Data to be processed
     */
    protected void onDataReceived(InputStream data) {
        // It's strongly advised to handle these events, so let's log under error
        // if the developer forgot to do so.
        logger.error("Unhandled async data receive");
    }

    /**
     * Receive a single data packet synchronously
     *
     * @return data received or null on EOF
     */
    public @Nullable InputStream receiveData() throws IOException, InterruptedException, ExecutionException {
        MESGPacket mesg;

        do {
            ReadResult ret = receiveRawPacket();

            if (ret == ReadResult.EOF) {
                return null;
            }

            mesg = onPacketReceived();
        } while (mesg == null);

        return getPayload(mesg);
    }

    /**
     * Send a single data packet synchronously
     *
     * @param data data to send
     */
    public void sendData(byte[] data) throws ProtocolException, IOException, InterruptedException, ExecutionException {
        sendMESG(data);
    }
}
