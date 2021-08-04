package org.opensdg.java;

import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.ClosedChannelException;
import java.rmi.RemoteException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.eclipse.jdt.annotation.Nullable;
import org.opensdg.internal.Utils.Hexdump;
import org.opensdg.protocol.Forward;
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

    private int discardFirstBytes = 0;

    /**
     * Connects to a remote peer
     *
     * @param grid master connection to use
     * @param peerId ID (AKA public key) of the peer to call
     * @param protocol application-specific protocol ID
     * @throws IOException if protocol fails
     * @throws ExecutionException if I/O fails
     * @throws InterruptedException if the current thread was interrupted
     * @throws TimeoutException if the operation has timed out
     */
    public void connectToRemote(GridConnection grid, byte[] peerId, String protocol)
            throws IOException, InterruptedException, ExecutionException, TimeoutException {
        init(grid);

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
        String peerStr = SDG.bin2hex(peerId);

        try {
            PeerReply reply = grid.connectToPeer(peerStr, protocol).get(timeout, TimeUnit.SECONDS);
            startForwarding(reply);
        } catch (Exception e) {
            setState(State.CLOSED);
            throw e;
        }
    }

    protected void init(GridConnection grid) {
        checkState(State.CLOSED);
        setState(State.CONNECTING);
        // Copy client keys from the grid connection.
        tunnel = grid.tunnel.makePeerTunnel(this);
    }

    protected void startForwarding(PeerReply reply)
            throws IOException, InterruptedException, ExecutionException, TimeoutException {
        if (reply.getResult() != 0) {
            // This may happen if e. g. there's no such peer ID on the Grid.
            // It seems that error code would always be 1, but we report it just in case
            throw new RemoteException("Connection refused by grid: " + reply.getResult());
        }

        PeerInfo info = reply.getPeer();
        PeerInfo.Endpoint host = info.getServer();
        ByteString tunnelId = info.getTunnelId();

        logger.debug("ForwardRequest #{}: created tunnel {}", reply.getId(), new Hexdump(tunnelId.toByteArray()));

        // Connect to the endpoint
        openSocket(host.getHost(), host.getPort());
        // Forward ourselves to the peer
        new Forward(tunnelId, this).establish();
        // Establish the encrypted connection
        tunnel.establish();
    }

    @Override
    public void onReadyPacket() throws IOException, InterruptedException, ExecutionException {
        setState(State.CONNECTED);
    }

    @Override
    public void onDataPacket(InputStream data) throws IOException, InterruptedException, ExecutionException {
        // Pass the data over to the client
        onDataReceived(handleProtocolBugs(data));
    }

    /**
     * A wrapper around {@link MESGPacket.getPayload} for handling discardFirstBytes
     *
     * @throws IOException
     *
     */
    private InputStream handleProtocolBugs(InputStream data) throws IOException {
        // Discard how much we need to and remember the position for user's
        // sake of convenience, so that calling reset() brings to the beginning
        // of usable data
        data.skip(discardFirstBytes);
        data.mark(0);

        // Data is discarded only once
        discardFirstBytes = 0;
        return data;
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
     * Start asynchronous data receiving
     *
     * Initiates asynchronous data handling on the Connection.
     * {@link onDataReceived} or {@link onError} will be called accordingly
     *
     */
    @Override
    public void asyncReceive() {
        super.asyncReceive();
    }

    /**
     * Receive a single data packet synchronously
     *
     * @return data received or null on EOF
     * @throws IOException if packet decoding fails
     * @throws ExecutionException if the response write operation threw an exception
     * @throws InterruptedException if the current thread was interrupted
     * @throws TimeoutException if the operation has timed out
     */
    public @Nullable InputStream receiveData()
            throws IOException, InterruptedException, ExecutionException, TimeoutException {
        ReadResult ret = tunnel.receiveRawPacket();

        if (ret == ReadResult.EOF) {
            return null;
        }

        return handleProtocolBugs(tunnel.getData());
    }

    /**
     * Send a single data packet synchronously
     *
     * @param data data to send
     * @throws IOException if packet encoding fails
     * @throws ExecutionException if the response write operation threw an exception
     * @throws InterruptedException if the current thread was interrupted
     * @throws TimeoutException if the operation has timed out
     */
    public void sendData(byte[] data) throws IOException, InterruptedException, ExecutionException, TimeoutException {
        if (getState() != State.CONNECTED) {
            throw new ClosedChannelException();
        }
        tunnel.sendData(data);
    }
}
