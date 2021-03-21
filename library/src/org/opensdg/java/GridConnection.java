package org.opensdg.java;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ProtocolException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import org.eclipse.jdt.annotation.NonNull;
import org.opensdg.protocol.Control;
import org.opensdg.protocol.Tunnel.MESGPacket;
import org.opensdg.protocol.Tunnel.REDYPacket;
import org.opensdg.protocol.generated.ControlProtocol.ConnectToPeer;
import org.opensdg.protocol.generated.ControlProtocol.PeerReply;
import org.opensdg.protocol.generated.ControlProtocol.Ping;
import org.opensdg.protocol.generated.ControlProtocol.Pong;
import org.opensdg.protocol.generated.ControlProtocol.ProtocolVersion;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.protobuf.AbstractMessage;

/**
 * A {@link Connection} to be used as a master connection to the Grid cloud.
 *
 * @author Pavel Fedin
 */
public class GridConnection extends Connection {
    private final Logger logger = LoggerFactory.getLogger(GridConnection.class);

    private int pingInterval = 30;
    private int pingSequence = 0;
    private int pingDelay = -1;
    private long lastPing;

    private ScheduledExecutorService pingScheduler = Executors.newScheduledThreadPool(1);
    private ScheduledFuture<?> scheduledPing;

    private @NonNull ArrayList<ForwardRequest> forwardQueue = new ArrayList<ForwardRequest>();

    private Runnable pingTask = new Runnable() {
        @Override
        public void run() {
            GridConnection.this.scheduledPing = null;

            try {
                GridConnection.this.ping();
            } catch (IOException | InterruptedException | ExecutionException e) {
                // TODO Auto-generated catch block
                GridConnection.this.onError(e);
            }
        }
    };

    public static class Endpoint {
        String host;
        int port;

        Endpoint(String h, int p) {
            host = h;
            port = p;
        }
    };

    /**
     * A well-known Danfoss Grid, used by many Danfoss products, including:
     * - DeviReg Smart(tm) Wi-Fi enabled thermostat
     * - Icon house heating control solution
     */
    public static final Endpoint Danfoss[] = { new Endpoint("77.66.11.90", 443), new Endpoint("77.66.11.92", 443),
            new Endpoint("5.179.92.180", 443), new Endpoint("5.179.92.182", 443) };

    /**
     * Creates a {@link GridConnection} with the given private key
     *
     * The private key is used for connection encryption. The public key,
     * also known as a peer ID, used to identify a host on the Grid, is also
     * derived from the given private key
     *
     * @param key a private key to use
     */
    public GridConnection(byte[] key) {
        clientPrivkey = key.clone();
        clientPubkey = SDG.calcPublicKey(clientPrivkey);
    }

    /**
     * Connects to a Grid and makes this Connection object a control connection.
     * There can be multiple servers for load-balancing purposes. The
     * array will be sorted in random order and connection is tried to
     * all of them.
     *
     * @param servers array of endpoint specifiers.
     */
    public void connect(@NonNull Endpoint[] servers) throws IOException, InterruptedException, ExecutionException {
        Endpoint[] list = servers.clone();
        Endpoint[] randomized = new Endpoint[servers.length];

        // Permute servers in random order in order to distribute the load
        int left = servers.length;
        for (int i = 0; i < servers.length; i++) {
            int idx = (int) (Math.random() * left);

            randomized[i] = list[idx];
            left--;
            list[idx] = list[left];
        }

        IOException lastErr = null;

        checkState(State.CLOSED);
        state = State.CONNECTING;

        for (int i = 0; i < servers.length; i++) {
            try {
                openSocket(randomized[i].host, randomized[i].port);
                startTunnel();
                // Grid is always serviced asynchronously. The job of this connection now
                // is to ping the grid (otherwise it times out in approximate 90 seconds)
                // and service forwarding requests from peers.
                asyncReceive();

                return;
            } catch (IOException e) {
                logger.debug("Failed to connect to {}:{}: {}", randomized[i].host, randomized[i].port, e.getMessage());
                lastErr = e;
            }
        }

        if (lastErr != null) {
            throw lastErr;
        }
    }

    @Override
    void handleREDY(REDYPacket pkt) throws IOException, InterruptedException, ExecutionException {
        // REDY payload from DEVISmart cloud is empty, nothing to do with it.
        logger.trace("REDY payload: {}", pkt.getPayload());

        // At this point the grid seems to be ready and subsequent steps are
        // probably optional. But let's do them just in case, to be as close
        // to original implementation as possible.
        // So let's do protocol version handshake
        ProtocolVersion.Builder protocolVer = ProtocolVersion.newBuilder();

        protocolVer.setMagic(Control.PROTOCOL_VERSION_MAGIC);
        protocolVer.setMajor(Control.PROTOCOL_VERSION_MAJOR);
        protocolVer.setMinor(Control.PROTOCOL_VERSION_MINOR);

        sendMESG(Control.MSG_PROTOCOL_VERSION, protocolVer.build());
    }

    @Override
    protected void handleMESG(MESGPacket pkt) throws IOException, InterruptedException, ExecutionException {
        InputStream data = pkt.getPayload();
        int msgType = data.read();

        switch (msgType) {
            case Control.MSG_PROTOCOL_VERSION:
                ProtocolVersion protocolVer = ProtocolVersion.parseFrom(data);
                int magic = protocolVer.getMagic();
                int major = protocolVer.getMajor();
                int minor = protocolVer.getMinor();

                if (magic != Control.PROTOCOL_VERSION_MAGIC) {
                    throw new ProtocolException("Incorrect protocol version magic " + Integer.toHexString(magic));
                }

                if (major != Control.PROTOCOL_VERSION_MAJOR || minor != Control.PROTOCOL_VERSION_MINOR) {
                    throw new ProtocolException("Unsupported grid protocol version " + major + "." + minor);
                }

                logger.debug("Using protocol version {}.{}", major, minor);

                // Send the first PING immediately, again, this is the same thing
                // as original mdglib does
                ping();
                state = Connection.State.CONNECTED;
                break;

            case Control.MSG_PONG:
                Pong pong = Pong.parseFrom(data);

                if (pong.getSeq() == pingSequence - 1) {
                    pingDelay = (int) (Calendar.getInstance().getTimeInMillis() - lastPing);
                    logger.debug("PING roundtrip {} ms", pingDelay);
                }

                scheduledPing = pingScheduler.schedule(pingTask, pingInterval, TimeUnit.SECONDS);
                break;

            case Control.MSG_REMOTE_REPLY:
            case Control.MSG_PAIR_REMOTE_REPLY:
                PeerReply reply = PeerReply.parseFrom(data);
                int requestId = reply.getId();
                ForwardRequest request = null;

                synchronized (forwardQueue) {
                    for (int i = 0; i < forwardQueue.size(); i++) {
                        ForwardRequest r = forwardQueue.get(i);

                        if (r.getId() == requestId) {
                            forwardQueue.remove(i);
                            request = r;
                            break;
                        }
                    }
                }

                if (request != null) {
                    request.reportDone(reply);
                } else {
                    // This is not really an error, perhaps some stale request
                    logger.debug("MSG_PEER_REPLY: ForwardRequest #{} not found", requestId);
                }

                break;

            case -1: // EOF while reading the payload, this really shouldn't happen
                throw new ProtocolException("empty MESG received");

            default:
                logger.warn("Unhandled grid message type {}", msgType);
                break;
        }
    }

    private void ping() throws IOException, InterruptedException, ExecutionException {
        Ping.Builder ping = Ping.newBuilder();

        ping.setSeq(pingSequence++);
        if (pingDelay != -1) {
            ping.setDelay(pingDelay);
        }

        lastPing = Calendar.getInstance().getTimeInMillis();

        sendMESG(Control.MSG_PING, ping.build());
    }

    private void sendMESG(byte cmd, AbstractMessage msg) throws IOException, InterruptedException, ExecutionException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(1 + msg.getSerializedSize());

        // The protobuf contents is prefixed by a packet ID
        out.write(cmd);
        msg.writeTo(out);

        sendMESG(out.toByteArray());
    }

    ForwardRequest connectToPeer(String peerId, String protocol) {
        ForwardRequest request;

        synchronized (forwardQueue) {
            int n = forwardQueue.size();
            int requestId;

            if (n > 0) {
                requestId = forwardQueue.get(n - 1).getId() + 1;
            } else {
                requestId = 0;
            }
            request = new ForwardRequest(requestId);
            forwardQueue.add(request);
        }

        logger.debug("Created {}", request);

        ConnectToPeer.Builder msg = ConnectToPeer.newBuilder();

        msg.setId(request.getId());
        msg.setPeerId(peerId);
        msg.setProtocol(protocol);

        try {
            sendMESG(Control.MSG_CALL_REMOTE, msg.build());
        } catch (IOException | InterruptedException | ExecutionException e) {
            synchronized (forwardQueue) {
                forwardQueue.remove(request);
            }
            request.reportError(e);
        }

        return request;
    }

    @Override
    public void close() throws IOException {
        // We need also to stop PINGs on close
        ScheduledFuture<?> pendingPing = scheduledPing;
        scheduledPing = null;

        if (pendingPing != null) {
            pendingPing.cancel(true);
        }

        pingScheduler.shutdown();
        super.close();
    }

    /**
     * Gets current ping interval in seconds
     *
     * @return number of seconds
     */
    public int getPingInterval() {
        return pingInterval;
    }

    /**
     * Sets ping interval in seconds. The new interval will be applied
     * after the next pending ping is sent. Default interval is 30 seconds.
     *
     * @param seconds new ping interval is seconds
     */
    public void setPingInterval(int seconds) {
        pingInterval = seconds;
    }
}
