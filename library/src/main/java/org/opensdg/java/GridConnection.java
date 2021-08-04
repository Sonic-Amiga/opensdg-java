package org.opensdg.java;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ProtocolException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.eclipse.jdt.annotation.NonNull;
import org.opensdg.protocol.Control;
import org.opensdg.protocol.Tunnel;
import org.opensdg.protocol.generated.ControlProtocol.ConnectToPeer;
import org.opensdg.protocol.generated.ControlProtocol.PairRemote;
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
    private int pingSequence;
    private int pingDelay;
    private long lastPing;

    private ScheduledExecutorService pingScheduler;
    private boolean ownScheduler;
    private ScheduledFuture<?> scheduledPing;

    private @NonNull ArrayList<ForwardRequest> forwardQueue = new ArrayList<ForwardRequest>();

    private Runnable pingTask = new Runnable() {
        @Override
        public void run() {
            GridConnection.this.scheduledPing = null;

            try {
                GridConnection.this.ping();
            } catch (IOException | InterruptedException | ExecutionException | TimeoutException e) {
                GridConnection.this.handleError(e);
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
        tunnel = new Tunnel(this, key);
        ownScheduler = true;
    }

    /**
     * Creates a {@link GridConnection} with the given private key and own task scheduler
     *
     * The private key is used for connection encryption. The public key,
     * also known as a peer ID, used to identify a host on the Grid, is also
     * derived from the given private key
     *
     * A given {@link ScheduledExecutorService} will be used instead of internally provided one
     * to schedule ping requests. This constructor is intended for use if a ScheduledExecutorService
     * is already provided by the environment, e. g. OpenHAB.
     *
     * @param key a private key to use
     * @param scheduler a ScheduledExecutorService
     */
    public GridConnection(byte[] key, ScheduledExecutorService scheduler) {
        tunnel = new Tunnel(this, key);
        pingScheduler = scheduler;
        ownScheduler = false;
    }

    /**
     * Connects to a Grid and makes this Connection object a control connection.
     * There can be multiple servers for load-balancing purposes. The
     * array will be sorted in random order and connection is tried to
     * all of them.
     *
     * @param servers array of endpoint specifiers.
     * @throws IOException if packet decoding fails
     * @throws ExecutionException if an I/O threw an exception
     * @throws InterruptedException if the current thread was interrupted
     * @throws TimeoutException if the operation has timed out
     */
    public void connect(@NonNull Endpoint[] servers)
            throws IOException, InterruptedException, ExecutionException, TimeoutException {
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
        setState(State.CONNECTING);
        pingSequence = 0;
        pingDelay = -1;

        if (ownScheduler) {
            pingScheduler = PingExecutorHolder.get();
        }

        for (int i = 0; i < servers.length; i++) {
            try {
                openSocket(randomized[i].host, randomized[i].port);
                tunnel.establish();

                // Tunnel handshake also includes handling some MESG packets,
                // the handler will set our state to CONNECTED when done
                while (getState() != State.CONNECTED) {
                    ReadResult ret = tunnel.receiveRawPacket();

                    if (ret == ReadResult.EOF) {
                        throw getEOFException();
                    }

                    tunnel.onPacketReceived();
                }

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
            setState(State.CLOSED);
            throw lastErr;
        }
    }

    @Override
    public void handleReadyPacket() throws IOException, InterruptedException, ExecutionException, TimeoutException {
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
    public void handleDataPacket(InputStream data)
            throws IOException, InterruptedException, ExecutionException, TimeoutException {
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
                setState(Connection.State.CONNECTED);
                break;

            case Control.MSG_PONG:
                Pong pong = Pong.parseFrom(data);

                // Ignore some old stray PINGs
                if (pong.getSeq() == pingSequence - 1) {
                    pingDelay = (int) (Calendar.getInstance().getTimeInMillis() - lastPing);
                    logger.debug("PING roundtrip {} ms", pingDelay);
                    scheduledPing = pingScheduler.schedule(pingTask, pingInterval, TimeUnit.SECONDS);
                }

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

    private void ping() throws IOException, InterruptedException, ExecutionException, TimeoutException {
        Ping.Builder ping = Ping.newBuilder();

        ping.setSeq(pingSequence++);
        if (pingDelay != -1) {
            ping.setDelay(pingDelay);
        }

        lastPing = Calendar.getInstance().getTimeInMillis();

        sendMESG(Control.MSG_PING, ping.build());
    }

    private void sendMESG(byte cmd, AbstractMessage msg)
            throws IOException, InterruptedException, ExecutionException, TimeoutException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(1 + msg.getSerializedSize());

        // The protobuf contents is prefixed by a packet ID
        out.write(cmd);
        msg.writeTo(out);

        tunnel.sendData(out.toByteArray());
    }

    ForwardRequest connectToPeer(String peerId, String protocol) {
        ForwardRequest request = createFwdReq();
        ConnectToPeer.Builder msg = ConnectToPeer.newBuilder();

        msg.setId(request.getId());
        msg.setPeerId(peerId);
        msg.setProtocol(protocol);

        sendFwdReq(request, Control.MSG_CALL_REMOTE, msg.build());
        return request;
    }

    ForwardRequest pair(String otp) {
        ForwardRequest request = createFwdReq();
        PairRemote.Builder msg = PairRemote.newBuilder();

        msg.setId(request.getId());
        msg.setOtp(otp);

        sendFwdReq(request, Control.MSG_PAIR_REMOTE, msg.build());
        return request;
    }

    ForwardRequest createFwdReq() {
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
        return request;
    }

    void sendFwdReq(ForwardRequest request, byte cmd, AbstractMessage msg) {
        try {
            sendMESG(cmd, msg);
        } catch (IOException | InterruptedException | ExecutionException | TimeoutException e) {
            synchronized (forwardQueue) {
                forwardQueue.remove(request);
            }
            request.reportError(e);
        }
    }

    @Override
    protected void handleError(Throwable t) {
        // Stop pinging
        stopPing();

        // Report all pending ForwardRequests as failed
        ArrayList<ForwardRequest> queue;

        synchronized (forwardQueue) {
            queue = new ArrayList<ForwardRequest>(forwardQueue);
            forwardQueue.clear();
        }

        for (ForwardRequest req : queue) {
            req.reportError(t);
        }

        super.handleError(t);
    }

    @Override
    protected void handleClose() {
        // We need also to stop PINGs on close
        stopPing();

        if (ownScheduler) {
            pingScheduler = null;
            PingExecutorHolder.put();
        }
    }

    private void stopPing() {
        ScheduledFuture<?> pendingPing = scheduledPing;
        scheduledPing = null;

        if (pendingPing != null) {
            pendingPing.cancel(true);
        }
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
