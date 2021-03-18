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

import javax.xml.bind.DatatypeConverter;

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

public class GridDataHandler extends DataHandler {
    private final Logger logger = LoggerFactory.getLogger(GridDataHandler.class);

    private int pingSequence = 0;
    private int pingDelay = -1;
    private long lastPing;

    private ScheduledExecutorService pingScheduler = Executors.newScheduledThreadPool(1);
    private ScheduledFuture<?> scheduledPing;

    private @NonNull ArrayList<ForwardRequest> forwardQueue = new ArrayList<ForwardRequest>();

    private Runnable pingTask = new Runnable() {
        @Override
        public void run() {
            GridDataHandler.this.scheduledPing = null;

            try {
                GridDataHandler.this.ping();
            } catch (IOException | InterruptedException | ExecutionException e) {
                // TODO Auto-generated catch block
                GridDataHandler.this.connection.onError(e);
            }
        }
    };

    GridDataHandler(Connection conn) {
        super(conn);
    }

    @Override
    int handleREDY(REDYPacket pkt) throws IOException, InterruptedException, ExecutionException {
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
        return 0;
    }

    @Override
    int handleMESG(MESGPacket pkt) throws IOException, InterruptedException, ExecutionException {
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

                ping();
                connection.asyncReceive();
                return 1; // This breaks the blocking read loop in connect()

            case Control.MSG_PONG:
                Pong pong = Pong.parseFrom(data);

                if (pong.getSeq() == pingSequence - 1) {
                    pingDelay = (int) (Calendar.getInstance().getTimeInMillis() - lastPing);
                    logger.debug("PING roundtrip {} ms", pingDelay);
                }

                scheduledPing = pingScheduler.schedule(pingTask, connection.getPingInterval(), TimeUnit.SECONDS);
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

                if (request == null) {
                    logger.debug("MSG_PEER_REPLY: ForwardRequest #{} not found", requestId);
                    return 0;
                }

                request.reportDone(reply);
                break;

            case -1: // EOF while reading the payload, this really shouldn't happen
                throw new ProtocolException("empty MESG received");

            default:
                logger.warn("Unhandled grid message type {}", msgType);
                break;
        }

        return 0;
    }

    private void sendMESG(byte cmd, AbstractMessage msg) throws IOException, InterruptedException, ExecutionException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(1 + msg.getSerializedSize());

        // The protobuf contents is prefixed by a packet ID
        out.write(cmd);
        msg.writeTo(out);

        connection.sendMESG(out.toByteArray());
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

    @Override
    void handleClose() {
        ScheduledFuture<?> pendingPing = scheduledPing;
        scheduledPing = null;

        if (pendingPing != null) {
            pendingPing.cancel(true);
        }

        pingScheduler.shutdown();
    }

    ForwardRequest connectToPeer(byte[] peerId, String protocol) {
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
        // DatatypeConverter produces upper case, but the server wants only lower
        msg.setPeerId(DatatypeConverter.printHexBinary(peerId).toLowerCase());
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

}
