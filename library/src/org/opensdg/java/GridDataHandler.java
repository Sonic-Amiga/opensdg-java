package org.opensdg.java;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ProtocolException;
import java.util.Calendar;
import java.util.concurrent.ExecutionException;

import org.opensdg.protocol.Control;
import org.opensdg.protocol.Tunnel.MESGPacket;
import org.opensdg.protocol.Tunnel.REDYPacket;
import org.opensdg.protocol.generated.ControlProtocol.Ping;
import org.opensdg.protocol.generated.ControlProtocol.Pong;
import org.opensdg.protocol.generated.ControlProtocol.ProtocolVersion;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.protobuf.AbstractMessage;

public class GridDataHandler extends DataHandler {
    private final Logger logger = LoggerFactory.getLogger(GridDataHandler.class);

    int pingSequence = 0;
    int pingDelay = -1;
    long lastPing;

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

                return 1;

            case Control.MSG_PONG:
                Pong pong = Pong.parseFrom(data);

                if (pong.getSeq() == pingSequence - 1) {
                    pingDelay = (int) (Calendar.getInstance().getTimeInMillis() - lastPing);
                    logger.debug("PING roundtrip {} ms", pingDelay);
                }

                break;

            case -1: // EOF while reading the payload
                throw new ProtocolException("MESG with no body");

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
}
