package org.opensdg.java;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ProtocolException;
import java.util.concurrent.ExecutionException;

import org.opensdg.protocol.Control;
import org.opensdg.protocol.Tunnel.MESGPacket;
import org.opensdg.protocol.Tunnel.REDYPacket;
import org.opensdg.protocol.generated.ControlProtocol.ProtocolVersion;
import org.opensdg.protocol.generated.ControlProtocol.ProtocolVersion.Builder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.protobuf.AbstractMessage;

public class GridDataHandler extends DataHandler {
    private final Logger logger = LoggerFactory.getLogger(GridDataHandler.class);

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
        Builder protocolVer = ProtocolVersion.newBuilder();

        protocolVer.setMagic(Control.PROTOCOL_VERSION_MAGIC);
        protocolVer.setMajor(Control.PROTOCOL_VERSION_MAJOR);
        protocolVer.setMinor(Control.PROTOCOL_VERSION_MINOR);

        sendMESG(Control.MSG_PROTOCOL_VERSION, protocolVer.build());
        return 0;
    }

    @Override
    int handleMESG(MESGPacket pkt) throws IOException {
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
                return 1;

            case -1:
                return -1; // EOF

            default:
                logger.warn("Unhandled grid message type {}", msgType);
                return 0;
        }
    }

    private void sendMESG(byte cmd, AbstractMessage msg) throws IOException, InterruptedException, ExecutionException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(1 + msg.getSerializedSize());

        // The protobuf contents is prefixed by a packet ID
        out.write(cmd);
        msg.writeTo(out);

        connection.sendMESG(out.toByteArray());
    }
}
