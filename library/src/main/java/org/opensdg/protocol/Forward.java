package org.opensdg.protocol;

import static org.opensdg.protocol.Control.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ProtocolException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.rmi.RemoteException;
import java.util.concurrent.ExecutionException;

import org.opensdg.java.Connection;
import org.opensdg.java.Connection.ReadResult;
import org.opensdg.protocol.generated.ForwardProtocol;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.protobuf.AbstractMessage;
import com.google.protobuf.ByteString;

/**
 * This class implements forwarding protocol
 *
 * The protocol runs unencrypted on a peer socket and tells the Grid
 * to forward the connection to to the actual peer.
 *
 * @author Pavel Fedin
 */
public class Forward extends SocketProtocol {
    private final Logger logger = LoggerFactory.getLogger(Forward.class);

    public static final byte MSG_FORWARD_REQUEST = 0;
    public static final byte MSG_FORWARD_HOLD = 1;
    public static final byte MSG_FORWARD_REPLY = 2;
    public static final byte MSG_FORWARD_ERROR = 3;

    private static final int FORWARD_REMOTE_MAGIC = 0xF09D8C95;
    private static final String FORWARD_REMOTE_SIGNATURE = "Mdg-NaCl/binary";

    public static class Packet {
        private ByteBuffer data;

        Packet(byte cmd, AbstractMessage msg) throws IOException {
            int msgSize = 1 + msg.getSerializedSize();
            ByteArrayOutputStream out = new ByteArrayOutputStream(2 + msgSize);

            out.write(msgSize >> 8);
            out.write(msgSize);
            out.write(cmd);
            msg.writeTo(out);
            data = ByteBuffer.wrap(out.toByteArray()).order(ByteOrder.BIG_ENDIAN);
        }

        Packet(ByteBuffer buffer) {
            data = buffer.order(ByteOrder.BIG_ENDIAN);
        }

        public ByteBuffer getData() {
            return data;
        }

        public int getPayloadLength() {
            return data.getShort(2) - 1;
        }

        public byte getCommand() {
            return data.get(2);
        }

        public InputStream getPayload() {
            return new ByteArrayInputStream(data.array(), 3, getPayloadLength());
        }

    }

    public static class ForwardRequest extends Packet {
        public ForwardRequest(ByteString tunnelId) throws IOException {
            super(MSG_FORWARD_REQUEST,
                    ForwardProtocol.ForwardRequest.newBuilder().setMagic(FORWARD_REMOTE_MAGIC)
                            .setProtocolMajor(PROTOCOL_VERSION_MAJOR).setProtocolMinor(PROTOCOL_VERSION_MINOR)
                            .setTunnelId(tunnelId).setSignature(FORWARD_REMOTE_SIGNATURE).build());
        }

        @Override
        public String toString() {
            return "FORWARD_REQUEST";
        }
    }

    public static class ForwardReply extends Packet {
        public ForwardReply(ByteBuffer buffer) throws IOException {
            super(buffer);

            ForwardProtocol.ForwardReply reply = ForwardProtocol.ForwardReply.parseFrom(getPayload());
            String signature = reply.getSignature();

            if (!signature.equals(FORWARD_REMOTE_SIGNATURE)) {
                throw new ProtocolException("Bad MSG_FORWARD_REQUEST signature: " + signature);
            }
        }

        @Override
        public String toString() {
            return "FORWARD_REPLY";
        }
    }

    public static class ForwardError extends Packet {
        private ForwardProtocol.ForwardError msg;

        public ForwardError(ByteBuffer buffer) throws IOException {
            super(buffer);
            msg = ForwardProtocol.ForwardError.parseFrom(getPayload());
        }

        public int getCode() {
            return msg.getCode();
        }

        @Override
        public String toString() {
            return "FORWARD_ERROR " + msg.getCode();
        }
    }

    public Forward(Connection conn) {
        super(conn);
    }

    public ReadResult establish(ByteString tunnelId) throws IOException, InterruptedException, ExecutionException {
        sendPacket(new ForwardRequest(tunnelId));
        return super.establish();
    }

    private void sendPacket(Forward.Packet pkt) throws IOException, InterruptedException, ExecutionException {
        logger.trace("Sending packet: {}", pkt);
        connection.sendRawData(pkt.getData());
    }

    @Override
    ReadResult onPacketReceived(ByteBuffer data) throws IOException, InterruptedException, ExecutionException {
        byte cmd = data.get(2);

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
                ForwardReply reply = new ForwardReply(data);
                logger.trace("Received packet: {}", reply);
                return ReadResult.DONE;

            case MSG_FORWARD_ERROR:
                ForwardError fwdErr = new ForwardError(data);
                logger.trace("Received packet: {}", fwdErr);
                throw new RemoteException("Connection refused by peer: " + fwdErr.getCode());

            default:
                throw new ProtocolException("Unknown forwarding packet received: " + cmd);
        }
    }
}
