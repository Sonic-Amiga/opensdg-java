package org.opensdg.protocol;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ProtocolException;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

import org.opensdg.internal.Utils;
import org.opensdg.internal.Utils.Hexdump;
import org.opensdg.java.Connection;
import org.opensdg.java.Connection.ReadResult;
import org.opensdg.java.SDG;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.neilalexander.jnacl.crypto.curve25519xsalsa20poly1305;

/**
 * This class implements mdglib's binary encryption protocol
 *
 * The protocol is a modified version of CurveCP. Packet formats are different,
 * plus some more nonce prefixes added
 *
 * @author Pavel Fedin
 */
public class Tunnel extends EncryptedSocket {
    private final Logger logger = LoggerFactory.getLogger(Tunnel.class);

    private static int CMD(int a, int b, int c, int d) {
        return (a << 24) | (b << 16) | (c << 8) | d;
    }

    private static byte[] buildShortTermNonce(String text, long value) {
        byte[] nonce = new byte[curve25519xsalsa20poly1305.crypto_secretbox_NONCEBYTES];
        ByteBuffer data = ByteBuffer.wrap(nonce).order(ByteOrder.BIG_ENDIAN);

        data.put(text.getBytes());
        data.putLong(value);

        return nonce;
    }

    private static byte[] buildLongTermNonce(String text, byte[] value) {
        byte[] nonce = new byte[curve25519xsalsa20poly1305.crypto_secretbox_NONCEBYTES];
        ByteBuffer data = ByteBuffer.wrap(nonce).order(ByteOrder.BIG_ENDIAN);

        data.put(text.getBytes());
        data.put(value);

        return nonce;
    }

    // Some short aliases to avoid long lines
    // This zero padding in front of the message is required by the NaCl
    private static final int OUTER_PAD = curve25519xsalsa20poly1305.crypto_secretbox_BOXZEROBYTES;
    // Actual encrypted messages also have zero padding in front
    private static final int INNER_PAD = curve25519xsalsa20poly1305.crypto_secretbox_BOXZEROBYTES;

    private static final int SHORT_NONCE_SIZE = 8;
    private static final int LONG_NONCE_SIZE = 16;
    private static final int COOKIE_SIZE = 96;

    private static void encrypt(byte[] c, byte[] m, byte[] n, byte[] pk, byte[] sk) throws ProtocolException {
        int ret = curve25519xsalsa20poly1305.crypto_box(c, m, n, pk, sk);
        if (ret != 0) {
            throw new ProtocolException("Encryption failed, code " + ret);
        }
    }

    private static void decrypt(byte[] m, byte[] c, byte[] n, byte[] pk, byte[] sk) throws ProtocolException {
        int ret = curve25519xsalsa20poly1305.crypto_box_open(c, m, n, pk, sk);
        if (ret != 0) {
            throw new ProtocolException("Decryption failed, code " + ret);
        }
    }

    private static void encrypt(byte[] c, byte[] m, byte[] n, byte[] k) throws ProtocolException {
        int ret = curve25519xsalsa20poly1305.crypto_box_afternm(c, m, n, k);
        if (ret != 0) {
            throw new ProtocolException("Encryption failed, code " + ret);
        }
    }

    private static void decrypt(byte[] m, byte[] c, byte[] n, byte[] k) throws ProtocolException {
        int ret = curve25519xsalsa20poly1305.crypto_box_open_afternm(c, m, n, k);
        if (ret != 0) {
            throw new ProtocolException("Decryption failed, code " + ret);
        }
    }

    private static class Packet {
        public static final short HEADER_SIZE = 10;
        private static final int MAGIC = 0xf09f909f;
        protected ByteBuffer data;

        protected Packet(int data_size, int cmd) {
            int size = HEADER_SIZE + data_size;

            data = ByteBuffer.allocate(size).order(ByteOrder.BIG_ENDIAN);

            // 0 - Packet size, excluding this field
            data.putShort((short) (size - 2));
            // 2 - magic
            data.putInt(MAGIC);
            // 6 - command
            data.putInt(cmd);
        }

        public Packet(ByteBuffer buffer, int data_size) throws ProtocolException {
            data = buffer.order(ByteOrder.BIG_ENDIAN);
            if (data.capacity() < HEADER_SIZE + data_size) {
                throw new ProtocolException("Invalid packet received, too short");
            }
            if (getMagic() != MAGIC) {
                throw new ProtocolException("Invalid packet received, bad magic");
            }
        }

        public Packet(ByteBuffer buffer) throws ProtocolException {
            this(buffer, 0);
        }

        public Packet(ByteBuffer buffer, int data_size, int cmd) throws ProtocolException {
            this(buffer, data_size);
            if (getCommand() != cmd) {
                throw new ProtocolException("Unexpected packet received: " + toString());
            }
        }

        public Packet(Packet pkt, int data_size) throws ProtocolException {
            if (pkt.getDataLength() < data_size) {
                throw new ProtocolException("Invalid packet received, too short");
            }
            data = pkt.data;
        }

        public ByteBuffer getData() {
            return data;
        }

        public int getDataLength() {
            return data.getShort(0) - 8;
        }

        public int getMagic() {
            return data.getInt(2);
        }

        public int getCommand() {
            return data.getInt(6);
        }

        protected void setPosition(int pos) {
            // Binary incompatibility workaround: In Java 9 position() method has been overridden
            // in ByteBuffer class; and overridden version returns ByteBuffer. This causes attempt
            // to call using incompatible signature if compiled with the newer JDK.
            // We care because we want to run on OpenHAB v2 using Java 1.8
            ((Buffer) data).position(pos);
        }

        protected byte[] getBytes(int start, int size) {
            byte[] ret = new byte[size];

            setPosition(start);
            data.get(ret);

            return ret;
        }

        @Override
        public String toString() {
            return new String(getBytes(6, 4));
        }
    }

    private static class EncryptedPacket extends Packet {
        private int box_size;
        protected ByteBuffer decrypted;

        protected void setDecryptedPosition(int pos) {
            // Binary incompatibility workaround: In Java 9 position() method has been overridden
            // in ByteBuffer class; and overridden version returns ByteBuffer. This causes attempt
            // to call using incompatible signature if compiled with the newer JDK.
            // We care because we want to run on OpenHAB v2 using Java 1.8
            ((Buffer) decrypted).position(pos);
        }

        EncryptedPacket(int raw_portion_size, int encrypted_data_size, int cmd) {
            super(raw_portion_size + INNER_PAD + encrypted_data_size, cmd);
            allocateDecryptedBuffer(encrypted_data_size);
            // Position to the beginning of usable decrypted data area for convenience
            setDecryptedPosition(OUTER_PAD + INNER_PAD);
        }

        EncryptedPacket(Packet pkt, int raw_portion_size, int encrypted_data_size) throws ProtocolException {
            super(pkt, raw_portion_size + INNER_PAD + encrypted_data_size);
            allocateDecryptedBuffer(encrypted_data_size);
        }

        EncryptedPacket(ByteBuffer data, int raw_portion_size, int encrypted_data_size, int cmd)
                throws ProtocolException {
            super(data, raw_portion_size + INNER_PAD + encrypted_data_size, cmd);
            allocateDecryptedBuffer(encrypted_data_size);
        }

        private void allocateDecryptedBuffer(int encrypted_data_size) {
            box_size = INNER_PAD + encrypted_data_size;
            decrypted = ByteBuffer.allocate(OUTER_PAD + box_size).order(ByteOrder.BIG_ENDIAN);
        }

        protected byte[] getDecryptedBytes(int start, int size) {
            byte[] ret = new byte[size];

            setDecryptedPosition(OUTER_PAD + INNER_PAD + start);
            decrypted.get(ret);

            return ret;
        }

        protected void putEncrypted(String nonce_prefix, long nonce, byte[] beforenm) throws ProtocolException {
            byte[] box_nonce = buildShortTermNonce(nonce_prefix, nonce);
            // We may implement both getters and setters, so for consistency use
            // another temporary buffer for encryption, despite it's a bit slow.
            // unfortunately jnacl doesn't allow to use ByteBuffers or ByteArrayStreams,
            // neither it allows to specify offset into arrays.
            byte[] encrypted = new byte[OUTER_PAD + box_size];

            encrypt(encrypted, decrypted.array(), box_nonce, beforenm);
            data.put(encrypted, OUTER_PAD, box_size);
        }

        protected byte[] fillDataToDecrypt(int box_offset) {
            byte[] msg = decrypted.array();

            setPosition(HEADER_SIZE + box_offset);
            data.get(msg, OUTER_PAD, box_size);

            return msg;
        }
    }

    // Command codes
    private static final int CMD_TELL = CMD('T', 'E', 'L', 'L');
    private static final int CMD_WELC = CMD('W', 'E', 'L', 'C');
    private static final int CMD_HELO = CMD('H', 'E', 'L', 'O');
    private static final int CMD_COOK = CMD('C', 'O', 'O', 'K');
    private static final int CMD_VOCH = CMD('V', 'O', 'C', 'H');
    private static final int CMD_REDY = CMD('R', 'E', 'D', 'Y');
    private static final int CMD_MESG = CMD('M', 'E', 'S', 'G');

    private static class TELLPacket extends Packet {
        // TELL packet has no payload
        public TELLPacket() {
            super(0, CMD_TELL);
        }
    }

    private static class WELCPacket extends Packet {
        public WELCPacket(Packet pkt) throws ProtocolException {
            super(pkt, SDG.KEY_SIZE);
        }

        public byte[] getPeerID() {
            return getBytes(HEADER_SIZE, SDG.KEY_SIZE);
        }

        @Override
        public String toString() {
            return super.toString() + " " + getPeerID().toString();
        }
    }

    private static class HELOPacket extends Packet {
        public static final int ZEROMSG_SIZE = 80;

        public HELOPacket(byte[] serverPk, byte[] clientPk, byte[] clientSk, long nonce) throws ProtocolException {
            super(SDG.KEY_SIZE + SHORT_NONCE_SIZE + ZEROMSG_SIZE, CMD_HELO);

            data.put(clientPk);
            data.putLong(nonce);

            byte[] box_nonce = buildShortTermNonce("CurveCP-client-H", nonce);
            byte[] zeroMsg = new byte[OUTER_PAD + ZEROMSG_SIZE];

            // Encrypt in place, NaCl allows this
            // Unfortunately crypto_box API doesn't allow to specify starting offset
            // in the destination buffer, so we have to copy the result into our packet
            // Note that outer BOX_PAD is stripped and not sent
            encrypt(zeroMsg, zeroMsg, box_nonce, serverPk, clientSk);

            data.put(zeroMsg, OUTER_PAD, ZEROMSG_SIZE);
        }

        long getNonce() {
            return data.getLong(HEADER_SIZE + SDG.KEY_SIZE);
        }

        @Override
        public String toString() {
            return super.toString() + " #" + getNonce();
        }
    }

    private static class COOKPacket extends EncryptedPacket {
        public COOKPacket(Packet pkt, byte[] serverPk, byte[] clientSk) throws ProtocolException {
            super(pkt, LONG_NONCE_SIZE, SDG.KEY_SIZE + COOKIE_SIZE);

            byte[] box_nonce = buildLongTermNonce("CurveCPK", getNonce());
            byte[] msg = fillDataToDecrypt(LONG_NONCE_SIZE);

            decrypt(msg, msg, box_nonce, serverPk, clientSk);
        }

        public byte[] getNonce() {
            return getBytes(HEADER_SIZE, LONG_NONCE_SIZE);
        }

        public byte[] getShortTermPubkey() {
            return getDecryptedBytes(0, SDG.KEY_SIZE);
        }

        public byte[] getCookie() {
            return getDecryptedBytes(SDG.KEY_SIZE, COOKIE_SIZE);
        }
    }

    private static class VOCHPacket extends EncryptedPacket {
        private static final int INNER_BOX_SIZE = INNER_PAD + SDG.KEY_SIZE;
        private static final String CERTIFICATE_PREFIX = "certificate";
        private static final int CERTIFICATE_PREFIX_SIZE = CERTIFICATE_PREFIX.length() + 3;

        public VOCHPacket(byte[] cookie, long nonce, byte[] beforenm, byte[] serverPk, byte[] clientSk, byte[] clientPk,
                byte[] clientTempPk, byte[] certificate) throws ProtocolException {
            super(COOKIE_SIZE + SHORT_NONCE_SIZE, SDG.KEY_SIZE + LONG_NONCE_SIZE + INNER_BOX_SIZE + 1
                    + (certificate == null ? 0 : (CERTIFICATE_PREFIX_SIZE + certificate.length)), CMD_VOCH);

            byte[] long_nonce = Utils.randomBytes(LONG_NONCE_SIZE);
            byte[] box_nonce = buildLongTermNonce("CurveCPV", long_nonce);
            byte[] innerMsg = new byte[OUTER_PAD + INNER_BOX_SIZE];

            // Don't bother about ByteBuffer because inner data is all just byte[]
            System.arraycopy(clientTempPk, 0, innerMsg, OUTER_PAD + INNER_PAD, SDG.KEY_SIZE);
            encrypt(innerMsg, innerMsg, box_nonce, serverPk, clientSk);

            decrypted.put(clientPk);
            decrypted.put(long_nonce);
            decrypted.put(innerMsg, OUTER_PAD, INNER_BOX_SIZE);

            /*
             * License key is appended to VOCH packet in a form of key-value pair.
             * Unlike MESG this is not protobuf, but a fixed structure. An empty
             * license key is reported as all zeroes.
             * Actually the grid (at least DEVISmart one) accepts VOCH packets
             * without this optional data just fine, but we fully replicate the
             * original library just in case, for better compatibility.
             */
            if (certificate == null) {
                decrypted.put((byte) 0);
            } else {
                // 1 byte - Presence flag
                decrypted.put((byte) 1);
                // 1 byte - Length of the following string without trailing NULL
                decrypted.put((byte) CERTIFICATE_PREFIX.length());
                // 12 bytes - NULL-terminated string
                decrypted.put(CERTIFICATE_PREFIX.getBytes());
                decrypted.put((byte) 0);
                // 1 byte - Length of the license key
                decrypted.put((byte) certificate.length);
                // The license key itself
                decrypted.put(certificate);
            }

            data.put(cookie);
            data.putLong(nonce);
            putEncrypted("CurveCP-client-I", nonce, beforenm);
        }

        long getNonce() {
            return data.getLong(HEADER_SIZE + COOKIE_SIZE);
        }

        @Override
        public String toString() {
            return super.toString() + " #" + getNonce();
        }
    }

    private static class DataPacket extends EncryptedPacket {
        protected DataPacket(int raw_portion_size, int encrypted_data_size, int cmd) {
            super(raw_portion_size, encrypted_data_size, cmd);
        }

        protected DataPacket(ByteBuffer data, String noncePrefix, byte[] beforenm, int cmd) throws ProtocolException {
            super(data, SHORT_NONCE_SIZE, data.capacity() - HEADER_SIZE - SHORT_NONCE_SIZE - INNER_PAD, cmd);

            byte[] box_nonce = buildShortTermNonce(noncePrefix, getNonce());
            byte[] msg = fillDataToDecrypt(SHORT_NONCE_SIZE);

            decrypt(msg, msg, box_nonce, beforenm);
        }

        protected DataPacket(Packet pkt, String noncePrefix, byte[] beforenm) throws ProtocolException {
            super(pkt, SHORT_NONCE_SIZE, pkt.getDataLength() - SHORT_NONCE_SIZE - INNER_PAD);

            byte[] box_nonce = buildShortTermNonce(noncePrefix, getNonce());
            byte[] msg = fillDataToDecrypt(SHORT_NONCE_SIZE);

            decrypt(msg, msg, box_nonce, beforenm);
        }

        public long getNonce() {
            return data.getLong(HEADER_SIZE);
        }

        @Override
        public String toString() {
            return super.toString() + " #" + getNonce();
        }
    }

    // REDY packet is identical to MESG with the only difference being nonce prefix
    private static class REDYPacket extends DataPacket {
        public REDYPacket(Packet pkt, byte[] beforenm) throws ProtocolException {
            super(pkt, "CurveCP-server-R", beforenm);
        }

        public int getPayloadLength() {
            return getDataLength() - SHORT_NONCE_SIZE - INNER_PAD;
        }

        public byte[] getPayload() {
            return getDecryptedBytes(0, getPayloadLength());
        }
    }

    private static class MESGPacket extends DataPacket {
        public MESGPacket(Packet pkt, byte[] beforenm) throws ProtocolException {
            super(pkt, "CurveCP-server-M", beforenm);
        }

        public MESGPacket(ByteBuffer data, byte[] beforenm) throws ProtocolException {
            super(data, "CurveCP-server-M", beforenm, CMD_MESG);
        }

        public MESGPacket(long nonce, byte[] beforenm, byte[] payload) throws ProtocolException {
            // Payload is prefixed by its length, yes, again
            super(SHORT_NONCE_SIZE, 2 + payload.length, CMD_MESG);

            decrypted.putShort((short) payload.length);
            decrypted.put(payload);

            data.putLong(nonce);
            putEncrypted("CurveCP-client-M", nonce, beforenm);
        }

        public short getPayloadLength() {
            return decrypted.getShort(OUTER_PAD + INNER_PAD);
        }

        public InputStream getPayload() {
            return new ByteArrayInputStream(decrypted.array(), OUTER_PAD + INNER_PAD + 2, getPayloadLength());
        }
    }

    private byte[] clientPubkey;
    private byte[] clientPrivkey;
    private byte[] serverPubkey;
    private byte[] tempPubkey;
    private byte[] tempPrivkey;
    private byte[] beforeNm;
    private long nonce;
    private Object sendLock = new Object();

    public Tunnel(Connection conn, byte[] privKey) {
        super(conn);
        clientPrivkey = privKey.clone();
        clientPubkey = SDG.calcPublicKey(clientPrivkey);
    }

    @Override
    public Tunnel makePeerTunnel(Connection conn) {
        Tunnel peer = new Tunnel(conn, clientPrivkey);
        peer.clientPubkey = clientPubkey;
        return peer;
    }

    @Override
    protected ReadResult onPacketReceived(ByteBuffer data)
            throws IOException, InterruptedException, ExecutionException, TimeoutException {
        Tunnel.Packet pkt = new Tunnel.Packet(data);
        int cmd = pkt.getCommand();

        logger.trace("Received packet: {}", pkt);

        if (cmd == CMD_WELC) {
            serverPubkey = new WELCPacket(pkt).getPeerID();
            logger.trace("Received server public key: {}", new Hexdump(serverPubkey));

            tempPubkey = new byte[SDG.KEY_SIZE];
            tempPrivkey = new byte[SDG.KEY_SIZE];
            curve25519xsalsa20poly1305.crypto_box_keypair(tempPubkey, tempPrivkey);
            logger.trace("Created short-term public key: {}", new Hexdump(tempPubkey));
            logger.trace("Created short-term secret key: {}", new Hexdump(tempPrivkey));

            sendPacket(new HELOPacket(serverPubkey, tempPubkey, tempPrivkey, getNextNonce()));
        } else if (cmd == CMD_COOK) {
            COOKPacket cook = new COOKPacket(pkt, serverPubkey, tempPrivkey);
            byte[] tempServerPubkey = cook.getShortTermPubkey();
            byte[] serverCookie = cook.getCookie();

            logger.trace("Received server short-term public key: {}", new Hexdump(tempServerPubkey));
            logger.trace("Received server cookie: {}", new Hexdump(serverCookie));

            beforeNm = new byte[curve25519xsalsa20poly1305.crypto_secretbox_BEFORENMBYTES];
            curve25519xsalsa20poly1305.crypto_box_beforenm(beforeNm, tempServerPubkey, tempPrivkey);

            sendPacket(new VOCHPacket(serverCookie, getNextNonce(), beforeNm, serverPubkey, clientPrivkey, clientPubkey,
                    tempPubkey, null));
        } else if (cmd == CMD_REDY) {
            handleREDY(new REDYPacket(pkt, beforeNm));
            return ReadResult.DONE;
        } else if (cmd == CMD_MESG) {
            connection.handleDataPacket(new MESGPacket(pkt, beforeNm).getPayload());
        } else {
            throw new ProtocolException("Unknown packet received: " + pkt.toString());
        }

        return ReadResult.CONTINUE;
    }

    private void handleREDY(REDYPacket pkt)
            throws IOException, InterruptedException, ExecutionException, TimeoutException {
        // REDY packet from DEVISmart cloud is empty, nothing to do with it.
        // REDY packet from a device contains its built-in license key
        // in the same format as in VOCH packet, sent by us.
        // Being an opensource project we simply don't care about it.
        connection.handleReadyPacket();
    }

    private void sendPacket(Tunnel.Packet pkt) throws InterruptedException, ExecutionException, TimeoutException {
        logger.trace("Sending packet: {}", pkt);
        connection.sendRawData(pkt.getData());
    }

    private long getNextNonce() {
        return nonce++;
    }

    @Override
    public ReadResult establish() throws IOException, InterruptedException, ExecutionException, TimeoutException {
        // Initialize nonce counter
        nonce = 0;
        // Start encrypted tunnel establishment by sending TELL packet
        sendPacket(new TELLPacket());

        return super.establish();
    }

    @Override
    public void sendData(byte[] data) throws IOException, InterruptedException, ExecutionException, TimeoutException {
        // We can be called by arbitrary number of threads, but we need to make sure
        // that packets are sent in the order of their nonces. Our remote peer simply
        // hangs up if we fail to do so
        synchronized (sendLock) {
            sendPacket(new MESGPacket(getNextNonce(), beforeNm, data));
        }
    }

    @Override
    public InputStream getData() throws ProtocolException {
        return new MESGPacket(detachBuffer(), beforeNm).getPayload();
    }

    @Override
    public byte[] getPeerId() {
        return serverPubkey;
    }

    @Override
    public byte[] getMyPeerId() {
        return clientPubkey;
    }

    @Override
    public byte[] getBeforeNm() {
        return beforeNm;
    }
}
