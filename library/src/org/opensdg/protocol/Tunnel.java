package org.opensdg.protocol;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.ProtocolException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.opensdg.java.InternalUtils;
import org.opensdg.java.SDG;

import com.neilalexander.jnacl.crypto.curve25519xsalsa20poly1305;

public class Tunnel {
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

    public static class Packet {
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

        public Packet(ByteBuffer buffer) throws ProtocolException {
            data = buffer.order(ByteOrder.BIG_ENDIAN);
            if (data.capacity() < HEADER_SIZE) {
                throw new ProtocolException("Invalid packet received, too short");
            }
            if (getMagic() != MAGIC) {
                throw new ProtocolException("Invalid packet received, bad magic");
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

        protected byte[] getBytes(int start, int size) {
            byte[] ret = new byte[size];

            data.position(start);
            data.get(ret);

            return ret;
        }

        @Override
        public String toString() {
            return new String(getBytes(6, 4));
        }
    }

    public static class EncryptedPacket extends Packet {
        private int box_size;
        protected ByteBuffer decrypted;

        EncryptedPacket(int raw_portion_size, int encrypted_data_size, int cmd) {
            super(raw_portion_size + INNER_PAD + encrypted_data_size, cmd);
            allocateDecryptedBuffer(encrypted_data_size);
            // Position to the beginning of usable decrypted data area for convenience
            decrypted.position(OUTER_PAD + INNER_PAD);
        }

        EncryptedPacket(Packet pkt, int raw_portion_size, int encrypted_data_size) throws ProtocolException {
            super(pkt, raw_portion_size + INNER_PAD + encrypted_data_size);
            allocateDecryptedBuffer(encrypted_data_size);
        }

        private void allocateDecryptedBuffer(int encrypted_data_size) {
            box_size = INNER_PAD + encrypted_data_size;
            decrypted = ByteBuffer.allocate(OUTER_PAD + box_size).order(ByteOrder.BIG_ENDIAN);
        }

        protected byte[] getDecryptedBytes(int start, int size) {
            byte[] ret = new byte[size];

            decrypted.position(OUTER_PAD + INNER_PAD + start);
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

            data.position(HEADER_SIZE + box_offset);
            data.get(msg, OUTER_PAD, box_size);

            return msg;
        }
    }

    // Command codes
    public static final int CMD_TELL = CMD('T', 'E', 'L', 'L');
    public static final int CMD_WELC = CMD('W', 'E', 'L', 'C');
    public static final int CMD_HELO = CMD('H', 'E', 'L', 'O');
    public static final int CMD_COOK = CMD('C', 'O', 'O', 'K');
    public static final int CMD_VOCH = CMD('V', 'O', 'C', 'H');
    public static final int CMD_REDY = CMD('R', 'E', 'D', 'Y');
    public static final int CMD_MESG = CMD('M', 'E', 'S', 'G');

    public static class TELLPacket extends Packet {
        // TELL packet has no payload
        public TELLPacket() {
            super(0, CMD_TELL);
        }
    }

    public static class WELCPacket extends Packet {
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

    public static class HELOPacket extends Packet {
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

    public static class COOKPacket extends EncryptedPacket {
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

    public static class VOCHPacket extends EncryptedPacket {
        private static final int INNER_BOX_SIZE = INNER_PAD + SDG.KEY_SIZE;
        private static final String CERTIFICATE_PREFIX = "certificate";
        private static final int CERTIFICATE_PREFIX_SIZE = CERTIFICATE_PREFIX.length() + 3;

        public VOCHPacket(byte[] cookie, long nonce, byte[] beforenm, byte[] serverPk, byte[] clientSk, byte[] clientPk,
                byte[] clientTempPk, byte[] certificate) throws ProtocolException {
            super(COOKIE_SIZE + SHORT_NONCE_SIZE, SDG.KEY_SIZE + LONG_NONCE_SIZE + INNER_BOX_SIZE + 1
                    + (certificate == null ? 0 : (CERTIFICATE_PREFIX_SIZE + certificate.length)), CMD_VOCH);

            byte[] long_nonce = InternalUtils.randomBytes(LONG_NONCE_SIZE);
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

    public static class DataPacket extends EncryptedPacket {
        protected DataPacket(int raw_portion_size, int encrypted_data_size, int cmd) {
            super(raw_portion_size, encrypted_data_size, cmd);
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
    public static class REDYPacket extends DataPacket {
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

    public static class MESGPacket extends DataPacket {
        public MESGPacket(Packet pkt, byte[] beforenm) throws ProtocolException {
            super(pkt, "CurveCP-server-M", beforenm);
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
            return getPayload(0);
        }

        public InputStream getPayload(int offset) {
            return new ByteArrayInputStream(decrypted.array(), OUTER_PAD + INNER_PAD + 2 + offset,
                    getPayloadLength() - offset);
        }
    }
}
