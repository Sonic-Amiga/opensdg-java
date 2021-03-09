package org.opensdg.java;

import static org.opensdg.protocol.Tunnel.*;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

import javax.xml.bind.DatatypeConverter;

import org.opensdg.protocol.Tunnel.COOKPacket;
import org.opensdg.protocol.Tunnel.HELOPacket;
import org.opensdg.protocol.Tunnel.Packet;
import org.opensdg.protocol.Tunnel.TELLPacket;
import org.opensdg.protocol.Tunnel.VOCHPacket;
import org.opensdg.protocol.Tunnel.WELCPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.neilalexander.jnacl.crypto.curve25519xsalsa20poly1305;

public class Connection {
    private final Logger logger = LoggerFactory.getLogger(Connection.class);

    private static class Hexdump {
        byte[] data;

        public Hexdump(byte[] raw_key) {
            data = raw_key;
        }

        @Override
        public String toString() {
            return DatatypeConverter.printHexBinary(data);
        }
    }

    private Socket s;
    private InputStream is;
    private OutputStream os;

    private byte[] receiveBuffer;
    private int bytesLeft;
    private int bytesReceived;

    private byte[] clientPubkey;
    private byte[] clientPrivkey;
    private byte[] serverPubkey;
    private byte[] tempPubkey;
    private byte[] tempPrivkey;
    private byte[] beforeNm;
    private long nonce;

    public void setPrivateKey(byte[] key) {
        clientPrivkey = key.clone();
        clientPubkey = SDG.calcPublicKey(clientPrivkey);
    }

    public void connect(String host, int port) throws IOException {
        s = new Socket(host, port);
        is = s.getInputStream();
        os = s.getOutputStream();

        logger.debug("Connected to {}:{}", host, port);

        nonce = 0;

        sendPacket(new TELLPacket());

        int ret;
        do {
            ret = receivePacket();
        } while (ret == 0);
    }

    public void close() throws IOException {
        os.close();
        is.close();
        s.close();
    }

    private void sendPacket(Packet pkt) throws IOException {
        logger.trace("Sending packet: {}", pkt);
        os.write(pkt.getData());
    }

    private int receivePacket() throws IOException {
        if (receiveBuffer == null) {
            // Every packet is prefixed with length, read it first
            receiveBuffer = new byte[2];
            bytesReceived = 0;
            bytesLeft = 2;
        }

        int ret = receiveData();

        if (ret == 2) { // Received 2 bytes, length of the buffer
            byte[] size_buffer = receiveBuffer;

            // Data size is bigendian
            bytesLeft = (Byte.toUnsignedInt(receiveBuffer[0]) << 8) | Byte.toUnsignedInt(receiveBuffer[1]);

            // Reallocate our buffer with the new size
            receiveBuffer = new byte[2 + bytesLeft];
            receiveBuffer[0] = size_buffer[0];
            receiveBuffer[1] = size_buffer[1];

            ret = receiveData();
        }

        if (ret <= 0) {
            return ret;
        }

        Packet pkt = new Packet(receiveBuffer);
        receiveBuffer = null;

        logger.trace("Received packet: {}", pkt);

        int cmd = pkt.getCommand();

        if (cmd == CMD_WELC) {
            serverPubkey = new WELCPacket(pkt).getPeerID();
            logger.trace("Received server public key: {}", new Hexdump(serverPubkey));

            tempPubkey = new byte[SDG.KEY_SIZE];
            tempPrivkey = new byte[SDG.KEY_SIZE];
            curve25519xsalsa20poly1305.crypto_box_keypair(tempPubkey, tempPrivkey);
            logger.trace("Created short-term public key: {}", new Hexdump(tempPubkey));
            logger.trace("Created short-term secret key: {}", new Hexdump(tempPrivkey));

            sendPacket(new HELOPacket(serverPubkey, tempPubkey, tempPrivkey, getNonce()));
            return 0;
        } else if (cmd == CMD_COOK) {
            COOKPacket cook = new COOKPacket(pkt, serverPubkey, tempPrivkey);
            byte[] tempServerPubkey = cook.getShortTermPubkey();
            byte[] serverCookie = cook.getCookie();

            logger.trace("Received server short-term public key: {}", new Hexdump(tempServerPubkey));
            logger.trace("Received server cookie: {}", new Hexdump(serverCookie));

            beforeNm = new byte[curve25519xsalsa20poly1305.crypto_secretbox_BEFORENMBYTES];
            curve25519xsalsa20poly1305.crypto_box_beforenm(beforeNm, tempServerPubkey, tempPrivkey);

            sendPacket(new VOCHPacket(serverCookie, getNonce(), beforeNm, serverPubkey, clientPrivkey, clientPubkey,
                    tempPubkey, null));
            return 0;
        }

        return 1;
    }

    private int receiveData() throws IOException {
        while (bytesLeft > 0) {
            int ret = is.read(receiveBuffer, bytesReceived, bytesLeft);

            if (ret == -1) {
                logger.debug("Connection closed by peer");
                return -1;
            }

            // TODO: Support non-blocking mode

            bytesReceived += ret;
            bytesLeft -= ret;
        }

        return bytesReceived;
    }

    private long getNonce() {
        return nonce++;
    }
}
