package org.opensdg.java;

import static org.opensdg.protocol.Tunnel.*;

import java.io.EOFException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ProtocolException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.util.concurrent.ExecutionException;

import javax.xml.bind.DatatypeConverter;

import org.eclipse.jdt.annotation.NonNull;
import org.opensdg.protocol.Tunnel.COOKPacket;
import org.opensdg.protocol.Tunnel.HELOPacket;
import org.opensdg.protocol.Tunnel.MESGPacket;
import org.opensdg.protocol.Tunnel.Packet;
import org.opensdg.protocol.Tunnel.REDYPacket;
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

    private static class ReadHandler implements CompletionHandler<Integer, Connection> {
        @Override
        public void completed(Integer result, Connection conn) {
            try {
                conn.onDataReceived(result);
                conn.asyncReceive();
            } catch (IOException | InterruptedException | ExecutionException e) {
                conn.onError(e);
            }
        }

        @Override
        public void failed(Throwable exc, Connection conn) {
            conn.onError(exc);
        }
    }

    private AsynchronousSocketChannel s;

    private ByteBuffer receiveBuffer;
    private short bytesLeft;
    private int bytesReceived;

    private byte[] clientPubkey;
    private byte[] clientPrivkey;
    private byte[] serverPubkey;
    private byte[] tempPubkey;
    private byte[] tempPrivkey;
    private byte[] beforeNm;
    private long nonce;

    private CompletionHandler<Integer, Connection> readHandler = new ReadHandler();
    private DataHandler dataHandler;

    public void setPrivateKey(byte[] key) {
        clientPrivkey = key.clone();
        clientPubkey = SDG.calcPublicKey(clientPrivkey);
    }

    public static class Endpoint {
        String host;
        int port;

        Endpoint(String h, int p) {
            host = h;
            port = p;
        }
    };

    private static final Endpoint danfoss_servers[] = { new Endpoint("77.66.11.90", 443),
            new Endpoint("77.66.11.92", 443), new Endpoint("5.179.92.180", 443), new Endpoint("5.179.92.182", 443) };

    public void connectToDanfoss() throws IOException, InterruptedException, ExecutionException {
        connectToGrid(danfoss_servers);
    }

    public void connectToGrid(@NonNull Endpoint[] servers)
            throws IOException, InterruptedException, ExecutionException {
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

        dataHandler = new GridDataHandler(this);

        for (int i = 0; i < servers.length; i++) {
            try {
                connect(randomized[i].host, randomized[i].port);
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

    protected void connect(String host, int port) throws IOException, InterruptedException, ExecutionException {
        s = AsynchronousSocketChannel.open();
        s.connect(new InetSocketAddress(host, port)).get();

        logger.debug("Connected to {}:{}", host, port);

        nonce = 0;

        sendPacket(new TELLPacket());

        int ret;
        do {
            ret = blockingReceive();
        } while (ret == 0);

        if (ret == -1) {
            throw new EOFException("Connection closed by peer");
        }
    }

    public void close() throws IOException {
        s.close();
    }

    private void sendPacket(Packet pkt) throws IOException, InterruptedException, ExecutionException {
        logger.trace("Sending packet: {}", pkt);
        ByteBuffer data = pkt.getData();

        data.position(0);

        int size = data.capacity();

        while (size > 0) {
            int ret = s.write(data).get();
            size -= ret;
        }
    }

    private int onDataReceived(int size) throws IOException, InterruptedException, ExecutionException {
        if (size == -1) {
            throw new EOFException("Connection closed by peer");
        }

        bytesReceived += size;
        bytesLeft -= size;

        if (bytesLeft > 0) {
            return 0;
        }

        if (bytesReceived == 2) { // Received 2 bytes, length of the buffer
            receiveBuffer.order(ByteOrder.BIG_ENDIAN);
            // Data size is bigendian
            bytesLeft = receiveBuffer.getShort(0);

            // Reallocate our buffer with the new size
            receiveBuffer = ByteBuffer.allocate(2 + bytesLeft);
            receiveBuffer.putShort(bytesLeft);

            return 0;
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
        } else if (cmd == CMD_REDY) {
            return dataHandler.handleREDY(new REDYPacket(pkt, beforeNm));
        } else if (cmd == CMD_MESG) {
            return dataHandler.handleMESG(new MESGPacket(pkt, beforeNm));
        }

        throw new ProtocolException("Unknown packet received: " + pkt.toString());
    }

    private void getBuffer() {
        if (receiveBuffer == null) {
            // Start receiving a new packet.
            // Every packet is prefixed with length, read it first
            receiveBuffer = ByteBuffer.allocate(2);
            bytesReceived = 0;
            bytesLeft = 2;
        }
    }

    private int blockingReceive() throws IOException, InterruptedException, ExecutionException {
        getBuffer();
        int ret = s.read(receiveBuffer).get();

        return onDataReceived(ret);
    }

    void asyncReceive() {
        getBuffer();
        s.read(receiveBuffer, this, readHandler);
    }

    private long getNonce() {
        return nonce++;
    }

    void sendMESG(byte[] data) throws ProtocolException, IOException, InterruptedException, ExecutionException {
        sendPacket(new MESGPacket(getNonce(), beforeNm, data));
    }

    protected void onError(Throwable exc) {
        logger.error("Unhandled async I/O error: {}", exc.getMessage());
    }
}
