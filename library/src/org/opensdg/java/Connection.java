package org.opensdg.java;

import static org.opensdg.protocol.Tunnel.*;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.ProtocolException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.AsynchronousCloseException;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.rmi.RemoteException;
import java.util.concurrent.ExecutionException;

import javax.xml.bind.DatatypeConverter;

import org.eclipse.jdt.annotation.NonNull;
import org.eclipse.jdt.annotation.Nullable;
import org.opensdg.protocol.Forward;
import org.opensdg.protocol.Forward.ForwardRequest;
import org.opensdg.protocol.Tunnel;
import org.opensdg.protocol.Tunnel.COOKPacket;
import org.opensdg.protocol.Tunnel.HELOPacket;
import org.opensdg.protocol.Tunnel.MESGPacket;
import org.opensdg.protocol.Tunnel.REDYPacket;
import org.opensdg.protocol.Tunnel.TELLPacket;
import org.opensdg.protocol.Tunnel.VOCHPacket;
import org.opensdg.protocol.Tunnel.WELCPacket;
import org.opensdg.protocol.generated.ControlProtocol.PeerInfo;
import org.opensdg.protocol.generated.ControlProtocol.PeerReply;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.protobuf.ByteString;
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
                ReadResult ret = conn.onDataReceived(result);

                switch (ret) {
                    case EOF:
                        conn.handleError(getEOFException());
                        return;
                    case DONE:
                        InputStream data = conn.onPacketReceived();
                        if (data != null) {
                            // handleMESG() can't return EOF, so ignore
                            conn.dataHandler.handleMESG(data);
                        }
                        break;
                    case CONTINUE:
                        break;

                }
                // Continue receiving
                conn.asyncReceive();
            } catch (IOException | InterruptedException | ExecutionException e) {
                conn.handleError(e);
            }
        }

        @Override
        public void failed(Throwable exc, Connection conn) {
            conn.handleError(exc);
        }
    }

    public enum State {
        CLOSED,
        CONNECTING,
        CONNECTED
    }

    enum ReadResult {
        CONTINUE,
        EOF,
        DONE
    }

    private static EOFException getEOFException() {
        return new EOFException("Connection closed by peer");
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

    private int pingInterval = 30;

    private State state = State.CLOSED;

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

    /**
     * Connects to a Grid and makes this Connection object a control connection.
     * There can be multiple servers for load-balancing purposes. The
     * array will be sorted in random order and connection is tried to
     * all of them.
     *
     * @param servers array of endpoint specifiers.
     */
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

        state = State.CONNECTING;
        dataHandler = new GridDataHandler(this);

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

    /**
     * Connects to a remote peer
     *
     * @param grid control connection to use
     * @param peerId ID (AKA public key) of the peer to call
     * @param protocol application-specific protocol ID
     */
    public void connectToRemote(Connection grid, byte[] peerId, String protocol)
            throws IOException, InterruptedException, ExecutionException {
        state = State.CONNECTING;
        // First ask our grid to make tunnel for us
        PeerReply reply = grid.dataHandler.connectToPeer(peerId, protocol).get();

        if (reply.getResult() != 0) {
            // This may happen if e. g. there's no such peer ID on the Grid.
            // It seems that error code would always be 1, but we report it just in case
            throw new RemoteException("Connection refused by grid: " + reply.getResult());
        }

        PeerInfo info = reply.getPeer();
        PeerInfo.Endpoint host = info.getServer();
        ByteString tunnelId = info.getTunnelId();

        logger.debug("ForwardRequest #{}: created tunnel {}", reply.getId(), new Hexdump(tunnelId.toByteArray()));

        // Get ready to open own socket. Copy client keys from the grid connection.
        clientPubkey = grid.clientPubkey;
        clientPrivkey = grid.clientPrivkey;

        PeerDataHandler peerHandler = new PeerDataHandler(this, protocol);
        dataHandler = peerHandler;

        openSocket(host.getHost(), host.getPort());
        // We're now connected to one of grid servers, ask it to forward us to our peer
        sendPacket(new ForwardRequest(tunnelId));

        ReadResult ret;
        do {
            ret = blockingReceive();

            if (ret == ReadResult.EOF) {
                throw getEOFException();
            }

            ret = peerHandler.handleFwdPacket(detachBuffer());
        } while (ret == ReadResult.CONTINUE);

        startTunnel();
    }

    private void openSocket(String host, int port) throws IOException, InterruptedException, ExecutionException {
        s = AsynchronousSocketChannel.open();
        s.connect(new InetSocketAddress(host, port)).get();
        logger.debug("Connected to {}:{}", host, port);
    }

    private void startTunnel() throws IOException, InterruptedException, ExecutionException {
        // Initialize nonce counter
        nonce = 0;
        // Start encrypted tunnel establishment by sending TELL packet
        sendPacket(new TELLPacket());

        do {
            InputStream msgData = receiveData();
            if (msgData == null) {
                throw getEOFException();
            }

            // Tunnel handshake also includes handling some MESG packets,
            // and normally the handler would be called only for async read,
            // so call it here explicitly. The handler will set our state to
            // CONNECTED when done
            dataHandler.handleMESG(msgData);
        } while (state != State.CONNECTED);
    }

    /**
     * Close the connection
     * After closing the Connection object can be reused
     *
     */
    public void close() throws IOException {
        DataHandler handler = dataHandler;
        dataHandler = null;

        if (handler != null) {
            handler.handleClose();
        }

        AsynchronousSocketChannel ch = s;
        s = null;

        if (ch != null) {
            ch.close();
        }
    }

    private void sendPacket(Tunnel.Packet pkt) throws IOException, InterruptedException, ExecutionException {
        logger.trace("Sending packet: {}", pkt);
        sendData(pkt.getData());
    }

    private void sendPacket(Forward.Packet pkt) throws IOException, InterruptedException, ExecutionException {
        logger.trace("Sending packet: {}", pkt);
        sendData(pkt.getData());
    }

    private synchronized void sendData(ByteBuffer data) throws IOException, InterruptedException, ExecutionException {
        int size = data.capacity();

        data.position(0);

        while (size > 0) {
            int ret = s.write(data).get();
            size -= ret;
        }
    }

    /**
     * Receive a single data packet synchronously
     *
     * @return data received or null on EOF
     */
    public @Nullable InputStream receiveData() throws IOException, InterruptedException, ExecutionException {
        InputStream data;

        do {
            ReadResult ret = blockingReceive();

            if (ret == ReadResult.EOF) {
                return null;
            }

            data = onPacketReceived();
        } while (data == null);

        return data;
    }

    private ReadResult onDataReceived(int size) throws IOException, InterruptedException, ExecutionException {
        if (size == -1) {
            return ReadResult.EOF;
        }

        bytesReceived += size;
        bytesLeft -= size;

        if (bytesLeft > 0) {
            return ReadResult.CONTINUE;
        }

        if (bytesReceived == 2) { // Received 2 bytes, length of the buffer
            receiveBuffer.order(ByteOrder.BIG_ENDIAN);
            // Data size is bigendian
            bytesLeft = receiveBuffer.getShort(0);

            // Reallocate our buffer with the new size
            receiveBuffer = ByteBuffer.allocate(2 + bytesLeft);
            receiveBuffer.putShort(bytesLeft);

            return ReadResult.CONTINUE;
        }

        return ReadResult.DONE;
    }

    private InputStream onPacketReceived() throws IOException, InterruptedException, ExecutionException {
        Tunnel.Packet pkt = new Tunnel.Packet(detachBuffer());
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

            sendPacket(new HELOPacket(serverPubkey, tempPubkey, tempPrivkey, getNonce()));
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
        } else if (cmd == CMD_REDY) {
            dataHandler.handleREDY(new REDYPacket(pkt, beforeNm));
            return null;
        } else if (cmd == CMD_MESG) {
            return new MESGPacket(pkt, beforeNm).getPayload();
        } else {
            throw new ProtocolException("Unknown packet received: " + pkt.toString());
        }

        return null;
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

    private ByteBuffer detachBuffer() {
        ByteBuffer buffer = receiveBuffer;

        receiveBuffer = null;
        return buffer;
    }

    private ReadResult blockingReceive() throws IOException, InterruptedException, ExecutionException {
        ReadResult ret;

        do {
            getBuffer();
            int size = s.read(receiveBuffer).get();
            ret = onDataReceived(size);
        } while (ret == ReadResult.CONTINUE);

        return ret;
    }

    /**
     * Start asynchronous data reading
     *
     */
    public void asyncReceive() {
        getBuffer();
        s.read(receiveBuffer, this, readHandler);
    }

    private long getNonce() {
        return nonce++;
    }

    void sendMESG(byte[] data) throws ProtocolException, IOException, InterruptedException, ExecutionException {
        sendPacket(new MESGPacket(getNonce(), beforeNm, data));
    }

    private void handleError(Throwable exc) {
        if (exc instanceof AsynchronousCloseException) {
            // This is not really an error, just someone has called close()
            // during pending read
            logger.debug("Async channel closed");
        } else {
            onError(exc);
        }
    }

    void setState(State s) {
        state = s;
    }

    /**
     * Gets current state of this Connection
     *
     * @return {@link State} value
     */
    public State getState() {
        return state;
    }

    /**
     * Called when an error happens during asynchronous reading
     *
     * @param exc an error description
     */
    protected void onError(Throwable exc) {
        // It's strongly adviced to handle these events, so let's log under error
        // if the developer forgot to do so.
        logger.error("Unhandled async I/O error:", exc);
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
     * after the next pending ping is sent.
     *
     * @param seconds new ping interval is seconds
     */
    public void setPingInterval(int seconds) {
        pingInterval = seconds;
    }

    /**
     * Gets current peer ID for this connection. PeerID is also known as
     * peer's public key.
     *
     * @return peer ID
     */
    public byte[] getPeerId() {
        return serverPubkey;
    }
}
