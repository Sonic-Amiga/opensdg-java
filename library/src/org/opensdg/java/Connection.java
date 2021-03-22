package org.opensdg.java;

import static org.opensdg.protocol.Tunnel.*;

import java.io.EOFException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ProtocolException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.AsynchronousCloseException;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.util.concurrent.ExecutionException;

import javax.xml.bind.DatatypeConverter;

import org.opensdg.protocol.Tunnel;
import org.opensdg.protocol.Tunnel.COOKPacket;
import org.opensdg.protocol.Tunnel.HELOPacket;
import org.opensdg.protocol.Tunnel.MESGPacket;
import org.opensdg.protocol.Tunnel.REDYPacket;
import org.opensdg.protocol.Tunnel.TELLPacket;
import org.opensdg.protocol.Tunnel.VOCHPacket;
import org.opensdg.protocol.Tunnel.WELCPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.neilalexander.jnacl.crypto.curve25519xsalsa20poly1305;

/**
 * This class represents a single connection over the Grid.
 *
 * A Connection is an encrypted channel, using asymmetric encryption
 * based on public and private keys. A public key is also known as a
 * peer ID; it's used to identify the peer on a network.
 *
 * In order to establish a connection to a remote host over the Grid,
 * you need a {@link PeerConnection} to perform the actual communication
 * and a {@link GridConnection}, representing a particular Grid which the
 * given peer is on.
 *
 * @author Pavel Fedin
 */
public abstract class Connection {
    private final Logger logger = LoggerFactory.getLogger(Connection.class);

    /**
     * An easy-to-use utility for printing hex dumps
     *
     */
    protected static class Hexdump {
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
                ReadResult ret = conn.onRawDataReceived(result);

                switch (ret) {
                    case EOF:
                        conn.handleError(getEOFException());
                        return;
                    case DONE:
                        MESGPacket data = conn.onPacketReceived();
                        if (data != null) {
                            conn.handleMESG(data);
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

    protected static EOFException getEOFException() {
        return new EOFException("Connection closed by peer");
    }

    protected State state = State.CLOSED;

    private AsynchronousSocketChannel s;

    private ByteBuffer receiveBuffer;
    private short bytesLeft;
    private int bytesReceived;

    protected byte[] clientPubkey;
    protected byte[] clientPrivkey;
    protected byte[] serverPubkey;
    private byte[] tempPubkey;
    private byte[] tempPrivkey;
    protected byte[] beforeNm;
    private long nonce;

    private CompletionHandler<Integer, Connection> readHandler = new ReadHandler();

    protected void openSocket(String host, int port) throws IOException, InterruptedException, ExecutionException {
        s = AsynchronousSocketChannel.open();
        s.connect(new InetSocketAddress(host, port)).get();
        logger.debug("Connected to {}:{}", host, port);
    }

    /**
     * Establish encrypted tunnel on this Connection
     *
     */
    protected void startTunnel() throws IOException, InterruptedException, ExecutionException {
        // Initialize nonce counter
        nonce = 0;
        // Start encrypted tunnel establishment by sending TELL packet
        sendPacket(new TELLPacket());

        do {
            ReadResult ret = receiveRawPacket();

            if (ret == ReadResult.EOF) {
                throw getEOFException();
            }

            // Tunnel handshake also includes handling some MESG packets,
            // and normally the handler would be called only for async read,
            // so call it here explicitly. The handler will set our state to
            // CONNECTED when done
            MESGPacket msgData = onPacketReceived();
            if (msgData != null) {
                handleMESG(msgData);
            }

        } while (state != State.CONNECTED);
    }

    /**
     * Close the connection
     *
     * For convenience it's allowed to call close() on an already closed
     * connection, it will do nothing. A closed {@link Connection} object can be reused.
     *
     */
    public void close() throws IOException {
        if (state == State.CLOSED) {
            return;
        }

        AsynchronousSocketChannel ch = s;
        s = null;

        if (ch != null) {
            ch.close();
        }

        state = State.CLOSED;
    }

    private void sendPacket(Tunnel.Packet pkt) throws IOException, InterruptedException, ExecutionException {
        logger.trace("Sending packet: {}", pkt);
        sendRawData(pkt.getData());
    }

    /**
     * Synchronously send a raw data buffer
     *
     * Keeps writing synchronously until the full packet has been written
     *
     */
    protected synchronized void sendRawData(ByteBuffer data)
            throws IOException, InterruptedException, ExecutionException {
        int size = data.capacity();

        data.position(0);

        while (size > 0) {
            int ret = s.write(data).get();
            size -= ret;
        }
    }

    /**
     * Start asynchronous data receiving
     *
     * Initiates asynchronous data handling on the Connection.
     * {@link onDataReceived} or {@link onError} will be called accordingly
     *
     */
    public void asyncReceive() {
        getBuffer();
        s.read(receiveBuffer, this, readHandler);
    }

    /**
     * Synchronously a raw packet into buffer
     *
     * Keeps reading synchronosly until the full packet has been read
     * or EOF reached
     *
     */
    protected ReadResult receiveRawPacket() throws IOException, InterruptedException, ExecutionException {
        ReadResult ret;

        do {
            getBuffer();
            int size = s.read(receiveBuffer).get();
            ret = onRawDataReceived(size);
        } while (ret == ReadResult.CONTINUE);

        return ret;
    }

    /**
     * Handle receiving raw data
     *
     * Advances current read buffer pointer, performing reallocation when needed
     *
     * @param size Number of bytes received
     */
    private ReadResult onRawDataReceived(int size) throws IOException, InterruptedException, ExecutionException {
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

    /**
     * Parse an incoming raw packet
     *
     * Inteprprets packet's contents and replies when needed.
     * For MESG packet payload will be retrieved and returned.
     *
     * @return Data to be passed over to the client or null if there's no one
     */
    protected MESGPacket onPacketReceived() throws IOException, InterruptedException, ExecutionException {
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
            handleREDY(new REDYPacket(pkt, beforeNm));
            return null;
        } else if (cmd == CMD_MESG) {
            return new MESGPacket(pkt, beforeNm);
        } else {
            throw new ProtocolException("Unknown packet received: " + pkt.toString());
        }

        return null;
    }

    abstract void handleREDY(REDYPacket pkt) throws IOException, InterruptedException, ExecutionException;

    abstract void handleMESG(MESGPacket pkt) throws IOException, InterruptedException, ExecutionException;

    private void getBuffer() {
        if (receiveBuffer == null) {
            // Start receiving a new packet.
            // Every packet is prefixed with length, read it first
            receiveBuffer = ByteBuffer.allocate(2);
            bytesReceived = 0;
            bytesLeft = 2;
        }
    }

    protected ByteBuffer detachBuffer() {
        ByteBuffer buffer = receiveBuffer;

        receiveBuffer = null;
        return buffer;
    }

    private long getNonce() {
        return nonce++;
    }

    protected void sendMESG(byte[] data)
            throws ProtocolException, IOException, InterruptedException, ExecutionException {
        sendPacket(new MESGPacket(getNonce(), beforeNm, data));
    }

    /**
     * This function is called if internal processing fails.
     * E. g. failed to respond to a packet. It takes care about internal normal events,
     * like asynchronous close.
     *
     */
    protected void handleError(Throwable exc) {
        if (exc instanceof AsynchronousCloseException) {
            // This is not really an error, just someone has called close()
            // during pending read
            logger.debug("Async channel closed");
        } else {
            onError(exc);
        }
    }

    protected void checkState(State required) {
        if (state != required) {
            throw new IllegalStateException(
                    "Bad Connection state " + state + " for the call; required state " + required);
        }
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
        // It's strongly advised to handle these events, so let's log under error
        // if the developer forgot to do so.
        logger.error("Unhandled async I/O error:", exc);
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
