package org.opensdg.protocol;

import java.io.IOException;
import java.io.InputStream;
import java.net.ProtocolException;
import java.nio.ByteBuffer;
import java.util.concurrent.ExecutionException;

import org.opensdg.java.Connection;
import org.opensdg.java.Connection.ReadResult;
import org.opensdg.java.SDG;

public class MockTunnel extends EncryptedProtocol {

    byte[] clientPubkey;

    static final byte[] serverPubkey = SDG.hex2bin(
            "314164D582A29A9A239D01158BE40BE37CC46EFE1EF60F3F7F396F91FF0266CB44CDE20409DB4BF509B8EF4E98C4AF58C62AF67DE34209DD4D35F619322B238F");
    static final byte[] beforenm = SDG.hex2bin("A5EFF81AD594D5A11F42120170249DEE0BDC16FE512DB291C48EC024DE4081E9");

    public MockTunnel(byte[] myPeerId, Connection conn) {
        super(conn);
        clientPubkey = myPeerId;
    }

    @Override
    public MockTunnel makePeerTunnel(Connection conn) {
        return new MockTunnel(clientPubkey, conn);
    }

    @Override
    protected ReadResult onPacketReceived(ByteBuffer data)
            throws IOException, InterruptedException, ExecutionException {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public void sendData(byte[] data) throws ProtocolException, IOException, InterruptedException, ExecutionException {
        // TODO Auto-generated method stub

    }

    @Override
    public InputStream getData() throws ProtocolException {
        // TODO Auto-generated method stub
        return null;
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
        return beforenm;
    }
}
