package org.opensdg.java;

import static org.junit.jupiter.api.Assertions.*;
import static org.opensdg.protocol.Pairing.MSG_PAIRING_RESPONSE;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Queue;

import javax.xml.bind.DatatypeConverter;

import org.eclipse.jdt.annotation.Nullable;
import org.opensdg.protocol.Pairing.ResponsePacket;
import org.opensdg.protocol.generated.ControlProtocol.PeerReply;

public class MockPairingConnection extends PairingConnection {
    private Queue<byte[]> injectedData;

    MockPairingConnection(byte[] serverPublicKey, byte[] beforenm, Queue<byte[]> packets) {
        serverPubkey = serverPublicKey;
        beforeNm = beforenm;
        injectedData = packets;
    }

    @Override
    protected void startForwarding(PeerReply reply) {
        // Do nothing here
    }

    @Override
    public @Nullable InputStream receiveData() {
        return new ByteArrayInputStream(injectedData.remove());
    }

    @Override
    protected void sendMESG(byte[] data) {
        ByteArrayInputStream input = new ByteArrayInputStream(data);

        assertEquals(MSG_PAIRING_RESPONSE, input.read());

        try {
            ResponsePacket response = new ResponsePacket(input);

            System.out.println("X = " + DatatypeConverter.printHexBinary(response.getX()));
            System.out.println("Y = " + DatatypeConverter.printHexBinary(response.getY()));
        } catch (IOException e) {
            fail("Error parsing ResponsePacket: " + e.toString());
        }
    }
}
