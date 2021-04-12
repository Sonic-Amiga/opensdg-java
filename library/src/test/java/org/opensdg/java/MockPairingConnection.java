package org.opensdg.java;

import static org.junit.jupiter.api.Assertions.*;
import static org.opensdg.internal.Utils.SCALARMULT_BYTES;
import static org.opensdg.protocol.Pairing.MSG_PAIRING_RESPONSE;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Queue;

import org.eclipse.jdt.annotation.Nullable;
import org.opensdg.protocol.Pairing.ResponsePacket;
import org.opensdg.protocol.generated.ControlProtocol.PeerReply;

public class MockPairingConnection extends PairingConnection {
    private Queue<byte[]> injectedData;

    MockPairingConnection(Queue<byte[]> packets) {
        injectedData = packets;
    }

    @Override
    protected void startForwarding(PeerReply reply) {
        // Do nothing here
    }

    @Override
    protected byte[] getSalt() {
        byte[] data = new byte[SCALARMULT_BYTES];

        for (int i = 0; i < SCALARMULT_BYTES; i++) {
            data[i] = (byte) i;
        }

        return data;
    }

    @Override
    public @Nullable InputStream receiveData() {
        return new ByteArrayInputStream(injectedData.remove());
    }

    @Override
    public void sendData(byte[] data) {
        ByteArrayInputStream input = new ByteArrayInputStream(data);

        assertEquals(MSG_PAIRING_RESPONSE, input.read());

        try {
            ResponsePacket response = new ResponsePacket(input);

            System.out.println("X = " + SDG.bin2hex(response.getX()));
            System.out.println("Y = " + SDG.bin2hex(response.getY()));
        } catch (IOException e) {
            fail("Error parsing ResponsePacket: " + e.toString());
        }
    }
}
