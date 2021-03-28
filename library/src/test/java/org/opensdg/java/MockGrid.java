package org.opensdg.java;

import org.opensdg.protocol.MockTunnel;

public class MockGrid extends GridConnection {

    public MockGrid(byte[] clientPrivateKey) {
        super(clientPrivateKey);

        // Replace the Tunnel with a mock
        tunnel = new MockTunnel(tunnel.getMyPeerId(), this);
    }

    @Override
    ForwardRequest pair(String otp) {
        ForwardRequest request = new ForwardRequest(0);

        request.reportDone(null);
        return request;
    }
}
