package org.opensdg.java;

import javax.xml.bind.DatatypeConverter;

public class MockGrid extends GridConnection {

    static final byte[] X = DatatypeConverter.parseHexBinary("8D259ECEF891F10F09BD848E3C7BB0D4");
    static final byte[] nonce = DatatypeConverter.parseHexBinary("7A5C452A0FC09C46E681A80A2E7B938C");
    static final byte[] Y = DatatypeConverter.parseHexBinary("6765471CC9D46AF9F9884003949E573F");

    public MockGrid(byte[] clientPrivateKey) {
        super(clientPrivateKey);
    }

    @Override
    ForwardRequest pair(String otp) {
        ForwardRequest request = new ForwardRequest(0);

        request.reportDone(null);
        return request;
    }
}
