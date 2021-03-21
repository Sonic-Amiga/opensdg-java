package org.opensdg.protocol;

import java.io.IOException;
import java.io.InputStream;

public class Pairing {
    public static final byte MSG_PAIRING_CHALLENGE = 3;
    public static final byte MSG_PAIRING_RESPONSE = 4;
    public static final byte MSG_PAIRING_RESULT = 5;

    public static final int NONCE_LENGTH = 32;
    public static final int SCALARMULT_BYTES = 32;

    public static class ChallengePacket {
        private byte[] X = new byte[SCALARMULT_BYTES];
        private byte[] nonce = new byte[NONCE_LENGTH];
        private byte[] Y = new byte[SCALARMULT_BYTES];

        public ChallengePacket(InputStream data) throws IOException {
            data.read(X);
            data.read(nonce);
            data.read(Y);
        }

        public byte[] getX() {
            return X;
        }

        public byte[] getNonce() {
            return nonce;
        }

        public byte[] getY() {
            return Y;
        }

        @Override
        public String toString() {
            return "MSG_CHALLENGE";
        }
    }

    public static class ResponsePacket {
        private byte[] X;
        private byte[] Y;

        public ResponsePacket(byte[] x, byte[] y) {
            X = x;
            Y = y;
        }

        public byte[] getData() {
            byte[] data = new byte[1 + SCALARMULT_BYTES * 2];

            data[0] = MSG_PAIRING_RESPONSE;
            System.arraycopy(X, 0, data, 1, SCALARMULT_BYTES);
            System.arraycopy(Y, 0, data, 1 + SCALARMULT_BYTES, SCALARMULT_BYTES);
            return data;
        }
    }

    public static class ResultPacket {
        private byte[] result = new byte[SCALARMULT_BYTES];

        public ResultPacket(InputStream data) throws IOException {
            data.read(result);
        }

        public byte[] gerResult() {
            return result;
        }
    }
}
