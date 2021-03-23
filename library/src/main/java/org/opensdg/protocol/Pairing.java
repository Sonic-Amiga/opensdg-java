package org.opensdg.protocol;

import static org.opensdg.java.InternalUtils.SCALARMULT_BYTES;

import java.io.IOException;
import java.io.InputStream;

public class Pairing {
    public static final byte MSG_PAIRING_CHALLENGE = 3;
    public static final byte MSG_PAIRING_RESPONSE = 4;
    public static final byte MSG_PAIRING_RESULT = 5;

    public static final int NONCE_LENGTH = 32;

    public static class ChallengePacket {
        private byte[] X;
        private byte[] nonce;
        private byte[] Y;

        public ChallengePacket(InputStream data) throws IOException {
            X = new byte[SCALARMULT_BYTES];
            nonce = new byte[NONCE_LENGTH];
            Y = new byte[SCALARMULT_BYTES];

            data.read(X);
            data.read(nonce);
            data.read(Y);
        }

        public ChallengePacket(byte[] x, byte[] n, byte[] y) {
            X = x;
            nonce = n;
            Y = y;
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

        public byte[] getData() {
            byte[] data = new byte[1 + SCALARMULT_BYTES * 3];

            data[0] = MSG_PAIRING_CHALLENGE;
            System.arraycopy(X, 0, data, 1, SCALARMULT_BYTES);
            System.arraycopy(nonce, 0, data, 1 + SCALARMULT_BYTES, SCALARMULT_BYTES);
            System.arraycopy(Y, 0, data, 1 + SCALARMULT_BYTES * 2, SCALARMULT_BYTES);
            return data;
        }
    }

    public static class ResponsePacket {
        private byte[] X;
        private byte[] Y;

        public ResponsePacket(byte[] x, byte[] y) {
            X = x;
            Y = y;
        }

        public ResponsePacket(InputStream data) throws IOException {
            X = new byte[SCALARMULT_BYTES];
            Y = new byte[SCALARMULT_BYTES];

            data.read(X);
            data.read(Y);
        }

        public byte[] getData() {
            byte[] data = new byte[1 + SCALARMULT_BYTES * 2];

            data[0] = MSG_PAIRING_RESPONSE;
            System.arraycopy(X, 0, data, 1, SCALARMULT_BYTES);
            System.arraycopy(Y, 0, data, 1 + SCALARMULT_BYTES, SCALARMULT_BYTES);
            return data;
        }

        public byte[] getX() {
            return X;
        }

        public byte[] getY() {
            return Y;
        }
    }

    public static class ResultPacket {
        private byte[] result;

        public ResultPacket(InputStream data) throws IOException {
            result = new byte[SCALARMULT_BYTES];
            data.read(result);
        }

        public ResultPacket(byte[] res) {
            result = res;
        }

        public byte[] getData() {
            byte[] data = new byte[1 + SCALARMULT_BYTES];

            data[0] = MSG_PAIRING_RESULT;
            System.arraycopy(result, 0, data, 1, SCALARMULT_BYTES);
            return data;
        }

        public byte[] getResult() {
            return result;
        }
    }
}
