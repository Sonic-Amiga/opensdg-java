package org.opensdg.java;

import com.neilalexander.jnacl.crypto.curve25519;

// A very ugly way to take control over randomBytes()
// TODO: Convert InternalUtils to a singletone with override-able members
public class InternalUtils {
    public static byte[] randomBytes(int size) {
        byte[] data = new byte[size];

        for (int i = 0; i < size; i++) {
            data[i] = (byte) i;
        }

        return data;
    }

    public static final int SCALARMULT_BYTES = 32;

    static byte[] crypto_scalarmult_base(byte[] n) {
        byte[] q = new byte[SCALARMULT_BYTES];

        curve25519.crypto_scalarmult_base(q, n);
        return q;
    }
}
