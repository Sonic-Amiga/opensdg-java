package org.opensdg.internal;

import java.security.SecureRandom;

import org.opensdg.java.SDG;

import com.neilalexander.jnacl.crypto.curve25519;

/**
 * A random collection of utilities for internal purposes.
 *
 * Please do not use from outside of the library!
 *
 * @author Pavel Fedin
 */
public class Utils {
    static SecureRandom rnd = new SecureRandom();

    public static byte[] randomBytes(int size) {
        byte[] data = new byte[size];

        rnd.nextBytes(data);
        return data;
    }

    public static final int SCALARMULT_BYTES = 32;

    public static byte[] crypto_scalarmult_base(byte[] n) {
        byte[] q = new byte[SCALARMULT_BYTES];

        curve25519.crypto_scalarmult_base(q, n);
        return q;
    }

    /**
     * An easy-to-use utility for printing hex dumps
     *
     */
    public static class Hexdump {
        byte[] data;

        public Hexdump(byte[] raw_key) {
            data = raw_key;
        }

        @Override
        public String toString() {
            return SDG.bin2hex(data);
        }
    }
}
