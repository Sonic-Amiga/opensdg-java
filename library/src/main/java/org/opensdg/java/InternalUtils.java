package org.opensdg.java;

import java.security.SecureRandom;

import com.neilalexander.jnacl.crypto.curve25519;

/**
 * A random collection of utilities for internal purposes.
 *
 * Please do not use from outside of the library!
 *
 * @author Pavel Fedin
 */
public class InternalUtils {
    public static byte[] randomBytes(int size) {
        byte[] data = new byte[size];

        new SecureRandom().nextBytes(data);
        return data;
    }

    public static final int SCALARMULT_BYTES = 32;

    static byte[] crypto_scalarmult_base(byte[] n) {
        byte[] q = new byte[SCALARMULT_BYTES];

        curve25519.crypto_scalarmult_base(q, n);
        return q;
    }
}