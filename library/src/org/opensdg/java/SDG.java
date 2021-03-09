package org.opensdg.java;

import java.security.SecureRandom;

import org.eclipse.jdt.annotation.NonNull;
import org.eclipse.jdt.annotation.Nullable;

import com.neilalexander.jnacl.crypto.curve25519xsalsa20poly1305;

public class SDG {
    public static final int KEY_SIZE = curve25519xsalsa20poly1305.crypto_secretbox_PUBLICKEYBYTES;

    public static byte[] randomBytes(int size) {
        byte[] data = new byte[size];

        new SecureRandom().nextBytes(data);
        return data;
    }

    public static byte @NonNull [] createPrivateKey() {
        return randomBytes(KEY_SIZE);
    }

    public static byte @Nullable [] calcPublicKey(byte @NonNull [] privKey) {
        byte[] pubKey = new byte[KEY_SIZE];
        int ret = curve25519xsalsa20poly1305.crypto_box_getpublickey(pubKey, privKey);

        return (ret == 0) ? pubKey : null;
    }
}
