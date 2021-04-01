package org.opensdg.java;

import org.eclipse.jdt.annotation.NonNull;
import org.opensdg.internal.Utils;

import com.neilalexander.jnacl.crypto.curve25519xsalsa20poly1305;

public class SDG {
    public static final int KEY_SIZE = curve25519xsalsa20poly1305.crypto_secretbox_PUBLICKEYBYTES;

    public static byte @NonNull [] createPrivateKey() {
        return Utils.randomBytes(KEY_SIZE);
    }

    public static byte @NonNull [] calcPublicKey(byte @NonNull [] privKey) {
        return Utils.crypto_scalarmult_base(privKey);
    }
}
