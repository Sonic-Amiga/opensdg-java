package org.opensdg.java;

import org.eclipse.jdt.annotation.NonNull;
import org.opensdg.internal.Utils;

import com.neilalexander.jnacl.NaCl;
import com.neilalexander.jnacl.crypto.curve25519xsalsa20poly1305;

public class SDG {
    public static final int KEY_SIZE = curve25519xsalsa20poly1305.crypto_secretbox_PUBLICKEYBYTES;

    public static byte @NonNull [] createPrivateKey() {
        return Utils.randomBytes(KEY_SIZE);
    }

    public static byte @NonNull [] calcPublicKey(byte @NonNull [] privKey) {
        return Utils.crypto_scalarmult_base(privKey);
    }

    /**
     * Converts hexadecimal string to a binary
     *
     * The input string is suggested to be a valid hexadecimal one, no
     * validation is done.
     *
     * @param hex hexaxdecimal string
     * @return binary value
     */
    public static byte @NonNull [] hex2bin(@NonNull String hex) {
        return NaCl.getBinary(hex);
    }

    /**
     * Converts binary array to a hexadecimal string
     *
     * @param bin binary value
     * @return hexadecimal string
     */
    public static @NonNull String bin2hex(byte @NonNull [] bin) {
        return NaCl.asHex(bin);
    }
}
