package io.github.sonic_amiga.opensdg.protocol;

import static org.junit.jupiter.api.Assertions.fail;

import java.net.ProtocolException;
import java.nio.ByteBuffer;

import org.junit.jupiter.api.Test;

import io.github.sonic_amiga.opensdg.internal.Utils;
import io.github.sonic_amiga.opensdg.java.SDG;

class HELOPacketTest {

    static {
        // We are in the process of testing, so we want to see everything
        System.setProperty("org.slf4j.simplelogger.defaultlog", "trace");
    }

    static final byte[] serverPubkey = SDG.hex2bin("97BF03FADD1DC842856368A44F84EA3B399F9A96C0BB2835BE00C11D4934F495");
    static final byte[] tempPrivkey = SDG.hex2bin("529B3955D4BA7A76AEF2D1F9ACFE24D1ABD771E70A5D8779646DBF6192329ED0");

    static final long nonce = 0;

    @Test
    void test() {
        byte[] tempPubkey = Utils.crypto_scalarmult_base(tempPrivkey);

        try {
            MDGBinary.HELOPacket pkt = new MDGBinary.HELOPacket(serverPubkey, tempPubkey, tempPrivkey, nonce);
            ByteBuffer data = pkt.getData().rewind();
            // Packet constructors use direct ByteBuffers, so we have to explicitly
            // copy its contents to an array
            byte[] rawData = new byte[data.remaining()];

            pkt.getData().get(rawData);
            System.out.println("Encrypted data = " + SDG.bin2hex(rawData));
        } catch (ProtocolException e) {
            fail("HELOPacket construction failed: " + e.toString());
        }

    }
}
