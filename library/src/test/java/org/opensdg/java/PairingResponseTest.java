package org.opensdg.java;

import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayDeque;
import java.util.concurrent.ExecutionException;

import javax.xml.bind.DatatypeConverter;

import org.junit.jupiter.api.Test;
import org.opensdg.protocol.Pairing.ChallengePacket;
import org.opensdg.protocol.Pairing.ResultPacket;

class PairingResponseTest {

    static {
        // We are in the process of testing, so we want to see everything
        System.setProperty("org.slf4j.simplelogger.defaultlog", "trace");
    }

    static final byte[] clientPrivkey = DatatypeConverter.parseHexBinary(
            "97BF03FADD1DC842856368A44F84EA3B399F9A96C0BB2835BE00C11D4934F495529B3955D4BA7A76AEF2D1F9ACFE24D1ABD771E70A5D8779646DBF6192329ED0");
    static final byte[] serverPubkey = DatatypeConverter.parseHexBinary(
            "314164D582A29A9A239D01158BE40BE37CC46EFE1EF60F3F7F396F91FF0266CB44CDE20409DB4BF509B8EF4E98C4AF58C62AF67DE34209DD4D35F619322B238F");
    static final byte[] beforenm = DatatypeConverter
            .parseHexBinary("A5EFF81AD594D5A11F42120170249DEE0BDC16FE512DB291C48EC024DE4081E9");

    static final byte[] X = DatatypeConverter
            .parseHexBinary("5D4F9A5980C946224C33A400932716131E9560558E9F4154F7740A4642BAFC5D");
    static final byte[] nonce = DatatypeConverter
            .parseHexBinary("1B28D7480ADA3AA9BDC5933570E997DFC1EBF7A036F9E646AC0A111765B55D93");
    static final byte[] Y = DatatypeConverter
            .parseHexBinary("96C0B7AEF0CE9DBEA3CDC47957A9219FF8038D36550A1BF983F5510946B09A3F");
    static final String otp = "1234567";

    static final byte[] result = DatatypeConverter
            .parseHexBinary("93582D3E66A750B14724F7AF53ADDA4CC3A243BD1BBDB1C9E20E9A2F9E875FDD");

    @Test
    void test() {
        ArrayDeque<byte[]> packets = new ArrayDeque<byte[]>();

        packets.add(new ChallengePacket(X, nonce, Y).getData());
        packets.add(new ResultPacket(result).getData());

        MockGrid grid = new MockGrid(clientPrivkey);
        MockPairingConnection pairing = new MockPairingConnection(serverPubkey, beforenm, packets);

        try {
            pairing.pairWithRemote(grid, otp);
        } catch (InterruptedException | ExecutionException | IOException | GeneralSecurityException e) {
            fail("pairWithRemote() failed: " + e.toString());
        }

    }

}
