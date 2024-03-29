package io.github.sonic_amiga.opensdg.java;

import static io.github.sonic_amiga.opensdg.internal.Utils.SCALARMULT_BYTES;
import static io.github.sonic_amiga.opensdg.protocol.Pairing.*;

import java.io.IOException;
import java.io.InputStream;
import java.net.ProtocolException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.neilalexander.jnacl.crypto.curve25519;
import com.neilalexander.jnacl.crypto.xsalsa20;

import io.github.sonic_amiga.opensdg.internal.Utils;
import io.github.sonic_amiga.opensdg.internal.Utils.Hexdump;
import io.github.sonic_amiga.opensdg.protocol.Pairing.ChallengePacket;
import io.github.sonic_amiga.opensdg.protocol.Pairing.ResponsePacket;
import io.github.sonic_amiga.opensdg.protocol.Pairing.ResultPacket;
import io.github.sonic_amiga.opensdg.protocol.generated.ControlProtocol.PeerReply;

public class PairingConnection extends PeerConnection {
    private final Logger logger = LoggerFactory.getLogger(PairingConnection.class);
    private static final int SHA512_LENGTH = 64;

    private String otp;
    private byte[] expectedResult = new byte[SCALARMULT_BYTES];

    public void pairWithRemote(GridConnection grid, String otp)
            throws InterruptedException, ExecutionException, IOException, GeneralSecurityException, TimeoutException {
        init(grid);

        // Filter the OTP, leaving only digits. The original library does the same.
        this.otp = otp.replaceAll("^0-9", "");
        // We never send the whole OTP to the Grid, i guess for security.
        // It looks like the generation algorithm takes care about first digits to be unique
        String otpServerPart = this.otp.substring(0, this.otp.length() - 3);

        try {
            PeerReply reply = grid.pair(otpServerPart).get();
            startForwarding(reply);

            ReadResult ret = ReadResult.CONTINUE;

            do {
                InputStream data = receiveData();

                if (data != null) {
                    ret = handlePairingPacket(data);
                }
            } while (ret != ReadResult.DONE);
        } catch (Exception e) {
            close();
            throw e;
        }
    }

    @Override
    protected final void onDataReceived(InputStream data) {
        try {
            if (handlePairingPacket(data) == ReadResult.DONE) {
                onPairingSuccess();
            }
        } catch (IOException | GeneralSecurityException | InterruptedException | ExecutionException
                | TimeoutException e) {
            handleError(e);
        }
    }

    protected void onPairingSuccess() {
        // TODO: Implement async pairing.
    }

    private static byte[] crypto_scalarmult(byte[] n, byte[] p) {
        byte[] q = new byte[SCALARMULT_BYTES];

        curve25519.crypto_scalarmult(q, n, p);
        return q;
    }

    // This is probably not good, but this is the only easy way to replace
    // random data for unit test.
    protected byte[] getSalt() {
        return Utils.randomBytes(SCALARMULT_BYTES);
    }

    // Pairing protocol is a challenge-response, designed to verify the OTP
    // (which both sides know) without actually sending it.
    private ReadResult handlePairingPacket(InputStream data)
            throws IOException, InterruptedException, ExecutionException, GeneralSecurityException, TimeoutException {
        int cmd = data.read();

        switch (cmd) {
            case MSG_PAIRING_CHALLENGE:
                ChallengePacket challenge = new ChallengePacket(data);
                logger.trace("Received MSG_PAIRING_CHALLENGE");
                logger.trace("X     {}", new Hexdump(challenge.getX()));
                logger.trace("nonce {}", new Hexdump(challenge.getNonce()));
                logger.trace("Y     {}", new Hexdump(challenge.getY()));

                int l = otp.length();
                // innerHash = sha512(otp + clientPubkey + serverPubkey)
                byte[] innerHash = new byte[SHA512_LENGTH + NONCE_LENGTH];
                byte[] buf = new byte[l + SDG.KEY_SIZE * 2];
                MessageDigest sha512 = MessageDigest.getInstance("SHA-512");

                System.arraycopy(otp.getBytes(), 0, buf, 0, l);
                System.arraycopy(getMyPeerId(), 0, buf, l, SDG.KEY_SIZE);
                System.arraycopy(getPeerId(), 0, buf, l + SDG.KEY_SIZE, SDG.KEY_SIZE);
                sha512.update(buf, 0, l + SDG.KEY_SIZE * 2);
                sha512.digest(innerHash, 0, SHA512_LENGTH);

                // hash = sha512(innerHash + challenge.nonce)
                System.arraycopy(challenge.getNonce(), 0, innerHash, SHA512_LENGTH, NONCE_LENGTH);
                byte[] hash = sha512.digest(innerHash);

                // challenge.Y is some test message. Probably random. Encrypt it using
                // the supplied nonce and calculated hash as a key.
                byte[] xor = new byte[SCALARMULT_BYTES];
                xsalsa20.crypto_stream_xor(xor, challenge.getY(), SCALARMULT_BYTES, challenge.getNonce(), hash);

                // The following is a pure mathemagic i have completely zero understanding of. :(
                byte[] base = Utils.crypto_scalarmult_base(tunnel.getBeforeNm());
                byte[] p1 = crypto_scalarmult(xor, base);
                byte[] salt = getSalt();
                byte[] responseX = crypto_scalarmult(salt, p1);

                byte[] p2 = crypto_scalarmult(salt, challenge.getX());
                // This is used in both hashing rounds below, avoid copying twice
                System.arraycopy(p2, 0, innerHash, SHA512_LENGTH, SCALARMULT_BYTES);

                sha512.update(challenge.getX());
                sha512.digest(innerHash, 0, SHA512_LENGTH);
                // responseY = sha512(sha512(challenge.X) + p2
                // Note that it will be trimmed, only first 32 bytes are sent
                byte[] responseY = sha512.digest(innerHash);

                // pairingResult = sha512(sha512(response.X) + p2
                sha512.update(responseX);
                sha512.digest(innerHash, 0, SHA512_LENGTH);
                byte[] expected = sha512.digest(innerHash);
                // ... but use only first 32 bytes
                System.arraycopy(expected, 0, expectedResult, 0, SCALARMULT_BYTES);
                logger.trace("Expected result: {}", new Hexdump(expectedResult));

                ResponsePacket response = new ResponsePacket(responseX, responseY);
                sendData(response.getData());
                break;

            case MSG_PAIRING_RESULT:
                ResultPacket resultPkt = new ResultPacket(data);
                byte[] result = resultPkt.getResult();

                logger.trace("Received MSG_PAIRING_RESULT");
                logger.trace("Result: {}", new Hexdump(result));

                // Compare the result like the original library does, just in case
                if (!Arrays.equals(expectedResult, result)) {
                    throw new ProtocolException("Received incorrect pairing reply");
                }

                logger.debug("MSG_PAIRING_RESULT successful");
                return ReadResult.DONE;
        }

        return ReadResult.CONTINUE;
    }
}
