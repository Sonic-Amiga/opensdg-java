package org.opensdg.java;

import static org.opensdg.protocol.Pairing.*;

import java.io.IOException;
import java.io.InputStream;
import java.net.ProtocolException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.concurrent.ExecutionException;

import org.opensdg.protocol.Pairing.ChallengePacket;
import org.opensdg.protocol.Pairing.ResponsePacket;
import org.opensdg.protocol.Pairing.ResultPacket;
import org.opensdg.protocol.generated.ControlProtocol.PeerReply;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.neilalexander.jnacl.crypto.curve25519;
import com.neilalexander.jnacl.crypto.salsa20;

public class PairingConnection extends PeerConnection {
    private final Logger logger = LoggerFactory.getLogger(PairingConnection.class);
    private static final int SHA512_LENGTH = 64;

    private String otp;
    private byte[] pairingResult;
    private boolean pairingDone;

    public void pairWithRemote(GridConnection grid, String otp)
            throws InterruptedException, ExecutionException, IOException, GeneralSecurityException {
        checkState(State.CLOSED);
        state = State.CONNECTING;
        // Copy client keys from the grid connection.
        clientPubkey = grid.clientPubkey;
        clientPrivkey = grid.clientPrivkey;

        pairingDone = false;
        // Filter the OTP, leaving only digits. The original library does the same.
        this.otp = otp.replaceAll("^0-9", "");
        // We never send the whole OTP to the Grid, i guess for security.
        // It looks like the generation algorithm takes care about first digits to be unique
        String otpServerPart = this.otp.substring(0, this.otp.length() - 3);

        PeerReply reply = grid.pair(otpServerPart).get();
        startForwarding(reply);

        InputStream data;
        do {
            data = receiveData();
            if (data != null) {
                onPairingDataReceived(data);
            }
        } while (!pairingDone);
    }

    @Override
    protected final void onDataReceived(InputStream data) {
        try {
            onPairingDataReceived(data);
        } catch (IOException | GeneralSecurityException | InterruptedException | ExecutionException e) {
            onError(e);
        }
    }

    private static byte[] crypto_scalarmult(byte[] n, byte[] p) {
        byte[] q = new byte[SCALARMULT_BYTES];

        curve25519.crypto_scalarmult(q, n, p);
        return q;
    }

    private void onPairingDataReceived(InputStream data)
            throws IOException, InterruptedException, ExecutionException, GeneralSecurityException {
        int cmd = data.read();

        switch (cmd) {
            case MSG_PAIRING_CHALLENGE:
                ChallengePacket challenge = new ChallengePacket(data);
                logger.trace("Received {}", challenge);
                logger.trace("X     {}", new Hexdump(challenge.getX()));
                logger.trace("nonce {}", new Hexdump(challenge.getNonce()));
                logger.trace("Y     {}", new Hexdump(challenge.getY()));

                int l = otp.length();
                // innerHash = sha512(otp + clientPubkey + serverPubkey)
                byte[] innerHash = new byte[SHA512_LENGTH + NONCE_LENGTH];
                byte[] buf = new byte[l + SDG.KEY_SIZE * 2];
                MessageDigest sha512 = MessageDigest.getInstance("SHA-512");

                System.arraycopy(otp.getBytes(), 0, buf, 0, l);
                System.arraycopy(clientPubkey, l, buf, cmd, SDG.KEY_SIZE);
                System.arraycopy(serverPubkey, l + SDG.KEY_SIZE, buf, cmd, SDG.KEY_SIZE);
                sha512.update(buf, 0, l + SDG.KEY_SIZE * 2);
                sha512.digest(innerHash, 0, SHA512_LENGTH);

                // hash = sha512(innerHash + challenge.nonce)
                System.arraycopy(challenge.getNonce(), 0, innerHash, SHA512_LENGTH, l);
                byte[] hash = sha512.digest(innerHash);

                // The following is a pure mathemagic i have completely zero understanding of. :(
                byte[] xor = new byte[32];
                salsa20.crypto_stream_xor(xor, challenge.getY(), 32, challenge.getNonce(), 0, hash);

                byte[] base = new byte[SCALARMULT_BYTES];
                curve25519.crypto_scalarmult_base(base, beforeNm);

                byte[] p1 = crypto_scalarmult(xor, base);
                byte[] rnd = SDG.randomBytes(SCALARMULT_BYTES);
                byte[] responseX = crypto_scalarmult(rnd, p1);

                byte[] p2 = crypto_scalarmult(rnd, challenge.getX());
                // This is used in both hashing rounds below, avoid copying twice
                System.arraycopy(p2, 0, innerHash, SHA512_LENGTH, SCALARMULT_BYTES);

                sha512.update(challenge.getX());
                sha512.digest(innerHash, 0, SHA512_LENGTH);
                // responseY = sha512(sha512(challenge.X) + p2
                byte[] responseY = sha512.digest(innerHash);

                // pairingResult = sha512(sha512(response.X) + p2
                sha512.update(responseX);
                sha512.digest(innerHash, 0, SHA512_LENGTH);
                pairingResult = sha512.digest(innerHash);

                ResponsePacket response = new ResponsePacket(responseX, responseY);
                sendData(response.getData());
                break;

            case MSG_PAIRING_RESULT:
                ResultPacket result = new ResultPacket(data);

                if (result.gerResult().equals(pairingResult)) {
                    logger.debug("MSG_PAIRING_RESULT successful");
                    pairingDone = true;
                } else {
                    throw new ProtocolException("Received incorrect pairing reply");
                }
                break;
        }
    }
}
