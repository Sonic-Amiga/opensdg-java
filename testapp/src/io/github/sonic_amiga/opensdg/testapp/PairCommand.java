package io.github.sonic_amiga.opensdg.testapp;

import java.io.DataInputStream;

import org.opensdg.java.PairingConnection;
import org.opensdg.java.PeerConnection;
import org.opensdg.java.SDG;

import com.google.gson.Gson;

public class PairCommand extends CommandHandler {

    private final Gson gson = new Gson();

    // A request is sent in a JSON format.
    // chunkedMessage field specifies whether the data will be split into
    // several packets. It is advised to always set it to true because original
    // mdglib on a phone may have hardcoded maximum buffer size, which is small enough,
    // so that sending config will crash if you have many devices.
    static public class ConfigRequest {
        String phoneName;
        String phonePublicKey;
        boolean chunkedMessage;

        ConfigRequest(String name, String myPeerId) {
            phoneName = name;
            phonePublicKey = myPeerId;
            chunkedMessage = true;
        }
    }

    @Override
    public int numRequiredArgs() {
        return 1;
    }

    @Override
    public void Execute(String[] command) {
        PairingConnection pairingConn = new PairingConnection();

        try {
            pairingConn.pairWithRemote(Main.grid, command[1]);
        } catch (Exception e) {
            Main.printError("Pairing failed", e);
            return;
        }

        byte[] peerId = pairingConn.getPeerId();

        if (peerId == null) {
            // This will never happen, just satisfy the null checker
            System.err.print("Unexpected: getPeerId() returns null");
            return;
        }

        System.out.println("Pairing successful, peer ID is " + SDG.bin2hex(peerId));
        try {
            pairingConn.close();
        } catch (Exception e) {
            Main.printError("Failed to close pairing connection", e);
        }

        // In case of DeviReg Smart(tm) we are pairing with the phone, not with the actual hardware.
        // The phone then allows us to establish a data connection in order to download information
        // about the real hardware this time. This will include peer IDs. The phone will also add
        // our own peer ID to the hardware's white list.
        PeerConnection peerConn = new PeerConnection();

        try {
            peerConn.connectToRemote(Main.grid, peerId, "dominion-configuration-1.0");
        } catch (Exception e) {
            Main.printError("Failed to establish data connection", e);
            return;
        }

        byte[] myId = Main.grid.getMyPeerId();

        if (myId == null) {
            // This will never happen, just satisfy the null checker
            System.err.print("Unexpected: getMyPeerId() returns null");
            return;
        }

        String myPeerId = SDG.bin2hex(myId).toLowerCase();
        ConfigRequest request = new ConfigRequest("OSDG-Java test", myPeerId);
        String json = gson.toJson(request);

        try {
            peerConn.sendData(json.getBytes());
        } catch (Exception e) {
            Main.printError("Failed to send config request", e);
            return;
        }

        int dataSize = 0;
        int offset = 0;
        byte[] data = null;

        try {
            do {
                DataInputStream chunk = new DataInputStream(peerConn.receiveData());
                int chunkSize = chunk.available();

                if (chunkSize > 8) {
                    // In chunked mode the data will arrive in several packets.
                    // The first one will contain the header, specifying full data length.
                    // The header has integer 0 in the beginning so that it's easily distinguished
                    // from JSON plaintext
                    if (chunk.readInt() == 0) {
                        // Size is little-endian here
                        dataSize = Integer.reverseBytes(chunk.readInt());
                        System.out.println("Chunked mode; full size = " + dataSize);
                        data = new byte[dataSize];
                        chunkSize -= 8; // We've consumed the header
                    } else {
                        // No header, go back to the beginning
                        chunk.reset();
                    }
                }

                if (dataSize == 0) {
                    // If the first packet didn't contain the header, this is not
                    // a chunked mode, so just use the complete length of this packet
                    // and we're done
                    dataSize = chunkSize;
                    System.out.println("Raw mode; full size = " + dataSize);
                    data = new byte[dataSize];
                }

                chunk.read(data, offset, chunkSize);
                offset += chunkSize;
            } while (offset < dataSize);
        } catch (Exception e) {
            Main.printError("Failed to receive config data", e);
            return;
        }

        try {
            peerConn.close();
        } catch (Exception e) {
            Main.printError("Failed to close data connection", e);
        }

        String config = new String(data);

        System.out.println("Received DeviReg Smart config data:");
        System.out.println(config);

    }

}
