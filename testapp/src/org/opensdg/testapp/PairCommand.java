package org.opensdg.testapp;

import java.io.DataInputStream;

import javax.xml.bind.DatatypeConverter;

import org.opensdg.java.PairingConnection;
import org.opensdg.java.PeerConnection;

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

        System.out.println("Pairing successful, peer ID is " + DatatypeConverter.printHexBinary(peerId));
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
            peerConn.connectToRemote(Main.grid, peerId, "dominion-config-1.0");
        } catch (Exception e) {
            Main.printError("Failed to establish data connection", e);
            return;
        }

        String myPeerId = DatatypeConverter.printHexBinary(Main.grid.getMyPeerId()).toLowerCase();
        ConfigRequest request = new ConfigRequest("OSDG-Java test", myPeerId);
        String json = gson.toJson(request);

        try {
            peerConn.sendData(json.getBytes());
        } catch (Exception e) {
            Main.printError("Failed to send config request", e);
            return;
        }

        String config = new String();
        int dataSize = 0;

        try {
            do {
                DataInputStream chunk = new DataInputStream(peerConn.receiveData());
                int size = chunk.available();

                if (size > 8) {
                    // In chunked mode the data will arrive in several packets.
                    // The first one will contain the header, specifying full data length.
                    // The header has integer 0 in the beginning so that it's easily distinguished
                    // from JSON plaintext
                    if (chunk.readInt() == 0) {
                        dataSize = chunk.readInt();
                        System.out.println("Chunked mode; full size = " + dataSize);
                        size -= 8;
                    } else {
                        chunk.reset();
                    }
                }

                if (dataSize == 0) {
                    // If the first packet didn't contain the header, this is not
                    // a chunked mode, so just use the complete length of this packet
                    // and we're done
                    dataSize = size;
                    System.out.println("Raw mode; full size = " + dataSize);
                }

                config += chunk.readUTF();
                dataSize -= size;
            } while (dataSize > 0);
        } catch (Exception e) {
            Main.printError("Failed to receive config data", e);
            return;
        }

        try {
            peerConn.close();
        } catch (Exception e) {
            Main.printError("Failed to close data connection", e);
        }

        System.out.println("Received DeviReg Smart config data:");
        System.out.println(config);

    }

}
