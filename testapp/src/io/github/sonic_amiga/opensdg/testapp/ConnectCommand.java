package io.github.sonic_amiga.opensdg.testapp;

import org.opensdg.java.PeerConnection;
import org.opensdg.java.SDG;

public class ConnectCommand extends CommandHandler {

    @Override
    public int numRequiredArgs() {
        return 1;
    }

    @Override
    public void Execute(String[] command) {

        if (command.length < 2) {
            System.out.println("connect: peer is not specified");
            return;
        }

        byte[] peerId = SDG.hex2bin(command[1]);
        String protocol = command.length > 2 ? command[2] : "dominion-1.0";

        PeerConnection conn = new PeerConnection();

        try {
            conn.connectToRemote(Main.grid, peerId, protocol);
        } catch (Exception e) {
            Main.printError("Failed to connect to peer", e);
            return;
        }

        int num = Main.peers.add(conn);
        System.out.println("Created connection #" + num);

        // Start asynchronous receiving on the Connection
        conn.asyncReceive();
    }

}
