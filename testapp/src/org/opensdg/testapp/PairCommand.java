package org.opensdg.testapp;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.concurrent.ExecutionException;

import javax.xml.bind.DatatypeConverter;

import org.opensdg.java.PairingConnection;

public class PairCommand extends CommandHandler {

    @Override
    public int numRequiredArgs() {
        return 1;
    }

    @Override
    public void Execute(String[] command) {
        PairingConnection conn = new PairingConnection();

        try {
            conn.pairWithRemote(Main.grid, command[1]);
        } catch (InterruptedException | ExecutionException | IOException | GeneralSecurityException e) {
            Main.printError("Pairing failed", e);
            return;
        }

        byte[] peerId = conn.getPeerId();

        System.out.println("Pairing successful, peer ID is " + DatatypeConverter.printHexBinary(peerId));
        try {
            conn.close();
        } catch (IOException e) {
            Main.printError("Failed to close pairing connection", e);
        }

        // TODO: Try to download DeviReg info
    }

}
