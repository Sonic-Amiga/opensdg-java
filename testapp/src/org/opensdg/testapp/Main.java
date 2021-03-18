package org.opensdg.testapp;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.HashSet;
import java.util.concurrent.ExecutionException;

import javax.xml.bind.DatatypeConverter;

import org.opensdg.java.Connection;
import org.opensdg.java.SDG;

public class Main {

    static {
        // We are in the process of development, so we want to see everything
        System.setProperty("org.slf4j.simplelogger.defaultlog", "trace");
    }

    private static byte[] privKey;
    private static Connection grid;
    private static HashSet<Connection> peers;

    public static void main(String[] args) {
        int len = 0;

        try {
            InputStream f = new FileInputStream("osdg_test_private_key.bin");

            privKey = new byte[SDG.KEY_SIZE];
            len = f.read(privKey);
            f.close();

            System.out.println("Loaded private key: " + DatatypeConverter.printHexBinary(privKey));
        } catch (IOException e) {
            // Nothing to do
        }

        if (len != SDG.KEY_SIZE) {
            privKey = SDG.createPrivateKey();
            System.out.println("Created new private key: " + DatatypeConverter.printHexBinary(privKey));

            try {
                OutputStream f = new FileOutputStream("osdg_test_private_key.bin");

                f.write(privKey);
                f.close();
            } catch (IOException e) {
                System.out.println("Failed to write private key file: " + e);
            }
        }

        grid = new Connection();
        grid.setPrivateKey(privKey);

        try {
            grid.connectToDanfoss();
        } catch (Exception e) {
            printError("Failed to connect to grid", e);
            return;
        }

        System.out.println("Grid connection established");

        BufferedReader console = new BufferedReader(new InputStreamReader(System.in));
        boolean quit = false;

        do {
            String line;

            System.out.print('>');

            try {
                line = console.readLine();
            } catch (IOException e) {
                printError("Error reading console", e);
                break;
            }

            String[] command = line.split(" ");

            if (command.length > 0) {
                switch (command[0]) {
                    case "connect":
                        connect(command);
                        break;
                    case "help":
                        printHelp();
                        break;
                    case "quit":
                        quit = true;
                        break;
                    default:
                        System.out.println("Unrecognized command: " + line);
                        break;
                }
            }
        } while (!quit);

        try {
            grid.close();
        } catch (IOException e) {
            printError("Failed to close the connection", e);
        }

        System.out.println("Bye!");
    }

    private static void connect(String[] command) {

        if (command.length < 2) {
            System.out.println("connect: peer is not specified");
            return;
        }

        byte[] peerId = DatatypeConverter.parseHexBinary(command[1]);
        String protocol = command.length > 2 ? command[2] : "dominion-1.0";

        Connection conn = new Connection();

        try {
            conn.connectToRemote(grid, peerId, protocol);
        } catch (IOException | InterruptedException | ExecutionException e) {
            printError("connectToRemote() failed", e);
            return;
        }

        peers.add(conn);
    }

    private static void printHelp() {
        System.out.println("help - this help");
        System.out.println("quit - quit program");
    }

    private static void printError(String header, Exception e) {
        System.err.print(header + " :");
        e.printStackTrace();
    }
}
