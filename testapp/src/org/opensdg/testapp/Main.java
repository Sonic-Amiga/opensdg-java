package org.opensdg.testapp;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;

import org.opensdg.java.Connection;
import org.opensdg.java.SDG;

public class Main {

    static {
        // We are in the process of development, so we want to see everything
        System.setProperty("org.slf4j.simplelogger.defaultlog", "trace");
    }

    private static byte[] privKey;

    public static void main(String[] args) {
        int len = 0;

        try {
            InputStream f = new FileInputStream("osdg_test_private_key.bin");

            privKey = new byte[SDG.KEY_SIZE];
            len = f.read(privKey);
        } catch (IOException e) {
            // Nothing to do
        }

        if (len != SDG.KEY_SIZE) {
            privKey = SDG.createPrivateKey();

            try {
                OutputStream f = new FileOutputStream("osdg_test_private_key.bin");
                f.write(privKey);
            } catch (IOException e) {
                System.out.println("Failed to write private key file: " + e);
            }
        }

        Connection grid = new Connection();

        grid.setPrivateKey(privKey);

        try {
            grid.connectToDanfoss();
        } catch (Exception e) {
            printError("Failed to connect to grid", e);
            return;
        }

        System.out.println("Grid connection established");

        BufferedReader console = new BufferedReader(new InputStreamReader(System.in));
        String cmd = "";

        do {
            System.out.print('>');
            try {
                cmd = console.readLine();
            } catch (IOException e) {
                printError("Error reading console", e);
                break;
            }

            switch (cmd) {
                case "help":
                    printHelp();
                    break;
                case "quit":
                    break;
                default:
                    System.out.println("Unrecognized command: " + cmd);
                    break;
            }
        } while (!cmd.equals("quit"));

        try {
            grid.close();
        } catch (IOException e) {
            printError("Failed to close the connection", e);
        }

        System.out.println("Bye!");
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
