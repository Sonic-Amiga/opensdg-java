package org.opensdg.testapp;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

import org.opensdg.java.Connection;
import org.opensdg.java.SDG;

public class Main {

    static {
        // We are in the process of development, so we want to see everything
        System.setProperty("org.slf4j.simplelogger.defaultlog", "trace");
    }

    public static void main(String[] args) {
        byte[] privKey = SDG.createPrivateKey();
        Connection grid = new Connection();

        grid.setPrivateKey(privKey);

        try {
            grid.connectToDanfoss();
        } catch (IOException e) {
            printError("Failed to connect to grid", e);
            return;
        }

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
