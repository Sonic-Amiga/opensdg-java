package io.github.sonic_amiga.opensdg.testapp;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.HashMap;

import javax.xml.bind.DatatypeConverter;

import org.opensdg.java.GridConnection;
import org.opensdg.java.SDG;

public class Main {

    static {
        // We are in the process of development, so we want to see everything
        System.setProperty("org.slf4j.simplelogger.defaultlog", "trace");
    }

    private static byte[] privKey;

    // In order to simplify the code these entities are global and avalible from within anywhere.
    // It's definitely not the best Java coding ever, but this is just a crudely hacked up test app.
    // Additionally having resources as static exposes various resource leaks, like unterminated
    // executors. When this happens, the app freezes after "quit" command waiting for those threads.
    public static GridConnection grid;
    public static boolean exitFlag = false;
    public static PeerRegistry peers = new PeerRegistry();

    public static void main(String[] args) {
        HashMap<String, CommandHandler> cmdMap = new HashMap<String, CommandHandler>();

        cmdMap.put("close", new CloseCommand());
        cmdMap.put("connect", new ConnectCommand());
        cmdMap.put("grid", new GridCommand());
        cmdMap.put("help", new HelpCommand());
        cmdMap.put("list", new ListCommand());
        cmdMap.put("pair", new PairCommand());
        cmdMap.put("ping", new PingCommand());
        cmdMap.put("quit", new QuitCommand());

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

        grid = new GridConnection(privKey);
        connectToGrid();

        System.out.println("Grid connection established");

        BufferedReader console = new BufferedReader(new InputStreamReader(System.in));

        while (!exitFlag) {
            String line;

            System.out.print('>');

            try {
                line = console.readLine();
            } catch (IOException e) {
                printError("Error reading console", e);
                break;
            }

            String[] command = line.split(" ");

            if (command.length > 0 && !command[0].isEmpty()) {
                CommandHandler handler = cmdMap.get(command[0]);

                if (handler != null) {
                    if (command.length - 1 < handler.numRequiredArgs()) {
                        System.out.println(command[0] + ": required argument(s) missing");
                    }
                    handler.Execute(command);
                } else {
                    System.out.println("Unrecognized command: " + line);
                }
            }
        }

        System.out.println("Closing grid connection...");
        disconnectGrid();
        System.out.println("Bye!");
    }

    public static void connectToGrid() {
        try {
            grid.connect(GridConnection.Danfoss);
        } catch (Exception e) {
            printError("Failed to connect to grid", e);
        }
    }

    public static void disconnectGrid() {
        grid.close();
    }

    public static void printError(String header, Exception e) {
        System.err.print(header + " :");
        e.printStackTrace();
    }
}
