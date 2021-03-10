package org.opensdg.testapp;

import java.io.IOException;

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
            System.out.println("Failed to connect to grid");
            e.printStackTrace();
        }

        try {
            grid.close();
        } catch (IOException e) {
            System.out.println("Failed to close the connection");
            e.printStackTrace();
        }
    }
}
