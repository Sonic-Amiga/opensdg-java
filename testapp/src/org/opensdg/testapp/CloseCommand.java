package org.opensdg.testapp;

import org.opensdg.java.Connection;

public class CloseCommand extends CommandHandler {

    @Override
    public int numRequiredArgs() {
        return 1;
    }

    @Override
    public void Execute(String[] command) {
        int num;

        try {
            num = Integer.parseInt(command[1]);
        } catch (NumberFormatException e) {
            System.out.println("Invalid number: " + command[1]);
            return;
        }

        Connection conn = Main.peers.get(num);

        if (conn == null) {
            System.out.println("Connection not found: " + num);
            return;
        }

        conn.close();
        Main.peers.remove(num);
    }

}
