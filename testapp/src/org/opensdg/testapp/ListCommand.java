package org.opensdg.testapp;

public class ListCommand extends CommandHandler {

    @Override
    public void Execute(String[] command) {
        Main.peers.print();
    }

}
