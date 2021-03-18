package org.opensdg.testapp;

public class GridCommand extends CommandHandler {

    @Override
    public int numRequiredArgs() {
        return 1;
    }

    @Override
    public void Execute(String[] command) {
        if (command.length < 2) {
            System.out.println("Malformed 'grid' command");
            return;
        }

        switch (command[1]) {
            case "connect":
                Main.connectToGrid();
                break;
            case "disconnect":
                Main.disconnectGrid();
                break;
            default:
                System.out.println("Unknown 'grid' argument: " + command[1]);
                break;
        }
    }

}
