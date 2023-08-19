package io.github.sonic_amiga.opensdg.testapp;

public class PingCommand extends CommandHandler {

    @Override
    public int numRequiredArgs() {
        return 1;
    }

    @Override
    public void Execute(String[] command) {
        int seconds;

        try {
            seconds = Integer.parseInt(command[1]);
        } catch (NumberFormatException e) {
            System.out.println("Invalid number: " + command[1]);
            return;
        }

        Main.grid.setPingInterval(seconds);
    }
}
