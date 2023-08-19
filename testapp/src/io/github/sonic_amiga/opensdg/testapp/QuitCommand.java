package io.github.sonic_amiga.opensdg.testapp;

public class QuitCommand extends CommandHandler {

    @Override
    public void Execute(String[] command) {
        Main.exitFlag = true;
    }

}
