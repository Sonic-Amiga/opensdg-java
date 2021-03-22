package org.opensdg.testapp;

public class HelpCommand extends CommandHandler {

    @Override
    public void Execute(String[] command) {
        System.out.println("close <N>        - close the given peer connection");
        System.out.println("connect <peerID> - connect to a given peerID");
        System.out.println("help             - this help");
        System.out.println("grid connect     - connect to grid");
        System.out.println("grid disconnect  - close the grid connection");
        System.out.println("list             - list currently open peer connections");
        System.out.println("pair <OTP>       - pair with remote using a one-time password");
        System.out.println("ping <seconds>   - set grid ping interval in seconds");
        System.out.println("quit             - quit program");
    }

}
