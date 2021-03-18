package org.opensdg.protocol;

public class Control {
    // Grid message types
    public static final byte MSG_PROTOCOL_VERSION = 1;
    public static final byte MSG_PING = 4;
    public static final byte MSG_PONG = 5;
    public static final byte MSG_CALL_REMOTE = 10;
    public static final byte MSG_REMOTE_REPLY = 11;
    public static final byte MSG_INCOMING_CALL = 12;
    public static final byte MSG_INCOMING_CALL_REPLY = 13;
    public static final byte MSG_PAIR_REMOTE = 32;
    public static final byte MSG_PAIR_REMOTE_REPLY = 33;

    public static final int PROTOCOL_VERSION_MAGIC = 0xF09D8CA8;
    public static final int PROTOCOL_VERSION_MAJOR = 1;
    public static final int PROTOCOL_VERSION_MINOR = 0;
}
