package org.opensdg.java;

import java.io.IOException;
import java.nio.channels.AsynchronousChannelGroup;

class ChannelGroupHolder {
    private static AsynchronousChannelGroup group;
    private static int useCount = 0;

    synchronized public static AsynchronousChannelGroup get() throws IOException {
        if (useCount == 0) {
            group = AsynchronousChannelGroup.withFixedThreadPool(1, new NamedThreadFactory("SDG socket thread"));
        }
        useCount++;

        return group;
    }

    synchronized static void put() {
        if (--useCount == 0) {
            group.shutdown();
            group = null;
        }
    }

}
