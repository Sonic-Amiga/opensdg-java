package io.github.sonic_amiga.opensdg.java;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

/**
 * A helper class to share a single ScheduledExecutorService between multiple instances of {@link GridConnection}
 *
 * Maintains usage count creates / destroys the executor service on demand.
 *
 * @author Pavel Fedin
 */
class PingExecutorHolder {
    private static ScheduledExecutorService scheduler = null;
    private static int useCount = 0;

    synchronized public static ScheduledExecutorService get() {
        if (useCount == 0) {
            scheduler = Executors.newScheduledThreadPool(1, new NamedThreadFactory("SDG ping thread"));
        }
        useCount++;

        return scheduler;
    }

    synchronized static void put() {
        if (--useCount == 0) {
            scheduler.shutdown();
            scheduler = null;
        }
    }
}
