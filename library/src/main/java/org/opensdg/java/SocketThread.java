package org.opensdg.java;

import java.io.IOException;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.Calendar;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class SocketThread extends Thread {
    private static SocketThread thread;

    synchronized public static SocketThread get() {
        if (thread == null) {
            thread = new SocketThread();
            thread.start();
        }
        return thread;
    }

    private final Logger logger = LoggerFactory.getLogger(SocketThread.class);
    private List<Request> requestQueue = Collections.synchronizedList(new LinkedList<Request>());
    private Selector selector;

    private SocketThread() {
        super("SDG socket thread");
        try {
            selector = Selector.open();
        } catch (IOException e) {
            logger.error("Failed to create a Selector: ", e);
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void run() {
        logger.debug("Thread started");

        try {
            mainLoop();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            logger.error("Critical error in main loop: ", e);
            throw new IllegalStateException(e);
        }
    }

    private void mainLoop() throws IOException {
        for (;;) {
            long sleep_until = Long.MAX_VALUE;
            long timeout = 0;

            // Check if we need to ping some GridConnection
            for (SelectionKey key : selector.keys()) {
                if (!(key.attachment() instanceof GridConnection)) {
                    continue;
                }
                GridConnection grid = (GridConnection) key.attachment();
                long interval = grid.getPingInterval() * 1000;

                if (Calendar.getInstance().getTimeInMillis() - grid.getLastPing() > interval) {
                    grid.asyncPing();
                }

                long next_ping = grid.getLastPing() + interval;

                if (sleep_until > next_ping) {
                    sleep_until = next_ping;
                }

                // Use "timeout" variable as a flag at this point.
                // sleep_until == Long.MAX_VALUE is theoretically legal, this trick
                // helps to distinguish between this situation and no Grids being registered.
                timeout = -1;
            }

            if (timeout != 0) {
                long now = Calendar.getInstance().getTimeInMillis();
                // We can't have zero so using 1ms for "timeout now"
                timeout = sleep_until > now ? sleep_until - now : 1;
            }

            // Check for readable sockets
            if (selector.select(timeout) > 0) {
                Iterator<SelectionKey> iterator = selector.selectedKeys().iterator();

                while (iterator.hasNext()) {
                    SelectionKey key = iterator.next();

                    iterator.remove();
                    ((Connection) key.attachment()).onAsyncRead();
                }
            }

            // Check for requests from other threads
            while (!requestQueue.isEmpty()) {
                Request req = requestQueue.remove(0);
                SocketChannel sock = req.conn.getSocket();

                logger.debug("Request: {}", req.action);

                switch (req.action) {
                    case ADD_SOCKET:
                        sock.configureBlocking(false);
                        sock.register(selector, SelectionKey.OP_READ, req.conn);
                        break;
                }
            }
        }
    }

    public static enum Action {
        ADD_SOCKET
    }

    private static class Request {
        public Request(Action a, Connection c) {
            action = a;
            conn = c;
        }

        private Action action;
        private Connection conn;
    }

    public void sendRequest(Action a, Connection c) {
        requestQueue.add(new Request(a, c));
        selector.wakeup();
    }
}
