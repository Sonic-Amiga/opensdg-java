package io.github.sonic_amiga.opensdg.java;

import java.nio.channels.ClosedChannelException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import io.github.sonic_amiga.opensdg.protocol.generated.ControlProtocol.PeerReply;

class ForwardRequest implements Future<PeerReply> {
    private int requestId;
    private PeerReply result = null;
    private Throwable error = null;

    ForwardRequest(int id) {
        requestId = id;
    }

    synchronized void reportDone(PeerReply reply) {
        result = reply;
        notifyAll();
    }

    synchronized void reportError(Throwable t) {
        error = t;
        notifyAll();
    }

    int getId() {
        return requestId;
    }

    @Override
    public String toString() {
        return "ForwardRequest #" + requestId;
    }

    @Override
    public boolean cancel(boolean mayInterruptIfRunning) {
        // We don't support canceling (yet)
        return false;
    }

    @Override
    public boolean isCancelled() {
        // We don't support canceling (yet)
        return false;
    }

    @Override
    public boolean isDone() {
        return result != null || error != null;
    }

    @Override
    public PeerReply get() throws InterruptedException, ExecutionException {
        return get(0);
    }

    @Override
    public PeerReply get(long timeout, TimeUnit unit) throws InterruptedException, ExecutionException {
        return get(unit.convert(timeout, TimeUnit.MILLISECONDS));

    }

    private synchronized PeerReply get(long ms) throws InterruptedException, ExecutionException {
        while (!isDone()) {
            wait(ms);
        }

        if (error != null) {
            // Provide a nice message to the user
            String message = error.getMessage();

            if (message == null) {
                // Some Throwables come without a message
                if (error instanceof ClosedChannelException) {
                    message = "Grid is not connected";
                } else if (error instanceof TimeoutException) {
                    message = "Grid communication timeout";
                } else {
                    message = "Grid connection error: " + error.toString();
                }
            }
            throw new ExecutionException(message, error);
        }

        return result;
    }
}
