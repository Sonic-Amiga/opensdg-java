package org.opensdg.java;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.opensdg.protocol.generated.ControlProtocol.PeerReply;

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
            throw new ExecutionException(error);
        }

        return result;
    }
}
