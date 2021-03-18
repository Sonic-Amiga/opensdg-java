package org.opensdg.java;

import java.util.concurrent.Callable;
import java.util.concurrent.FutureTask;

import org.opensdg.protocol.generated.ControlProtocol.PeerReply;

class ForwardRequest extends FutureTask<PeerReply> {
    private static class NoRun implements Callable<PeerReply> {
        @Override
        public PeerReply call() throws Exception {
            throw new IllegalStateException("ForwardRequest must not be scheduled");
        }

    }

    private int requestId;

    ForwardRequest(int id) {
        super(new NoRun());
        requestId = id;
    }

    void reportDone(PeerReply reply) {
        set(reply);
    }

    void reportError(Throwable t) {
        setException(t);
    }

    int getId() {
        return requestId;
    }

    @Override
    public String toString() {
        return "ForwardRequest #" + requestId;
    }
}
