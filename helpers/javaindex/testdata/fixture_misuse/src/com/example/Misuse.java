// Misuse-shape fixture: one method per rule of the overbroad_catch class. A
// handler that catches java.lang.Exception or java.lang.Throwable and does
// not throw is the shape. The bounded forms are below it.
package com.example;

import java.io.IOException;
import java.util.logging.Logger;

class Misuse {
    private static final Logger log = Logger.getLogger("misuse");

    // Two handlers of Exception and one of Throwable: two packets, one per
    // identity, with the count on each.
    void broad() {
        try {
            risky();
        } catch (Exception e) {
            log.warning("first");
        }
        try {
            risky();
        } catch (Exception e) {
            log.warning("second");
        }
        try {
            risky();
        } catch (Throwable t) {
            log.severe("third");
        }
    }

    // A second function: the aggregate is per enclosing function.
    void alsoBroad() {
        try {
            risky();
        } catch (Exception e) {
            log.warning("again");
        }
    }

    // The bounded forms. None of them is an overbroad catch.
    void bounded(boolean fatal) {
        try {
            risky();
        } catch (IOException e) {
            // A narrow type.
            log.warning("io");
        } catch (Exception e) {
            // Throws again: the error propagates.
            log.warning("wrapped");
            throw new IllegalStateException(e);
        }
        try {
            risky();
        } catch (Exception e) {
            // A throw on one branch is a throw.
            log.warning("maybe");
            if (fatal) {
                throw new IllegalStateException(e);
            }
        }
        try {
            risky();
        } catch (IllegalStateException | IllegalArgumentException e) {
            // A union of narrow types.
            log.warning("narrow union");
        } catch (Exception e) {
            // A swallow: the emission lane reports this handler.
        }
    }

    void risky() throws Exception {}
}
