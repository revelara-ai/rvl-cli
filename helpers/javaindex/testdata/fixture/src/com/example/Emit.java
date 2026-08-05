// G4 emission surfaces: an import-attributed slf4j logger (declared with its
// fully-qualified type to dodge the java.util.logging.Logger name clash), a
// JDK-typed JUL logger, a static-class Sentry capture, an instrumented catch,
// and a swallowing catch.
package com.example;

import java.util.logging.Logger;

import io.sentry.Sentry;
import org.slf4j.LoggerFactory;

class Emit {
    private static final org.slf4j.Logger log = LoggerFactory.getLogger(Emit.class);
    private static final Logger jul = Logger.getLogger("emit");

    void work() {
        log.info("starting");
        log.warn("wobbly");
        try {
            risky();
        } catch (Exception e) {
            log.error("failed", e);
            Sentry.captureException(e);
        }
        try {
            risky();
        } catch (Exception e) {
            // swallowed: no emission, no rethrow
        }
        jul.info("done");
    }

    void risky() throws Exception {}
}
