package com.example.shadow;

import java.util.logging.Logger;

class Shadow {
    private static final Logger log = Logger.getLogger("shadow");

    void local() {
        try {
            log.info("work");
        } catch (Exception e) {
            log.warning("a local type");
        }
    }
}
