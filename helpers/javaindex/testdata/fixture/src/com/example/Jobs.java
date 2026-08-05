// G3 background-job surfaces: JDK-typed registrations (ScheduledExecutorService,
// Timer), an import-attributed quartz registration, and the Spring @Scheduled
// annotation idiom -- one bare registration and one whose neighbouring
// annotation carries a time bound.
package com.example;

import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.quartz.Scheduler;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.transaction.annotation.Transactional;

class Jobs {
    private final ScheduledExecutorService ses = Executors.newSingleThreadScheduledExecutor();

    void wire(Scheduler quartz) throws Exception {
        ses.scheduleAtFixedRate(() -> sync(), 0, 30, TimeUnit.SECONDS);
        new Timer().schedule(new TimerTask() {
            public void run() {
                sync();
            }
        }, 1000L);
        quartz.scheduleJob(null, null);
    }

    @Scheduled(fixedRate = 5000)
    void sync() {}

    @Scheduled(cron = "0 0 * * * *")
    @Transactional(timeout = 30)
    void flush() {}
}
