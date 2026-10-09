// Connection pools that take a bound. The retriever reports every
// construction with the setters it saw. It never says which setter is a
// bound; a construction-bound spec does. HikariCP has no stub here, so the
// types are import-attributed (the classpath-less path).
package com.example;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

class Pools {
    static final int MAX_POOL = 20;

    private HikariDataSource shared;

    void unsizedConfig() {
        HikariConfig cfg = new HikariConfig();
        cfg.setJdbcUrl("jdbc:postgresql://db/app");
        cfg.validate();
    }

    void literalConfig() {
        HikariConfig cfg = new HikariConfig();
        cfg.setMaximumPoolSize(10);
        cfg.validate();
    }

    void constantConfig() {
        HikariConfig cfg = new HikariConfig();
        cfg.setMaximumPoolSize(MAX_POOL);
        cfg.validate();
    }

    void namedConfig(Settings settings) {
        HikariConfig cfg = new HikariConfig();
        cfg.setMaximumPoolSize(settings.poolSize());
        cfg.validate();
    }

    HikariConfig leavesConfig() {
        HikariConfig cfg = new HikariConfig();
        cfg.setJdbcUrl("jdbc:postgresql://db/app");
        return cfg;
    }

    void unsizedSource() throws Exception {
        HikariDataSource ds = new HikariDataSource();
        ds.setJdbcUrl("jdbc:postgresql://db/app");
        ds.getConnection();
    }

    void sizedSource() throws Exception {
        HikariDataSource ds = new HikariDataSource();
        ds.setMaximumPoolSize(5);
        ds.getConnection();
    }

    HikariDataSource fromConfig(HikariConfig cfg) {
        return new HikariDataSource(cfg);
    }

    void storedSource() {
        this.shared = new HikariDataSource();
        this.shared.setJdbcUrl("jdbc:postgresql://db/app");
    }
}
