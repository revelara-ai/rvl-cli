// Same simple names, different types: a local class and a wildcard import.
// Neither is attributed, so neither is a construction.
package com.example;

import com.zaxxer.hikari.*;

class Lookalike {
    static class HikariConfig {
    }

    Object lookalike() {
        return new HikariConfig();
    }

    Object wildcard() {
        return new HikariDataSource();
    }
}
