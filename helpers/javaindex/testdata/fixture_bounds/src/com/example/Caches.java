// Caffeine caches. The construction is Caffeine.newBuilder(); the options
// are the links of the builder chain, up to build().
package com.example;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import java.util.concurrent.TimeUnit;

class Caches {
    static final long MAX_WEIGHT = 1_000_000L;

    Cache<String, String> unsizedCache() {
        return Caffeine.newBuilder().build();
    }

    Cache<String, String> expiringOnly() {
        return Caffeine.newBuilder()
                .expireAfterWrite(10, TimeUnit.MINUTES)
                .build();
    }

    Cache<String, String> sizedCache() {
        return Caffeine.newBuilder()
                .expireAfterWrite(10, TimeUnit.MINUTES)
                .maximumSize(10_000)
                .build();
    }

    Cache<String, String> weightedCache() {
        return Caffeine.newBuilder()
                .maximumWeight(MAX_WEIGHT)
                .weigher((String k, String v) -> v.length())
                .build();
    }

    Cache<String, String> namedSize(Settings settings) {
        return Caffeine.newBuilder().maximumSize(settings.cacheSize()).build();
    }

    Caffeine<Object, Object> builderLeaves() {
        Caffeine<Object, Object> builder = Caffeine.newBuilder();
        return builder;
    }
}
