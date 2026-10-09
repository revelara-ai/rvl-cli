// A builder held in a local: the options are the methods called on it. This
// file is also the "elsewhere in the module" for Caches.builderLeaves.
package com.example;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import java.util.concurrent.TimeUnit;

class CacheTuning {
    Cache<Object, Object> stepwise() {
        Caffeine<Object, Object> builder = Caffeine.newBuilder();
        builder.expireAfterWrite(10, TimeUnit.MINUTES).maximumSize(50);
        return builder.build();
    }
}
