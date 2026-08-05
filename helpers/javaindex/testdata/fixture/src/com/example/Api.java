// G2 server-entry surfaces, Spring wildcard-import idiom: the mapping
// annotations attribute through `import org.springframework.web.bind.annotation.*`.
package com.example;

import org.springframework.web.bind.annotation.*;

class Api {
    @GetMapping("/users/{id}")
    String getUser(@PathVariable String id) {
        return "u:" + id;
    }

    @RequestMapping(path = "/health", method = RequestMethod.GET)
    String health() {
        return "ok";
    }
}
