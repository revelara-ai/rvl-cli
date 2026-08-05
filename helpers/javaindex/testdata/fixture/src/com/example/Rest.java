// G2 server-entry surfaces, JAX-RS single-type-import idiom.
package com.example;

import javax.ws.rs.GET;
import javax.ws.rs.Path;

class Rest {
    @GET
    @Path("/things")
    String list() {
        return "[]";
    }
}
