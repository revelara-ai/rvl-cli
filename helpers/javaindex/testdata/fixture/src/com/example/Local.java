// A call to a method this repository declares: the repo-internal surface that
// provenance.api_in_repo marks.
package com.example;

class Local {
    static class Ledger {
        String post(String entry) {
            return entry;
        }
    }

    String record(Ledger ledger) {
        return ledger.post("entry");
    }
}
