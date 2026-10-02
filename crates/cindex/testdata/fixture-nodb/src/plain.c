/* No-compile-db fixture: the curated extern-C allowlist tier. There is no
 * compile_commands.json here and deliberately no headers: the allowlist names
 * are unique unmangled C identifiers, so a best-effort single-file parse can
 * still inventory them at LOW tier (client_type_resolved=false). Everything
 * off the allowlist abstains. */
int use_curl(void *h) {
  curl_easy_perform(h); /* allowlisted: emitted, low tier */
  helper_step(h);       /* NOT allowlisted: never emitted */
  pthread_create(h, 0, 0, 0); /* allowlisted G3 registration, low tier */
  return 0;
}

/* syslog is on the allowlist tier too: with no compile db its two calls still
 * make one G4 aggregate, stamped low tier like every other no-db packet. */
int note(void) {
  syslog(3, "first");
  syslog(3, "second");
  return 0;
}
