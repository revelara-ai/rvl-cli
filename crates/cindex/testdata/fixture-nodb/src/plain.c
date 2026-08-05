/* No-compile-db fixture: the curated extern-C allowlist tier. There is no
 * compile_commands.json here and deliberately no headers: the allowlist names
 * are unique unmangled C identifiers, so a best-effort single-file parse can
 * still inventory them at LOW tier (client_type_resolved=false). Everything
 * off the allowlist abstains. */
int use_curl(void *h) {
  curl_easy_perform(h); /* allowlisted: emitted, low tier */
  helper_step(h);       /* NOT allowlisted: never emitted */
  return 0;
}
