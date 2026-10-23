/* The C site the smoke scan must decide: a perform on a handle with no
 * CURLOPT_TIMEOUT. Only the stub header in vendor/ is included, so the TU
 * parses on any runner without a system SDK. */
#include "curl/curl.h"

int main(void) {
  CURL *h = curl_easy_init();
  curl_easy_setopt(h, CURLOPT_URL, "https://example.com");
  CURLcode rc = curl_easy_perform(h);
  curl_easy_cleanup(h);
  return (int)rc;
}
