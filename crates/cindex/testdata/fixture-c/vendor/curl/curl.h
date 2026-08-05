/* Vendored STUB of the libcurl surface the fixture exercises. Test fixture
 * only: real repos compile against real curl headers via their compile db. */
#ifndef FIXTURE_CURL_H
#define FIXTURE_CURL_H

typedef void CURL;
typedef int CURLcode;

typedef enum {
  CURLOPT_WRITEFUNCTION = 20011,
  CURLOPT_URL = 10002,
  CURLOPT_TIMEOUT = 13
} CURLoption;

CURL *curl_easy_init(void);
CURLcode curl_easy_setopt(CURL *handle, CURLoption option, ...);
CURLcode curl_easy_perform(CURL *handle);
void curl_easy_cleanup(CURL *handle);

#endif /* FIXTURE_CURL_H */
