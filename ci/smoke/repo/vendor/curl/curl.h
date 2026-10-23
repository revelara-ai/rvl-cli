/* A stub of the libcurl surface src/fetch.c calls. */
#ifndef SMOKE_CURL_H
#define SMOKE_CURL_H

typedef void CURL;
typedef int CURLcode;

typedef enum {
  CURLOPT_URL = 10002,
  CURLOPT_TIMEOUT = 13
} CURLoption;

CURL *curl_easy_init(void);
CURLcode curl_easy_setopt(CURL *handle, CURLoption option, ...);
CURLcode curl_easy_perform(CURL *handle);
void curl_easy_cleanup(CURL *handle);

#endif /* SMOKE_CURL_H */
