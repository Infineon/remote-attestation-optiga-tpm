/**
* MIT License
*
* Copyright (c) 2020 Infineon Technologies AG
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE
*/

#include <stdio.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <string.h>
#include <libconfig.h>

static char *fMalloc(FILE *fd, size_t *sz) {
  fseek(fd, 0, SEEK_END);
  *sz = ftell(fd);
  rewind(fd);
  return malloc(*sz);  
}

static char *fByteAry2HexStr(char *ba, size_t size) {
  int i = 0, j = 0;
  char *str = malloc((size*2)+1);
  
  for (; i<size; i++) {
    sprintf(&str[j], "%02x", ba[i]);
    j+=2;
  }
  str[j] = '\0';
  return str;
}

static size_t fRespBody(void *ptr, size_t size, size_t nmemb, void *stream) {
  if (size != 1) {
    printf("element size error!");
  }
  {
    json_object *json, *status, *qualification;
    enum json_tokener_error jerr = json_tokener_error_depth;

    json = json_tokener_parse_verbose((char *) ptr, &jerr);
    if (jerr != json_tokener_success) {
      printf("Failed to parse json string\n");
      json_object_put(json);
      return nmemb*size;
    }

    //printf("%s\n", json_object_to_json_string(json));

    status = json_object_object_get(json, "status");
    if (status != NULL) {
      if (!strcmp(json_object_get_string(status), "ok")) {
        printf("Status: ok\n");
      } else {
        printf("%s\n", json_object_to_json_string(json));
      }
    }

    json_object_put(json);
  }
  return nmemb*size;
}

static size_t fRespHeader(void *ptr, size_t size, size_t nmemb, void *stream) {
  if (size != 1) {
    printf("element size error!");
  }
  //printf("%s\n", (char *) ptr);
  return nmemb*size;
}

int main(void)
{
  CURLcode res;
  const char *server = NULL;
  const char *username = NULL;
  const char *password = NULL;
  const char *quote_path = NULL;
  const char *sig_path = NULL;
  const char *template_path = NULL;
  config_t cfg;

  // To be freed on exit
  CURL *curl = NULL;
  config_t *cf = NULL;
  json_object *json = NULL;
  struct curl_slist *headers = NULL;
  char *quote = NULL;
  char *sig = NULL;
  char *template = NULL;

  cf = &cfg;
  config_init(cf);

  if (!config_read_file(cf, "config.cfg")) {
    printf("config.cfg file bad format\n");
    goto exit;
  }

  if (!config_lookup_string(cf, "auth.server", &server)) {
    printf("server url is not defined\n");
    goto exit;
  }

  if (!config_lookup_string(cf, "auth.username", &username)) {
    printf("username is not defined\n");
    goto exit;
  }

  if (!config_lookup_string(cf, "auth.password", &password)) {
    printf("password is not defined\n");
    goto exit;
  }

  /**
   * Read quote
   */
  if (!config_lookup_string(cf, "attest.file_quote", &quote_path)) {
    printf("file_quote is not defined\n");
    goto exit;
  }

  {
    FILE *fd = NULL;
    if ((fd = fopen(quote_path, "rb")) != NULL) {
      size_t sz = 0;
      char *buf = fMalloc(fd, &sz);
      printf("Quote size: %d Bytes\n",sz);
      fread(buf, sizeof(char), sz, fd);
      fclose(fd);
      quote = fByteAry2HexStr(buf, sz);
      free(buf);
      //printf("%s\n", quote);
    } else {
      printf("Quote file not found\n");
      goto exit;
    }
  }

  /**
   * Read signature 
   */
  if (!config_lookup_string(cf, "attest.file_sig", &sig_path)) {
    printf("file_sig is not defined\n");
    goto exit;
  }

  {
    FILE *fd = NULL;
    if ((fd = fopen(sig_path, "rb")) != NULL) {
      size_t sz = 0;
      char *buf = fMalloc(fd, &sz);
      printf("Signature size: %d Bytes\n",sz);
      fread(buf, sizeof(char), sz, fd);
      fclose(fd);
      sig = fByteAry2HexStr(buf, sz);
      free(buf);
      //printf("%s\n", sig);
    } else {
      printf("Signature file not found\n");
      goto exit;
    }
  }

  /**
   * Read binary_runtime_measure 
   */
  if (!config_lookup_string(cf, "attest.file_imaTemplate", &template_path)) {
    printf("file_imaTemplate is not defined\n");
    goto exit;
  }

  {
    FILE *fd = NULL;
    if ((fd = fopen(template_path, "rb")) != NULL) {
      size_t sz = 0;
      char *buf = fMalloc(fd, &sz);
      printf("IMA template size: %d Bytes\n",sz);
      fread(buf, sizeof(char), sz, fd);
      fclose(fd);
      template = fByteAry2HexStr(buf, sz);
      free(buf);
      //printf("%s\n", template);
    } else {
      printf("IMA template file (binary_runtime_measure) not found\n");
      goto exit;
    }
  }

  /**
   * Build JSON
   */
  curl = curl_easy_init();
  if(curl) {
    char *url = NULL;

    url = malloc(strlen("/atelic") + strlen(server) + 1);
    url[0] = '\0';
    strcat(url, server);
    strcat(url,"/attest");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");

    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, fRespHeader);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fRespBody);

    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    free(url);

    json = json_object_new_object();
    json_object_object_add(json, "username", json_object_new_string(username));
    json_object_object_add(json, "password", json_object_new_string(password));
    json_object_object_add(json, "quote", json_object_new_string(quote));
    json_object_object_add(json, "signature", json_object_new_string(sig));
    json_object_object_add(json, "imaTemplate", json_object_new_string(template));
 
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_object_to_json_string(json));
    // Do not verify SSL server cert since we will be using self-sign cert for localhost
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
 
    res = curl_easy_perform(curl);
    if(res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));
  }

exit:
  if (curl != NULL) curl_easy_cleanup(curl);
  if (cf != NULL) config_destroy(cf);
  if (json != NULL) json_object_put(json);
  if (headers != NULL) curl_slist_free_all(headers);
  if (quote != NULL) free(quote);
  if (sig != NULL) free(sig);
  if (template != NULL) free(template);

  return 0;
}
