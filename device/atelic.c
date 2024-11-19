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

unsigned char* hexstr_to_char(const char* hexstr)
{
    size_t len = strlen(hexstr);
    size_t final_len = len / 2;
    unsigned char* chrs = (unsigned char*)malloc((final_len+1) * sizeof(*chrs));
    for (size_t i=0, j=0; j<final_len; i+=2, j++)
        chrs[j] = (hexstr[i] % 32 + 9) % 25 * 16 + (hexstr[i+1] % 32 + 9) % 25;
    chrs[final_len] = '\0';
    return chrs;
}

static size_t fRespBody(void *ptr, size_t size, size_t nmemb, void *stream) {
  if (size != 1) {
    printf("element size error!");
  }
  {
    json_object *json, *status, *data, *qualification, *credential;
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
        data = json_object_object_get(json, "data");
        if (data != NULL) {
          qualification = json_object_object_get(data, "qualification");
          credential = json_object_object_get(data, "credential");
          if (qualification != NULL && json_object_is_type(qualification, json_type_string)) {
            const char *str = json_object_get_string(qualification);
            if (*str != '\0')
              printf("Qualification: %s\n", str);
          }
          if (credential != NULL && json_object_is_type(credential, json_type_string)) {
            const char *cred = json_object_get_string(credential);
            if (*cred != '\0') {
              printf("Credential: %s\n", cred);
              FILE *fd = NULL;
              if ((fd = fopen("./credential.blob", "wb")) != NULL) {
                unsigned char* bArray = hexstr_to_char(cred);
                fwrite(bArray, strlen(cred)/2, 1, fd);
                free(bArray);
                fclose(fd);
                printf("written to ./credential.blob\n");
              }
            }
          }
        }
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
  config_t cfg;

  // To be freed on exit
  CURL *curl = NULL;
  json_object *json = NULL;
  config_t *cf = NULL;
  struct curl_slist *headers = NULL;

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

  curl = curl_easy_init();
  if(curl) {
    char *url = NULL;
    
    url = malloc(strlen("/atelic") + strlen(server) + 1);
    url[0] = '\0';
    strcat(url, server);
    strcat(url,"/atelic");

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

  return 0;
}
