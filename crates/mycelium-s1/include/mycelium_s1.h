#ifndef MYCELIUM_S1_H
#define MYCELIUM_S1_H
#ifdef __cplusplus
extern "C" {
#endif
/* UTF-8 JSON request. Result must be released with s1_free. NULL input returns NULL. */
char *s1_evaluate(const char *request);
void s1_free(char *result);
#ifdef __cplusplus
}
#endif
#endif
