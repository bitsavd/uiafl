#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "alloc-inl.h"
#include "aflnet.h"

/* Keep one mapping across all response captures in a historical run. */
int main(int argc, char **argv) {
  if (argc != 2) return 2;
  unsigned int *(*parse)(unsigned char *, unsigned int, unsigned int *);
  if (!strcmp(argv[1], "MQTT")) parse = extract_response_codes_mqtt;
  else if (!strcmp(argv[1], "MODBUS")) parse = extract_response_codes_modbus;
  else return 2;
  init_message_code_map();
  char path[4096];
  while (fgets(path, sizeof(path), stdin)) {
    path[strcspn(path, "\r\n")] = 0;
    FILE *file = fopen(path, "rb");
    if (!file) return 3;
    if (fseek(file, 0, SEEK_END)) return 3;
    long length = ftell(file);
    if (length < 0 || length > 8 * 1024 * 1024) return 3;
    rewind(file);
    unsigned char *data = ck_alloc(length ? length : 1);
    if (fread(data, 1, length, file) != length) return 3;
    fclose(file);
    unsigned int count = 0;
    unsigned int *states = parse(data, length, &count);
    printf("[");
    for (unsigned int i = 0; i < count; i++) printf("%s%u", i ? "," : "", states[i]);
    puts("]");
    ck_free(states);
    ck_free(data);
  }
  destroy_message_code_map();
  return 0;
}
