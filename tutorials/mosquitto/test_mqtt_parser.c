#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "alloc-inl.h"
#include "aflnet.h"

static unsigned int state(unsigned char header) {
  unsigned char frame[] = {header, 2, 0, 0};
  unsigned int count;
  unsigned int *states = extract_response_codes_mqtt(frame, sizeof(frame), &count);
  assert(count == 2 && states[0] == 0);
  unsigned int result = states[1];
  ck_free(states);
  return result;
}

int main(void) {
  init_message_code_map();
  unsigned int connack = state(0x20), suback = state(0x90), ping = state(0xd0);
  unsigned char stream[] = {0x20, 2, 0, 0, 0x30, 4, 0xd0, 0, 0x90, 0,
                            0x90, 3, 0, 1, 0, 0xd0, 0};
  unsigned int count;
  unsigned int *states = extract_response_codes_mqtt(stream, sizeof(stream), &count);
  assert(count == 4 && states[1] == connack && states[2] == suback && states[3] == ping);
  ck_free(states);

  unsigned char large[137] = {0x30, 0x82, 0x01};
  memset(large + 3, 0xd0, 130);
  large[133] = 0x40; large[134] = 2; large[135] = 0; large[136] = 1;
  states = extract_response_codes_mqtt(large, sizeof(large), &count);
  assert(count == 2 && states[1] == state(0x40));
  ck_free(states);
  region_t *regions = extract_requests_mqtt(large, sizeof(large), &count);
  assert(count == 2 && regions[0].end_byte == 132 && regions[1].start_byte == 133);
  ck_free(regions);

  unsigned char truncated[] = {0x20, 2, 0};
  for (unsigned int size = 0; size <= sizeof(truncated); size++) {
    states = extract_response_codes_mqtt(truncated, size, &count);
    assert(count == 1);
    ck_free(states);
  }
  unsigned char malformed[] = {0x30, 0xff, 0xff, 0xff, 0xff, 0x20, 0};
  states = extract_response_codes_mqtt(malformed, sizeof(malformed), &count);
  assert(count == 1);
  ck_free(states);
  regions = extract_requests_mqtt(malformed, sizeof(malformed), &count);
  assert(count == 1 && regions[0].end_byte == sizeof(malformed) - 1);
  ck_free(regions);
  unsigned char zero_length[] = {0xc0, 0, 0xe0, 0};
  regions = extract_requests_mqtt(zero_length, sizeof(zero_length), &count);
  assert(count == 2 && regions[0].end_byte == 1 && regions[1].end_byte == 3);
  ck_free(regions);

  for (unsigned int seed = 1; seed <= 6; seed++) {
    char path[80];
    snprintf(path, sizeof(path), "tutorials/mosquitto/in-mqtt/seed%u.raw", seed);
    FILE *file = fopen(path, "rb");
    assert(file);
    unsigned char data[1024];
    unsigned int size = fread(data, 1, sizeof(data), file);
    fclose(file);
    regions = extract_requests_mqtt(data, size, &count);
    unsigned int offset = 0;
    for (unsigned int i = 0; i < count; i++) {
      assert(regions[i].start_byte == offset && regions[i].end_byte < size);
      offset = regions[i].end_byte + 1;
    }
    assert(offset == size);
    ck_free(regions);
  }
  destroy_message_code_map();
  puts("MQTT framing and response-state tests passed (including all six seeds)");
  return 0;
}
