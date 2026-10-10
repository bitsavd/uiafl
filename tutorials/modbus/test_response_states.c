#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "alloc-inl.h"
#include "aflnet.h"

static unsigned int response_state(unsigned char unit, unsigned char fc,
                                   unsigned char exception) {
  unsigned char packet[] = {0, 1, 0, 0, 0, 3, unit, fc, exception};
  unsigned int count = 0;
  unsigned int *states = extract_response_codes_modbus(packet, sizeof(packet), &count);
  assert(count == 2 && states[0] == 0);
  unsigned int state = states[1];
  ck_free(states);
  return state;
}

int main(void) {
  init_message_code_map();
  unsigned int read_state = response_state(1, 3, 0);
  assert(read_state == response_state(255, 3, 127));
  assert(read_state != response_state(1, 4, 0));

  unsigned int illegal_function = response_state(1, 0x83, 1);
  assert(illegal_function == response_state(42, 0xff, 1));
  assert(illegal_function != response_state(1, 0x83, 3));
  assert(illegal_function != read_state);
  assert(response_state(1, 0x83, 0x7f) == response_state(254, 0x81, 0xfe));

  unsigned int count;
  unsigned char packets[] = {
    0, 1, 0, 0, 0, 3, 1, 0x83, 1,
    0, 2, 0, 0, 0, 3, 7, 0x91, 1,
    0, 3, 0, 0, 0, 3, 1, 0x83, 3
  };
  unsigned int *states = extract_response_codes_modbus(packets, sizeof(packets), &count);
  assert(count == 4 && states[1] == states[2] && states[2] != states[3]);
  ck_free(states);

  /* Reject invalid protocol IDs, truncated ADUs and malformed exceptions. */
  unsigned char invalid[] = {0, 1, 0, 1, 0, 3, 1, 0x83, 1};
  states = extract_response_codes_modbus(invalid, sizeof(invalid), &count);
  assert(count == 1);
  ck_free(states);
  invalid[3] = 0;
  states = extract_response_codes_modbus(invalid, sizeof(invalid) - 1, &count);
  assert(count == 1);
  ck_free(states);
  invalid[5] = 2;
  states = extract_response_codes_modbus(invalid, sizeof(invalid) - 1, &count);
  assert(count == 1);
  ck_free(states);

  /* Fuzzed Unit IDs and undefined function codes must not multiply errors. */
  for (unsigned int unit = 0; unit < 256; unit++) {
    for (unsigned int fc = 0x80; fc < 256; fc++) {
      assert(response_state(unit, fc, 1) == illegal_function);
    }
  }
  destroy_message_code_map();
  puts("Modbus response-state tests passed");
  return 0;
}
