#include <assert.h>
#include <stdio.h>
#include "alloc-inl.h"
#include "aflnet.h"

int main(void) {
  unsigned char protocol;
  unsigned char *host;
  unsigned int port;
  assert(parse_net_config((unsigned char *)"tcp://localhost/5158", &protocol, &host, &port) == 0);
  assert(protocol == PRO_TCP && port == 5158);
  free(host);
  assert(parse_net_config((unsigned char *)"udp://127.0.0.1/99999", &protocol, &host, &port) != 0);
  assert(parse_net_config((unsigned char *)"udp://127.0.0.1/53abc", &protocol, &host, &port) != 0);
  init_message_code_map();
  unsigned char stream[] = {2, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 2, 0, 0,
                            6, 0, 0, 0, 0, 0};
  unsigned int count;
  unsigned int *states = extract_response_codes_dicom(stream, sizeof(stream), &count);
  assert(count == 4 && states[0] == 0);
  assert(states[1] != states[2] && states[2] != states[3]);
  ck_free(states);
  for (unsigned int size = 1; size < 6; size++) {
    states = extract_response_codes_dicom(stream, size, &count);
    assert(count == 1);
    ck_free(states);
  }
  unsigned char oversized[] = {4, 0, 255, 255, 255, 255};
  states = extract_response_codes_dicom(oversized, sizeof(oversized), &count);
  assert(count == 1);
  ck_free(states);
  destroy_message_code_map();
  puts("DICOM complete, concatenated and truncated PDU tests passed");
  return 0;
}
