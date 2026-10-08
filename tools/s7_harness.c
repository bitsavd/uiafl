#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/time.h>

#define DEFAULT_TIMEOUT_MS 200
#define MAX_S7_ITEM_COUNT 8
#define DEFAULT_MAX_INPUT 4096

static volatile unsigned int coverage_sink;
static int s7_only_coverage = -1;

static void ignore_sigpipe(void) {
  signal(SIGPIPE, SIG_IGN);
}

static void *xrealloc(void *ptr, size_t size) {
  void *p = realloc(ptr, size);
  if (!p) {
    fprintf(stderr, "[!] memory allocation failed\n");
    exit(1);
  }
  return p;
}

static ssize_t read_all_input(unsigned char **buf) {
  size_t cap = 4096;
  size_t sz = 0;
  ssize_t r;

  *buf = malloc(cap);
  if (!*buf) return -1;

  while (1) {
    if (sz + 4096 > cap) {
      cap = cap * 2;
      *buf = xrealloc(*buf, cap);
    }

    r = read(STDIN_FILENO, *buf + sz, 4096);
    if (r < 0) return -1;
    if (r == 0) break;
    sz += (size_t)r;
  }

  return (ssize_t)sz;
}

static ssize_t read_file_input(const char *path, unsigned char **buf) {
  FILE *fp = fopen(path, "rb");
  if (!fp) return -1;
  if (fseek(fp, 0, SEEK_END) != 0) {
    fclose(fp);
    return -1;
  }
  long sz = ftell(fp);
  if (sz <= 0) {
    fclose(fp);
    return -1;
  }
  rewind(fp);
  *buf = malloc((size_t)sz);
  if (!*buf) {
    fclose(fp);
    return -1;
  }
  if (fread(*buf, 1, (size_t)sz, fp) != (size_t)sz) {
    fclose(fp);
    free(*buf);
    *buf = NULL;
    return -1;
  }
  fclose(fp);
  return (ssize_t)sz;
}

static int send_all(int sock, const unsigned char *buf, size_t len) {
  size_t sent = 0;
  while (sent < len) {
    ssize_t ret = send(sock, buf + sent, len - sent, 0);
    if (ret <= 0) return -1;
    sent += (size_t)ret;
  }
  return 0;
}

static void touch(unsigned int v) {
  coverage_sink ^= v;
}

static size_t max_input_size(void) {
  const char *override = getenv("S7_HARNESS_MAX_INPUT");
  char *endptr = NULL;
  unsigned long parsed;

  if (!override || !*override) return DEFAULT_MAX_INPUT;
  parsed = strtoul(override, &endptr, 10);
  if (endptr == override) return DEFAULT_MAX_INPUT;
  return (size_t)parsed;
}

static int strict_s7_coverage(void) {
  const char *override;
  if (s7_only_coverage >= 0) return s7_only_coverage;
  override = getenv("S7_HARNESS_S7_ONLY_COVERAGE");
  if (override && (!strcmp(override, "0") || !strcmp(override, "false") || !strcmp(override, "FALSE"))) {
    s7_only_coverage = 0;
  } else {
    s7_only_coverage = 1;
  }
  return s7_only_coverage;
}

static void inspect_var_items(const unsigned char *params, unsigned int params_len) {
  if (params_len < 2) return;
  unsigned int item_count = params[1];
  if (item_count > MAX_S7_ITEM_COUNT) item_count = MAX_S7_ITEM_COUNT;
  touch(0x100 + item_count);

  for (unsigned int i = 0; i < item_count; i++) {
    unsigned int idx = 2 + i * 12;
    if (idx + 12 > params_len) break;
    unsigned char spec_type = params[idx];
    unsigned char spec_len = params[idx + 1];
    unsigned char syntax_id = params[idx + 2];
    unsigned char transport_size = params[idx + 3];
    unsigned int count = ((unsigned int)params[idx + 4] << 8) | params[idx + 5];
    unsigned int db_number = ((unsigned int)params[idx + 6] << 8) | params[idx + 7];
    unsigned char area = params[idx + 8];
    unsigned int bit_addr = ((unsigned int)params[idx + 9] << 16) |
                            ((unsigned int)params[idx + 10] << 8) |
                            params[idx + 11];

    if (spec_type == 0x12) touch(0x200 + i);
    else touch(0x210 + (spec_type & 0x0f));

    if (spec_len == 0x0a && syntax_id == 0x10) touch(0x220 + i);
    if (transport_size == 0x02) touch(0x230 + (count & 0x0f));
    else if (transport_size == 0x04) touch(0x240 + (count & 0x0f));
    else if (transport_size == 0x1c || transport_size == 0x1d) touch(0x250 + transport_size);
    else touch(0x260 + (transport_size & 0x0f));

    switch (area) {
      case 0x81: touch(0x300 + (bit_addr & 0x1f)); break;
      case 0x82: touch(0x340 + (bit_addr & 0x1f)); break;
      case 0x83: touch(0x380 + (bit_addr & 0x1f)); break;
      case 0x84:
        if (db_number == 1) touch(0x3c0 + (bit_addr & 0x1f));
        else if (db_number > 1000) touch(0x3e0 + (db_number & 0x0f));
        else touch(0x3d0 + (db_number & 0x0f));
        break;
      case 0x1c: touch(0x410 + (bit_addr & 0x0f)); break;
      case 0x1d: touch(0x420 + (bit_addr & 0x0f)); break;
      default: touch(0x430 + (area & 0x0f)); break;
    }

    if (bit_addr == 0) touch(0x500 + i);
    else if (bit_addr < 128) touch(0x520 + (bit_addr & 0x0f));
    else touch(0x540 + ((bit_addr >> 3) & 0x0f));
  }
}

static void inspect_write_data(const unsigned char *data, unsigned int data_len) {
  unsigned int off = 0;
  unsigned int item_idx = 0;
  while (off + 4 <= data_len && item_idx < MAX_S7_ITEM_COUNT) {
    unsigned char transport_size = data[off + 1];
    unsigned int bit_len = ((unsigned int)data[off + 2] << 8) | data[off + 3];
    unsigned int byte_len = (bit_len + 7) / 8;
    if (transport_size == 0x04) touch(0x600 + (bit_len & 0x0f));
    else touch(0x620 + (transport_size & 0x0f));
    if (off + 4 + byte_len <= data_len && byte_len > 0) {
      unsigned char first = data[off + 4];
      if (first == 0x00) touch(0x640 + item_idx);
      else if (first == 0xff) touch(0x650 + item_idx);
      else touch(0x660 + (first & 0x0f));
      off += 4 + byte_len;
    } else {
      touch(0x670 + item_idx);
      break;
    }
    item_idx++;
  }
}

static void handle_s7_function(unsigned char fn_code, unsigned char rosctr,
                               unsigned int param_len, const unsigned char *params,
                               unsigned int data_len, const unsigned char *data) {
  switch (fn_code) {
    case 0xf0:
      if (param_len >= 8) {
        unsigned int pdu_len = ((unsigned int)params[6] << 8) | params[7];
        if (pdu_len >= 480) touch(0x700);
        else touch(0x710 + (pdu_len & 0x0f));
      }
      break;
    case 0x04:
      inspect_var_items(params, param_len);
      break;
    case 0x05:
      inspect_var_items(params, param_len);
      inspect_write_data(data, data_len);
      break;
    case 0x00:
      if (param_len > 0 && params[0] == 0x00) {
        touch(0x720);
      }
      break;
    case 0x0f:
      if (rosctr == 0x01) {
        inspect_var_items(params, param_len);
      } else {
        if (data_len > 0 && data[0] == 0x00) {
          touch(0x730);
        }
      }
      break;
    case 0x16:
      if (param_len > 2) {
        inspect_var_items(params + 2, param_len - 2);
      }
      break;
    case 0x1a: touch(0x740); break;
    case 0x28: touch(0x750); break;
    case 0x29: touch(0x760); break;
    default:
      if (fn_code < 0x10) {
        touch(0x780 + fn_code);
      } else {
        touch(0x7a0 + (fn_code & 0x0f));
      }
  }
}

static void parse_s7_packet(const unsigned char *packet, unsigned int pkt_len) {
  if (pkt_len < 12) return;
  unsigned int payload_off = 4; // skip TPKT

  if (payload_off + 3 > pkt_len) return;
  unsigned char cotp_len = packet[payload_off];
  unsigned char cotp_type = packet[payload_off + 1];
  unsigned char cotp_last = packet[payload_off + 2];

  if (cotp_len < 2 || payload_off + cotp_len > pkt_len) return;
  if (!strict_s7_coverage()) {
    if ((cotp_type & 0xf0) == 0xe0) touch(0x800 + cotp_len);
    else if ((cotp_type & 0xf0) == 0xf0) touch(0x820 + (cotp_last & 0x0f));
    else touch(0x840 + ((cotp_type >> 4) & 0x0f));
  }

  unsigned int s7_off = payload_off + 3;
  if (s7_off + 10 > pkt_len) return;
  if (packet[s7_off] != 0x32) return;

  unsigned char rosctr = packet[s7_off + 1];
  if (rosctr == 0x01) touch(0x900);
  else if (rosctr == 0x03) touch(0x910);
  else touch(0x920 + (rosctr & 0x0f));
  unsigned int header_len = 10;
  if ((rosctr == 0x03 || rosctr == 0x07) && s7_off + 12 <= pkt_len) {
    header_len = 12;
  }
  unsigned int param_len = ((unsigned int)packet[s7_off + 6] << 8) | packet[s7_off + 7];
  unsigned int data_len = ((unsigned int)packet[s7_off + 8] << 8) | packet[s7_off + 9];
  unsigned int params_start = s7_off + header_len;
  unsigned int data_start = params_start + param_len;

  unsigned char fn_code = 0;
  if (params_start < pkt_len) fn_code = packet[params_start];
  if (params_start > pkt_len) {
    touch(0x930);
    return;
  }

  unsigned int param_avail = pkt_len - params_start;
  if (param_len > param_avail) {
    touch(0x940 + (param_len & 0x0f));
    param_len = param_avail;
  }

  const unsigned char *data_ptr = NULL;
  if (data_start <= pkt_len) {
    unsigned int data_avail = pkt_len - data_start;
    if (data_len > data_avail) {
      touch(0x960 + (data_len & 0x0f));
      data_len = data_avail;
    }
    data_ptr = packet + data_start;
  } else {
    touch(0x950 + (data_len & 0x0f));
    data_len = 0;
  }

  handle_s7_function(fn_code, rosctr, param_len,
                     packet + params_start,
                     data_len,
                     data_ptr);

  if (cotp_last & 0x80) {
    (void)cotp_type;
    (void)cotp_last;
  }
}

static void inspect_unknown_input(const unsigned char *buf, size_t buf_sz) {
  if (buf_sz > 0) {
    volatile unsigned char x = buf[0];
    if (x == 0) __builtin_expect(x, 0);
  }
}

static int configure_timeout(int sock) {
  const char *override = getenv("S7_TIMEOUT_MS");
  long timeout_ms = DEFAULT_TIMEOUT_MS;
  if (override) {
    char *endptr = NULL;
    timeout_ms = strtol(override, &endptr, 10);
    if (endptr == override || timeout_ms < 100) timeout_ms = DEFAULT_TIMEOUT_MS;
  }

  struct timeval tv;
  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;
  if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) return -1;
  return setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

int main(int argc, char **argv) {
  const char *default_ip = "192.168.0.13";
  const char *default_port = "102";
  const char *ip = getenv("S7_TARGET");
  const char *port = getenv("S7_PORT");
  if (!ip) ip = default_ip;
  if (!port) port = default_port;

  unsigned char *buf = NULL;
  ssize_t buf_sz;
  if (argc > 1) buf_sz = read_file_input(argv[1], &buf);
  else buf_sz = read_all_input(&buf);
  if (buf_sz <= 0) {
    free(buf);
    return 1;
  }

  size_t max_input = max_input_size();
  if (max_input && (size_t)buf_sz > max_input) {
    touch(0xa00 + (((unsigned int)buf_sz >> 8) & 0x3f));
    buf_sz = (ssize_t)max_input;
  }

  ignore_sigpipe();

  int saw_s7 = 0;
  size_t offset = 0;
  while (offset + 4 <= (size_t)buf_sz) {
    if (buf[offset] != 0x03) {
      offset++;
      continue;
    }

    if (offset + 4 > (size_t)buf_sz) break;
    unsigned int pkt_len = ((unsigned int)buf[offset + 2] << 8) | buf[offset + 3];
    if (pkt_len < 4 || offset + pkt_len > (size_t)buf_sz) break;

    parse_s7_packet(buf + offset, pkt_len);
    saw_s7 = 1;
    offset += pkt_len;
  }

  if (!saw_s7) {
    inspect_unknown_input(buf, (size_t)buf_sz);
  }

  const char *connect_mode = getenv("S7_HARNESS_CONNECT");
  if (!connect_mode || strcmp(connect_mode, "1") != 0) {
    free(buf);
    return 0;
  }

  struct addrinfo hints;
  struct addrinfo *res = NULL;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  if (getaddrinfo(ip, port, &hints, &res) != 0) {
    free(buf);
    return 1;
  }

  int sock = -1;
  for (struct addrinfo *rp = res; rp != NULL; rp = rp->ai_next) {
    sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (sock == -1) continue;
    if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) break;
    close(sock);
    sock = -1;
  }
  freeaddrinfo(res);

  if (sock == -1) {
    free(buf);
    return 1;
  }

  int one = 1;
  setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
  if (configure_timeout(sock) < 0) {
    close(sock);
    free(buf);
    return 1;
  }

  if (send_all(sock, buf, (size_t)buf_sz) < 0) {
    close(sock);
    free(buf);
    return 1;
  }

  unsigned char rbuf[4096];
  while (1) {
    ssize_t rr = recv(sock, rbuf, sizeof(rbuf), 0);
    if (rr <= 0) break;
  }

  close(sock);
  free(buf);
  return 0;
}
