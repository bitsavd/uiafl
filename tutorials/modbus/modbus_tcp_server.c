#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_ADU 260

static uint16_t be16(const uint8_t *p) {
  return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static void put16(uint8_t *p, uint16_t value) {
  p[0] = (uint8_t)(value >> 8);
  p[1] = (uint8_t)(value & 0xff);
}

static int send_response(int fd, const uint8_t *req, const uint8_t *pdu, uint16_t pdu_len) {
  uint8_t out[MAX_ADU];
  if ((size_t)pdu_len + 7 > sizeof(out)) return -1;

  memcpy(out, req, 4);
  put16(out + 4, (uint16_t)(pdu_len + 1));
  out[6] = req[6];
  memcpy(out + 7, pdu, pdu_len);
  size_t sent = 0, total = pdu_len + 7;
  while (sent < total) {
    ssize_t n = send(fd, out + sent, total - sent, 0);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return -1;
    sent += (size_t)n;
  }
  return (int)total;
}

static int send_exception(int fd, const uint8_t *req, uint8_t fc, uint8_t code) {
  uint8_t pdu[2] = {(uint8_t)(fc | 0x80), code};
  return send_response(fd, req, pdu, sizeof(pdu));
}

static int handle_request(int fd, const uint8_t *req, size_t len) {
  uint8_t pdu[MAX_ADU];
  uint8_t fc;
  uint16_t start, qty, byte_count;

  if (len < 8) return -1;
  if (be16(req + 2) != 0) return send_exception(fd, req, 0, 0x01);

  fc = req[7];

  switch (fc) {
    case 0x01:
    case 0x02:
      if (len < 12) return send_exception(fd, req, fc, 0x03);
      start = be16(req + 8);
      qty = be16(req + 10);
      (void)start;
      if (qty == 0 || qty > 2000) return send_exception(fd, req, fc, 0x03);
      byte_count = (uint16_t)((qty + 7) / 8);
      pdu[0] = fc;
      pdu[1] = (uint8_t)byte_count;
      for (uint16_t i = 0; i < byte_count; i++) pdu[2 + i] = (uint8_t)(0x5a ^ i);
      return send_response(fd, req, pdu, (uint16_t)(2 + byte_count));

    case 0x03:
    case 0x04:
      if (len < 12) return send_exception(fd, req, fc, 0x03);
      start = be16(req + 8);
      qty = be16(req + 10);
      if (qty == 0 || qty > 125) return send_exception(fd, req, fc, 0x03);
      pdu[0] = fc;
      pdu[1] = (uint8_t)(qty * 2);
      for (uint16_t i = 0; i < qty; i++) put16(pdu + 2 + i * 2, (uint16_t)(start + i));
      return send_response(fd, req, pdu, (uint16_t)(2 + qty * 2));

    case 0x05:
      if (len < 12) return send_exception(fd, req, fc, 0x03);
      if (be16(req + 10) != 0x0000 && be16(req + 10) != 0xff00) return send_exception(fd, req, fc, 0x03);
      return send_response(fd, req, req + 7, 5);

    case 0x06:
      if (len < 12) return send_exception(fd, req, fc, 0x03);
      return send_response(fd, req, req + 7, 5);

    case 0x08:
      if (len < 12) return send_exception(fd, req, fc, 0x03);
      return send_response(fd, req, req + 7, 5);

    case 0x0f:
      if (len < 13) return send_exception(fd, req, fc, 0x03);
      qty = be16(req + 10);
      byte_count = req[12];
      if (qty == 0 || qty > 1968 || byte_count != (uint16_t)((qty + 7) / 8) || len < 13 + byte_count) {
        return send_exception(fd, req, fc, 0x03);
      }
      memcpy(pdu, req + 7, 5);
      return send_response(fd, req, pdu, 5);

    case 0x10:
      if (len < 13) return send_exception(fd, req, fc, 0x03);
      qty = be16(req + 10);
      byte_count = req[12];
      if (qty == 0 || qty > 123 || byte_count != qty * 2 || len < 13 + byte_count) {
        return send_exception(fd, req, fc, 0x03);
      }
      memcpy(pdu, req + 7, 5);
      return send_response(fd, req, pdu, 5);

    case 0x16:
      if (len < 14) return send_exception(fd, req, fc, 0x03);
      return send_response(fd, req, req + 7, 7);

    case 0x17:
      if (len < 17) return send_exception(fd, req, fc, 0x03);
      qty = be16(req + 10);
      if (qty == 0 || qty > 125) return send_exception(fd, req, fc, 0x03);
      pdu[0] = fc;
      pdu[1] = (uint8_t)(qty * 2);
      for (uint16_t i = 0; i < qty; i++) put16(pdu + 2 + i * 2, (uint16_t)(0x1000 + i));
      return send_response(fd, req, pdu, (uint16_t)(2 + qty * 2));

    case 0x2b:
      if (len < 11 || req[8] != 0x0e) return send_exception(fd, req, fc, 0x01);
      pdu[0] = 0x2b;
      pdu[1] = 0x0e;
      pdu[2] = 0x01;
      pdu[3] = 0x01;
      pdu[4] = 0x00;
      pdu[5] = 0x00;
      pdu[6] = 0x01;
      pdu[7] = 0x00;
      pdu[8] = 0x06;
      memcpy(pdu + 9, "AFLNET", 6);
      return send_response(fd, req, pdu, 15);

    default:
      return send_exception(fd, req, fc, 0x01);
  }
}

static int receive_exact(int fd, uint8_t *buf, size_t length) {
  size_t received = 0;
  while (received < length) {
    ssize_t n = recv(fd, buf + received, length - received, 0);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return -1;
    received += (size_t)n;
  }
  return 0;
}

static void serve_client(int fd) {
  uint8_t buf[MAX_ADU];

  /* Read one ADU at a time, independently of TCP segment boundaries. */
  while (receive_exact(fd, buf, 7) == 0) {
    uint16_t length = be16(buf + 4);
    if (length < 2 || length > 254) return;
    size_t adu_len = 6 + length;
    if (receive_exact(fd, buf + 7, adu_len - 7) != 0) return;
    if (handle_request(fd, buf, adu_len) < 0) return;
  }
}

int main(int argc, char **argv) {
  int port = argc > 1 ? atoi(argv[1]) : 1502;
  int srv = socket(AF_INET, SOCK_STREAM, 0);
  int yes = 1;
  struct sockaddr_in addr;

  signal(SIGPIPE, SIG_IGN);

  if (srv < 0) {
    perror("socket");
    return 1;
  }

  setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons((uint16_t)port);

  if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("bind");
    close(srv);
    return 1;
  }

  if (listen(srv, 16) < 0) {
    perror("listen");
    close(srv);
    return 1;
  }

  for (;;) {
    int client = accept(srv, NULL, NULL);
    if (client < 0) {
      if (errno == EINTR) continue;
      perror("accept");
      break;
    }
    serve_client(client);
    close(client);
  }

  close(srv);
  return 0;
}
