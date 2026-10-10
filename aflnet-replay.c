#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <netdb.h>
#include "alloc-inl.h"
#include "aflnet.h"

#define server_wait_usecs 10000

unsigned int* (*extract_response_codes)(unsigned char* buf, unsigned int buf_size, unsigned int* state_count_ref) = NULL;

/* Expected arguments:
1. Path to the test case (e.g., crash-triggering input)
2. Application protocol (e.g., RTSP, FTP)
3. Server's network port
Optional:
4. Response poll timeout (ms), default 1
5. Per-recv socket timeout (us), default 1000
6. Target hostname or IPv4 address, default 127.0.0.1
7. Transport (tcp/udp), defaults to the protocol's usual transport
*/

static int drain_available_responses(int sockfd, struct timeval timeout, int poll_w,
                                     char **response_buf, unsigned int *len) {
  char temp_buf[1000];
  int n;
  struct pollfd pfd[1];

  pfd[0].fd = sockfd;
  pfd[0].events = POLLIN;

  if (poll(pfd, 1, poll_w) <= 0) return 0;
  if (!(pfd[0].revents & POLLIN)) return (pfd[0].revents != 0);

  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));

  while (1) {
    n = recv(sockfd, temp_buf, sizeof(temp_buf), MSG_DONTWAIT);
    if (n > 0) {
      *response_buf = (unsigned char *)ck_realloc(*response_buf, *len + n + 1);
      memcpy(&(*response_buf)[*len], temp_buf, n);
      (*response_buf)[(*len) + n] = '\0';
      *len += n;
      continue;
    }

    if (n == 0) break;
    if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) break;
    return 1;
  }

  return 0;
}

int main(int argc, char* argv[])
{
  FILE *fp;
  int portno, n;
  struct sockaddr_in serv_addr;
  char* buf = NULL, *response_buf = NULL;
  int response_buf_size = 0;
  unsigned int size, i, state_count, packet_count = 0;
  unsigned int *state_sequence;
  unsigned int socket_timeout = 1000;
  unsigned int poll_timeout = 1;


  if (argc < 4) {
    PFATAL("Usage: ./aflnet-replay packet_file protocol port [poll_timeout(ms) [socket_timeout(us) [host [tcp|udp]]]]");
  }

  fp = fopen(argv[1],"rb");
  if(fp == NULL){
    fprintf(stderr, "[AFLNet-replay] Error opening file %s\n", argv[1]); 
    exit(1);
  }
  
  if (!strcmp(argv[2], "RTSP")) extract_response_codes = &extract_response_codes_rtsp;
  else if (!strcmp(argv[2], "FTP")) extract_response_codes = &extract_response_codes_ftp;
  else if (!strcmp(argv[2], "MQTT")) extract_response_codes = &extract_response_codes_mqtt;
  else if (!strcmp(argv[2], "DNS")) extract_response_codes = &extract_response_codes_dns;
  else if (!strcmp(argv[2], "DTLS12")) extract_response_codes = &extract_response_codes_dtls12;
  else if (!strcmp(argv[2], "DICOM")) extract_response_codes = &extract_response_codes_dicom;
  else if (!strcmp(argv[2], "SMTP")) extract_response_codes = &extract_response_codes_smtp;
  else if (!strcmp(argv[2], "SSH")) extract_response_codes = &extract_response_codes_ssh;
  else if (!strcmp(argv[2], "TLS")) extract_response_codes = &extract_response_codes_tls;
  else if (!strcmp(argv[2], "SIP")) extract_response_codes = &extract_response_codes_sip;
  else if (!strcmp(argv[2], "HTTP")) extract_response_codes = &extract_response_codes_http;
  else if (!strcmp(argv[2], "IPP")) extract_response_codes = &extract_response_codes_ipp;
  else if (!strcmp(argv[2], "SNMP")) extract_response_codes = &extract_response_codes_SNMP;
  else if (!strcmp(argv[2], "TFTP")) extract_response_codes = &extract_response_codes_tftp;
  else if (!strcmp(argv[2], "NTP")) extract_response_codes = &extract_response_codes_NTP;
  else if (!strcmp(argv[2], "DHCP")) extract_response_codes = &extract_response_codes_dhcp;
  else if (!strcmp(argv[2], "SNTP")) extract_response_codes = &extract_response_codes_SNTP;  
  else if (!strcmp(argv[2], "MODBUS")) extract_response_codes = &extract_response_codes_modbus;
else {fprintf(stderr, "[AFLNet-replay] Protocol %s has not been supported yet!\n", argv[2]); exit(1);}

  init_message_code_map();

  portno = atoi(argv[3]);

  if (argc > 4) {
    poll_timeout = atoi(argv[4]);
    if (argc > 5) {
      socket_timeout = atoi(argv[5]);
    }
  }

  //Wait for the server to initialize
  usleep(server_wait_usecs);

  if (response_buf) {
    ck_free(response_buf);
    response_buf = NULL;
    response_buf_size = 0;
  }

  int sockfd;
  int udp = !strcmp(argv[2], "DTLS12") || !strcmp(argv[2], "DNS") || !strcmp(argv[2], "SIP") ||
            !strcmp(argv[2], "SNMP") || !strcmp(argv[2], "TFTP") || !strcmp(argv[2], "NTP") ||
            !strcmp(argv[2], "DHCP") || !strcmp(argv[2], "SNTP");
  if (argc > 7) {
    if (strcmp(argv[7], "tcp") && strcmp(argv[7], "udp")) FATAL("Transport must be tcp or udp");
    udp = !strcmp(argv[7], "udp");
  }
  sockfd = socket(AF_INET, udp ? SOCK_DGRAM : SOCK_STREAM, 0);

  if (sockfd < 0) {
    PFATAL("Cannot create a socket");
  }

  //Set timeout for socket data sending/receiving -- otherwise it causes a big delay
  //if the server is still alive after processing all the requests
  struct timeval timeout;

  timeout.tv_sec = 0;
  timeout.tv_usec = socket_timeout;

  setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));

  memset(&serv_addr, '0', sizeof(serv_addr));

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(portno);
  struct addrinfo hints, *address;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = udp ? SOCK_DGRAM : SOCK_STREAM;
  if (getaddrinfo(argc > 6 ? argv[6] : "127.0.0.1", NULL, &hints, &address)) FATAL("Cannot resolve target host");
  serv_addr.sin_addr = ((struct sockaddr_in *)address->ai_addr)->sin_addr;
  freeaddrinfo(address);

  if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    //If it cannot connect to the server under test
    //try it again as the server initial startup time is varied
    for (n=0; n < 1000; n++) {
      if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0) break;
      usleep(1000);
    }
    if (n== 1000) {
      close(sockfd);
      return 1;
    }
  }

  //Send requests one by one
  //And save all the server responses
  while(!feof(fp)) {
    if (buf) {ck_free(buf); buf = NULL;}
    if (fread(&size, sizeof(unsigned int), 1, fp) > 0) {
      packet_count++;
    	fprintf(stderr,"\nSize of the current packet %d is  %d\n", packet_count, size);

      buf = (char *)ck_alloc(size);
      fread(buf, size, 1, fp);

      n = net_send(sockfd, timeout, buf,size);
      if (n != size) break;

      if (drain_available_responses(sockfd, timeout, poll_timeout, &response_buf, &response_buf_size)) break;
    }
  }

  fclose(fp);
  close(sockfd);

  //Extract response codes
  state_sequence = (*extract_response_codes)(response_buf, response_buf_size, &state_count);

  fprintf(stderr,"\n--------------------------------");
  fprintf(stderr,"\nResponses from server:");

  for (i = 0; i < state_count; i++) {
    fprintf(stderr,"%d-",state_sequence[i]);
  }

  fprintf(stderr,"\n++++++++++++++++++++++++++++++++\nResponses in details:\n");
  for (i=0; i < response_buf_size; i++) {
    unsigned char byte = response_buf[i];
    if ((byte >= 32 && byte <= 126) || byte == '\n' || byte == '\r' || byte == '\t')
      fprintf(stderr, "%c", byte);
    else
      fprintf(stderr, "\\x%02x", byte);
  }
  fprintf(stderr,"\n--------------------------------");

  //Free memory
  ck_free(state_sequence);
  if (buf) ck_free(buf);
  ck_free(response_buf);
  destroy_message_code_map();

  return 0;
}
