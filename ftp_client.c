/* cc -Wall -Wextra -std=c18 -static */

#define _POSIX_C_SOURCE 1

#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <unistd.h>

#define min(a,b) (a > b ? b : a)
#define max(a,b) (a < b ? b : a)

#define BUF_SIZE 2048

#define CACHE_SIZE (BUF_SIZE * 2)
typedef struct SCache
{
  char buf[CACHE_SIZE];
  size_t len;
} cache_s;

int
cache_append(cache_s *const cache, const char *const src, const size_t n)
{
  int nb_lost_bytes = 0;
  if (cache->len + n >= CACHE_SIZE)
  {
    nb_lost_bytes = (cache->len + n) - (CACHE_SIZE - 1);
    if (n >= CACHE_SIZE)
    {
      cache->len = 0;
    }
    else
    {
      nb_lost_bytes =  CACHE_SIZE - 1 - (cache->len + n);
      char *const new_start = cache->buf + nb_lost_bytes;
      const size_t new_len = cache->len - nb_lost_bytes;
      memmove(cache->buf, new_start, new_len);
      cache->len = new_len;
    }
  }
  memcpy(cache->buf + cache->len, src, n);
  cache->len += n;
  cache->buf[cache->len] = '\0';
  return nb_lost_bytes;
}

void
cache_full_flush(cache_s *const cache)
{
  cache->len = 0;
  cache->buf[cache->len] = '\0';
}


int
cache_line_flush(cache_s *const cache)
{
  const char *const newline = memchr(cache->buf, '\n', cache->len);
  if (newline == NULL)
  {
    return -1;
  }
  const size_t nb_bytes_to_flush = newline + 1 - cache->buf;
  const size_t new_len = cache->len - nb_bytes_to_flush;
  memmove(cache->buf, newline + 1, new_len);
  cache->len = new_len;
  cache->buf[cache->len] = '\0';
  return 0;
}

struct SListNode
{
  int val;
  struct SListNode * next;
};

typedef struct SListNode * list_t;

int
list_add(list_t *const list, const int val)
{
  if (list == NULL)
  {
    return -1;
  }
  errno = 0;
  struct SListNode * new_node = malloc(sizeof(struct SListNode));
  if (new_node == NULL)
  {
    warn("Cannot alloacate memory for a new list element");
    return -2;
  }
  new_node->val = val;
  new_node->next = *list;
  *list = new_node;
  return 0;
}

int
list_remove(list_t *const list, const list_t elem)
{
  if (list == NULL || *list == NULL || elem == NULL)
  {
    return -1;
  }
  if (*list == elem)
  {
    *list = (*list)->next;
    free(elem);
    return 0;
  }
  for (struct SListNode *node = *list; node->next != NULL; node = node->next)
  {
    if (node->next == elem)
    {
      node->next = node->next->next;
      free(elem);
      return 0;
    }
  }
  return -1;
}

int
strtoport(const char *const str, uint16_t *const port)
{
  char * endptr = NULL;
  errno = 0;
  const unsigned long value = strtoul(str, &endptr, 10);
  if (endptr == str || *endptr != '\0' || value > UINT16_MAX || errno != 0)
  {
    warnx("Invalid port number (%s). Should be a number between "
          "0 and %" PRIu16, str, UINT16_MAX);
    return -1;
  }
  *port = htons((uint16_t) value);
  return 0;
}

int
strtobyte(const char *const str, uint8_t *const byte)
{
  char * endptr = NULL;
  errno = 0;
  unsigned long value = strtoul(str, &endptr, 10);
  if (endptr == str || *endptr != '\0' || value > UINT8_MAX || errno != 0)
  {
    warnx("Invalid byte value (%s). Should be a number between 0 and %" PRIu8,
           str, UINT8_MAX);
    return -1;
  }
  *byte = (uint8_t) value;
  return 0;
}

int
connect_to_server(const char *const ip, const uint16_t port)
{
  struct sockaddr_in server_addr = {.sin_family = AF_INET, .sin_port = port};

  errno = 0;
  const int res = inet_pton(AF_INET, ip, &server_addr.sin_addr);
  if (res == 0)
  {
    warnx("Invalid IP address (%s)", ip);
    return -1;
  }
  else if (res < 0)
  {
    warn("Bad address family");
    return -1;
  }

  int sock = -1;
  errno = 0;
  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
  {
    warn("Cannot create socket");
    return -1;
  }

  errno = 0;
  if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
  {
    warn("Cannot connect to server at %s:%hu", ip, ntohs(port));
    if (close(sock) < 0)
    {
      warn("Cannot close the socket");
    }
    return -1;
  }
  return sock;
}

/* 227 Entering Passive Mode (ip1,ip2,ip3,ip4,port1,port2) */
#define PASV_RESP_PREFIX "227 Entering passive mode ("
#define PASV_RESP_LAST_CHAR ')'
#define PASV_RESP_BYTE_SEP ","

int
search_pasv_resp(cache_s *const cache, list_t *const pasv_sock)
{
  // puts("Looking for PASV resp code"); /* DEBUG */
  if (memcmp(cache->buf, PASV_RESP_PREFIX, sizeof(PASV_RESP_PREFIX) - 1) != 0)
  {
    return 1;
  }
  // printf("Resp found in %s\n", cache->buf); /* DEBUG */
  char *const ip_port_pos = cache->buf + sizeof(PASV_RESP_PREFIX) - 1;
  char *const end_resp = memchr(cache->buf, PASV_RESP_LAST_CHAR, cache->len);
  if (end_resp == NULL)
  {
    warnx("Invalid PASV response (should end with %c)", PASV_RESP_LAST_CHAR);
  }
  else
  {
    *end_resp = '\0';
  }
  uint8_t ip_port[6];
  const char * current_byte = strtok(ip_port_pos, PASV_RESP_BYTE_SEP);
  for (size_t i = 0; i < 6; ++i)
  {
    if (current_byte == NULL)
    {
      warnx("Invalid PASV response (should contain 6 numbers separated by "
            "'%s')", PASV_RESP_BYTE_SEP);
      return -1;
    }
    if (strtobyte(current_byte, &ip_port[i]) < 0)
    {
      return -1;
    }
    current_byte = strtok(NULL, PASV_RESP_BYTE_SEP);
  }
  char pasv_ip[16] = {0};
  snprintf(pasv_ip, 16, "%hhu.%hhu.%hhu.%hhu", ip_port[0], ip_port[1],
           ip_port[2], ip_port[3]);
  const uint16_t pasv_port = htons(((uint16_t) ip_port[4]) << 8 |
                                   (uint16_t) ip_port[5]);
  const int sock = connect_to_server(pasv_ip, pasv_port);
  if (sock < 0)
  {
    return -1;
  }

  if (list_add(pasv_sock, sock) < 0)
  {
    warn("Cannot add passive socket to the list of sockets");
    errno = 0;
    if (shutdown(sock, SHUT_RDWR) < 0)
    {
      warn("Cannot shutdown the passive connexion");
    }
    errno = 0;
    if (close(sock) < 0)
    {
      warn("Cannot close the passive socket");
    }
    return -1;
  }
  return 0;
}

int
force_pasv(char *buf, list_t *const pasv_sock)
{
  const char *const ip = strtok(buf, " ");
  if (ip == NULL)
  {
    warnx("Missing <IP> and <PORT> arguments to command");
    return -1;
  }
  uint16_t port;
  if (strtoport(strtok(NULL, "\n"), &port) < 0)
  {
    return -1;
  }
  const int sock = connect_to_server(ip, port);
  if (sock < 0)
  {
    return -1;
  }
  if (list_add(pasv_sock, sock) < 0)
  {
    warn("Cannot add passive socket to the list of sockets");
    errno = 0;
    if (shutdown(sock, SHUT_RDWR) < 0)
    {
      warn("Cannot shutdown the passive connexion");
    }
    errno = 0;
    if (close(sock) < 0)
    {
      warn("Cannot close the passive socket");
    }
    return -1;
  }
  return 0;
}

int
main(int argc, char *argv[])
{
  if (argc != 3)
  {
    printf("usage: %s <IP> <PORT>\n", argv[0]);
    return 64;
  }

  uint16_t port;
  if (strtoport(argv[2], &port) < 0)
  {
    return EXIT_FAILURE;
  }

  const int sock = connect_to_server(argv[1], port);
  if (sock < 0)
  {
    return EXIT_FAILURE;
  }

  errno = 0;
  int stdin_fd = fileno(stdin);
  if (stdin_fd < 0)
  {
    err(EXIT_FAILURE, "Cannot get stdin file descriptor");
  }

  fd_set readfds;
  FD_ZERO(&readfds);
  FD_SET(stdin_fd, &readfds);
  FD_SET(sock, &readfds);
  int max_fd = max(stdin_fd, sock);
  list_t pasv_sock = NULL;

  bool expecting_response = false, pasv_requested = false;
  char buf[BUF_SIZE] = {0};
  cache_s cache = {.buf = {0}, .len = 0};
  int fd = -1;
  while (errno = 0, fd = select(max_fd + 1, &readfds, NULL, NULL, NULL) >= 0)
  {
    if (FD_ISSET(sock, &readfds))
    {
      const ssize_t n = recv(sock, buf, BUF_SIZE - 1, 0);
      buf[n] = '\0';
      fputs(buf, stdout);

      if (pasv_requested)
      {
        cache_append(&cache, buf, n);
      }

      if (expecting_response)
      {
        expecting_response = (memchr(buf, '\n', n) == NULL);
      }

      while (pasv_requested && memchr(cache.buf, '\n', cache.len))
      {
        // puts("Looking for PASV resp code"); /* DEBUG */
        const int res = search_pasv_resp(&cache, &pasv_sock);
        if (res == 0)
        {
          pasv_requested = false;
          cache_full_flush(&cache);
        }
        else if (res < 0)
        {
          pasv_requested = false;
          cache_full_flush(&cache);
          warnx("Could not establish a connection to the passive port given "
                "by the server. If this might be due to port redirection, "
                "please try the command '--force PASV <IP> <PORT>'.");
        }
        else
        {
          cache_line_flush(&cache);
        }
      }
    }

    if (FD_ISSET(stdin_fd, &readfds))
    {
      if (feof(stdin))
      {
        send(sock, "QUIT\r\n", 6, 0);
        goto end;
      }
      if (expecting_response)
      {
        goto after_stdin_block;
      }

      fgets(buf, BUF_SIZE - 1, stdin); /* -1 for \r if needed */
      size_t n = strlen(buf) - 1;

      if (memcmp(buf, "--force PASV", 12) == 0)
      {
        buf[n] = '\0';
        force_pasv(buf + 12, &pasv_sock);
        goto after_stdin_block;
      }

      if (buf[n] == '\n')
      {
        if (n == 1 || buf[n - 1] != '\r')
        {
          buf[n++] = '\r';
          buf[n] = '\n';
        }
      }
      errno = 0;
      if (send(sock, buf, n, 0) < 0)
      {
        warn("Cannot send data to server.");
      }
      else if (buf[n] == '\n')
      {
        expecting_response = true;
      }

      if (memcmp(buf, "PASV", 4) == 0)
      {
        // puts("REQUESTING PASV mode"); /* DEBUG */
        pasv_requested = true;
      }
      else if (memcmp(buf, "QUIT", 4) == 0)
      {
        goto end;
      }
    }
    after_stdin_block:

    for (list_t s = pasv_sock, next = NULL; s != NULL; s = next)
    {
      next = s->next;
      if (FD_ISSET(s->val, &readfds))
      {
        const ssize_t n = recv(s->val, buf, BUF_SIZE - 1, 0);
        if (n <= 0)
        {
          list_remove(&pasv_sock, s);
          close(s->val);
        }
        else
        {
          buf[n] = '\0';
          fputs(buf, stdout);
        }
      }
    }

    max_fd = max(stdin_fd, sock);
    FD_ZERO(&readfds);
    FD_SET(stdin_fd, &readfds);
    FD_SET(sock, &readfds);
    for (list_t s = pasv_sock; s != NULL; s = s->next)
    {
      FD_SET(s->val, &readfds);
      max_fd = max(max_fd, s->val);
    }
  }
  err(EXIT_FAILURE, "An issue happened with the connection");

  end:
  shutdown(sock, SHUT_RDWR);
  close(sock);
  for (list_t s = pasv_sock, next = NULL; s != NULL; s = next)
  {
    next = s->next;
    shutdown(s->val, SHUT_RDWR);
    close(s->val);
    list_remove(&pasv_sock, s);
  }
  return EXIT_SUCCESS;
}