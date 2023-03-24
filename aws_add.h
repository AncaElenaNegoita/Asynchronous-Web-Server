#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libaio.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "http-parser/http_parser.h"

#define ECHO_LISTEN_PORT		42424

#define ERROR_MSG                                                              \
	"HTTP/1.1 404 Not Found\r\n"                                           \
	"Date: Mon, 30 May 2022 16:00:00 GMT\r\n"                              \
	"Server: Neard/9.9.9\r\n"                                              \
	"Last-Modified: Mon, 1 May 2022 15:00:00 GMT\r\n"                      \
	"Accept-Ranges: bytes\r\n"                                             \
	"Content-Length: 0\r\n"                                                \
	"Vary: Accept-Encoding\r\n"                                            \
	"Connection: close\r\n"                                                \
	"Content-Type: text/html\r\n"                                          \
	"\r\n"

#define OK_MSG                                                                 \
	"HTTP/1.1 200 OK\r\n"                                                  \
	"Date: Mon, 30 May 2022 16:00:00 GMT\r\n"                              \
	"Server: Neard/9.9.9\r\n"                                              \
	"Last-Modified: 1 May 2022 15:00:00 GMT\r\n"                           \
	"Accept-Ranges: bytes\r\n"                                             \
	"Content-Length: %ld\r\n"                                              \
	"Vary: Accept-Encoding\r\n"                                            \
	"Connection: close\r\n"                                                \
	"Content-Type: text/html\r\n"                                          \
	"\r\n"

/* server socket file descriptor */
static int listenfd;

/* epoll file descriptor */
static int epollfd;

/* path of a request */
static char request_path[BUFSIZ];

enum connection_state {
	STATE_INIT,
	STATE_RECEIVING_DATA,
	STATE_DATA_RECEIVED,
	STATE_SENDING_DATA,
	STATE_DATA_SENT,
	STATE_COPYING_FILE,
	STATE_SENDING_FILE,
	STATE_FILE_SENT,
	STATE_CONNECTION_CLOSED
};

enum file_type { STATIC_FILE, DYNAMIC_FILE, NO_FILE };

/* structure acting as a connection handler */
struct connection {
	int sockfd;
	int filefd;
	int efd;
	off_t offset;
	off_t size;

	/* buffers used for receiving messages and then echoing them back */
	char recv_buffer[BUFSIZ];
	size_t recv_len;
	char send_buffer[BUFSIZ];
	char *send_ptr;
	size_t send_len;

	enum connection_state state;
	enum file_type type;

	struct iocb *iocb;
	struct iocb **piocb;
	io_context_t ctx;
};

int request_path_cb(http_parser *p, const char *buf, size_t len);

static http_parser_settings settings_null = {
						 .on_message_begin = 0,
					     .on_header_field = 0,
					     .on_header_value = 0,
					     .on_path = request_path_cb,
					     .on_url = 0,
					     .on_fragment = 0,
					     .on_query_string = 0,
					     .on_body = 0,
					     .on_headers_complete = 0,
					     .on_message_complete = 0};
