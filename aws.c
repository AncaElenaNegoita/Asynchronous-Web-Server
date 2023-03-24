#include "aws.h"
#include "aws_add.h"
#include "debug.h"
#include "http-parser/http_parser.h"
#include "sock_util.h"
#include "util.h"
#include "w_epoll.h"

int request_path_cb(http_parser *p, const char *buf, size_t len)
{
	strncpy(request_path, ".", BUFSIZ);
	strncat(request_path, buf, len);

	return 0;
}

/*
 * Initialize connection structure on given socket.
 * FROM epoll_echo_server.c
 */

static struct connection *connection_create(int sockfd)
{
	struct connection *conn = malloc(sizeof(*conn));

	DIE(conn == NULL, "malloc");

	conn->sockfd = sockfd;
	memset(conn->recv_buffer, 0, BUFSIZ);
	memset(conn->send_buffer, 0, BUFSIZ);

	return conn;
}

/*
 * Copy receive buffer to send buffer (echo).
 * FROM epoll_echo_server.c
 */

static void connection_copy_buffers(struct connection *conn)
{
	conn->send_len = conn->recv_len;
	memcpy(conn->send_buffer, conn->recv_buffer, conn->send_len);
}

/*
 * Remove connection handler.
 * FROM epoll_echo_server.c
 */

static void connection_remove(struct connection *conn)
{
	close(conn->sockfd);
	conn->state = STATE_CONNECTION_CLOSED;
	free(conn);
}

/*
 * Handle a new connection request on the server socket.
 * FROM epoll_echo_server.c and calling the function fcntl to make it nonblock
 */

static void handle_new_connection(void)
{
	static int sockfd;
	socklen_t addrlen = sizeof(struct sockaddr_in);
	struct sockaddr_in addr;
	struct connection *conn;
	int rc;

	/* accept new connection */
	sockfd = accept(listenfd, (SSA *)&addr, &addrlen);
	DIE(sockfd < 0, "accept");

	fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL, 0) | O_NONBLOCK);

	dlog(LOG_ERR, "Accepted connection from: %s:%d\n",
	     inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

	/* instantiate new connection handler */
	conn = connection_create(sockfd);

	/* add socket to epoll */
	rc = w_epoll_add_ptr_in(epollfd, sockfd, conn);
	DIE(rc < 0, "w_epoll_add_in");
}

/*
 * Receive message on socket.
 * Store message in recv_buffer in struct connection.
 * FROM epoll_echo_server.c, but implementing the verification of using the
 * non blocking operations on sockets
 */

static enum connection_state receive_message(struct connection *conn)
{
	ssize_t bytes_received;
	int rc;
	char abuffer[64];

	rc = get_peer_address(conn->sockfd, abuffer, 64);
	if (rc < 0) {
		ERR("get_peer_address");
		goto remove_connection;
	}
	/* Necessary because the operations on socket are non-blocking.
	 * It reads BUFSIZ - conn->recv_len bytes and returns the number read(received). */
	bytes_received = recv(conn->sockfd, conn->recv_buffer + conn->recv_len, BUFSIZ - conn->recv_len, 0);
	if (bytes_received < 0) {
		/* Error in communication. */
		dlog(LOG_ERR, "Error in communication from: %s\n", abuffer);
		goto remove_connection;
	}
	if (bytes_received == 0) {
		/* Connection closed. */
		dlog(LOG_INFO, "Connection closed from: %s\n", abuffer);
		goto remove_connection;
	}

	conn->recv_len += bytes_received;
	if (strncmp(conn->recv_buffer + conn->recv_len - 4, "\r\n\r\n", 4) != 0) {
		conn->state = STATE_RECEIVING_DATA;
		return STATE_RECEIVING_DATA;
	}

	dlog(LOG_DEBUG, "Received message from: %s\n", abuffer);

	printf("--\n%s--\n", conn->recv_buffer);

	conn->state = STATE_DATA_RECEIVED;

	return STATE_DATA_RECEIVED;

remove_connection:
	rc = w_epoll_remove_ptr(epollfd, conn->sockfd, conn);
	DIE(rc < 0, "w_epoll_remove_ptr");

	/* remove current connection */
	connection_remove(conn);

	return STATE_CONNECTION_CLOSED;
}

/*
 * Send message on socket.
 * Store message in send_buffer in struct connection.
 * FROM epoll_echo_server.c and adding the necessary functionalities in order to
 * respect that the operation on sockets are non blocking and the notification won't
 * be removed.
 */

static enum connection_state send_message(struct connection *conn)
{
	ssize_t bytes_sent;
	int rc;
	char abuffer[64];

	rc = get_peer_address(conn->sockfd, abuffer, 64);
	if (rc < 0) {
		ERR("get_peer_address");
		goto remove_connection;
	}

	bytes_sent = send(conn->sockfd, conn->send_ptr, conn->send_len, 0);
	if (bytes_sent < 0) {
		/* Error in communication. */
		dlog(LOG_ERR, "Error in communication to %s\n", abuffer);
		goto remove_connection;
	}
	if (bytes_sent == 0) {
		/* Connection closed. */
		dlog(LOG_INFO, "Connection closed to %s\n", abuffer);
		goto remove_connection;
	}

	/* The pointer now goes over the number of bytes sent. */
	conn->send_ptr += bytes_sent;
	/* The length shortens because a number of bytes is sent. */
	conn->send_len -= bytes_sent;

	/* If it still has some bytes left, it stays in the sending state. */
	if (conn->send_len != 0) {
		conn->state = STATE_SENDING_DATA;
		return STATE_SENDING_DATA;
	}

	dlog(LOG_DEBUG, "Sending message to %s\n", abuffer);

	dlog(LOG_DEBUG, "--\n%s--\n", conn->send_buffer);

	conn->state = STATE_DATA_SENT;

	return STATE_DATA_SENT;

remove_connection:
	rc = w_epoll_remove_ptr(epollfd, conn->sockfd, conn);
	DIE(rc < 0, "w_epoll_remove_ptr");

	/* remove current connection */
	connection_remove(conn);

	return STATE_CONNECTION_CLOSED;
}

/* Sending a static file synchronous. */
static void static_file_send(struct connection *conn)
{
	/* Change the state to copying(sending the file). */
	conn->state = STATE_COPYING_FILE;

	/* Generate the number of bytes sent by the file. */
	ssize_t bytes_sent = sendfile(conn->sockfd, conn->filefd, &conn->offset,
				      conn->size - conn->offset);
	/* If the function returns -1, then there is a problem in the communication,
	 * and the buffer remains empty. */
	if (bytes_sent == -1) {
		char buf[64];
		dlog(LOG_ERR, "Error in communication to %s\n", buf);
		connection_remove(conn);
		return;
	}

	/* If the size is equal to the number of bytes, then the whole static file was
	 * sent and the operation finished. All the connection's atributes are reseted and
	 * the connection closes. */
	if (conn->size == conn->offset) {
		close(conn->filefd);
		conn->state = STATE_FILE_SENT;
	}
}

/* Sending a dynamic file asynchronous. */
static void async_file_send(struct connection *conn) {
    int rc;
    struct io_event event;

    rc = io_getevents(conn->ctx, 1, 1, &event, NULL);
    DIE(rc < 0, "io_getevents");

    switch(conn->state)
    {
        case STATE_COPYING_FILE:
            /* Increase the offset by the number of bytes read. */
            conn->offset += event.res;

            /* Prepare for sending the data. */
            io_prep_pwrite(conn->iocb, conn->sockfd, conn->send_buffer, event.res, 0);
            *conn->piocb = conn->iocb;
            io_set_eventfd(conn->iocb, conn->efd);

            /* Update the state. */
            conn->state = STATE_SENDING_FILE;
            break;
        case STATE_SENDING_FILE:
            /* Check if all the data has been sent. */
            if (conn->offset == conn->size) {
                conn->state = STATE_FILE_SENT;

                /* Remove the event from epoll. */
                rc = w_epoll_remove_ptr(epollfd, conn->efd, conn);
                DIE(rc < 0, "w_epoll_remove_ptr");

                /* Add socket to epoll. */
                rc = w_epoll_add_ptr_in(epollfd, conn->sockfd, conn);
                DIE(rc < 0, "w_epoll_add_in");

                /* Clean it all up. */
                io_destroy(conn->ctx);
                close(conn->efd);

                free(conn->iocb);
                free(conn->piocb);
                return;
            }

            /* Prepare for reading more data */
			int dif = conn->size - conn->offset;
			if (dif > BUFSIZ) {
            io_prep_pread(conn->iocb, conn->filefd, conn->send_buffer,
                    	  BUFSIZ, conn->offset);
			} else {
			io_prep_pread(conn->iocb, conn->filefd, conn->send_buffer,
                 		  dif, conn->offset);
			}
            *conn->piocb = conn->iocb;
            io_set_eventfd(conn->iocb, conn->efd);

            /* Update the state. */
            conn->state = STATE_COPYING_FILE;
            break;
    }

    /* Submit the request */
    rc = io_submit(conn->ctx, 1, conn->piocb);
    DIE(rc < 0, "io_submit");
}

void handle_no_file(struct connection *conn) {
    int rc = w_epoll_update_ptr_in(epollfd, conn->sockfd, conn);
    DIE(rc < 0, "w_epoll_update_ptr_in");
}

void handle_static_file(struct connection *conn) {
    static_file_send(conn);
    if (conn->state != STATE_FILE_SENT) {
        return;
    }

    int rc = w_epoll_update_ptr_in(epollfd, conn->sockfd, conn);
    DIE(rc < 0, "w_epoll_update_ptr_in");
}

void handle_dynamic_file(struct connection *conn) {
    conn->state = STATE_COPYING_FILE;
    int rc = w_epoll_remove_ptr(epollfd, conn->sockfd, conn);
    DIE(rc < 0, "w_epoll_remove_ptr");

    conn->iocb = (struct iocb *)malloc(sizeof(*conn->iocb));
    DIE(conn->iocb == NULL, "malloc");

    conn->piocb = (struct iocb **)malloc(sizeof(*conn->piocb));
    DIE(conn->piocb == NULL, "malloc");

    conn->efd = eventfd(0, 0);
    DIE(conn->efd < 0, "eventfd");

    rc = io_setup(1, &conn->ctx);
    DIE(rc < 0, "io_setup");

    rc = w_epoll_add_ptr_in(epollfd, conn->efd, conn);
    DIE(rc < 0, "w_epoll_add_in");

    int dif = conn->size - conn->offset;
    if (dif > BUFSIZ) {
        io_prep_pread(conn->iocb, conn->filefd, conn->send_buffer, BUFSIZ, conn->offset);
    } else {
        io_prep_pread(conn->iocb, conn->filefd, conn->send_buffer, dif, conn->offset);
    }
    *conn->piocb = conn->iocb;
    io_set_eventfd(conn->iocb, conn->efd);

    rc = io_submit(conn->ctx, 1, conn->piocb);
    DIE(rc < 0, "io_submit");
}

/*
 * Handle a client reply on a client connection.
 */
static void handle_client_reply(struct connection *conn)
{
	int rc;
    enum connection_state ret_state;

    /* Check if data is received or still sending. */
    if (conn->state == STATE_DATA_RECEIVED || conn->state == STATE_SENDING_DATA) {
        if (send_message(conn) != STATE_DATA_SENT)
            return;
    }

	switch (conn->type) {
		case NO_FILE:
			/* Handle no file case. */
			handle_no_file(conn);
			return;
		case STATIC_FILE:
			handle_static_file(conn);
			return;
		case DYNAMIC_FILE:
			handle_dynamic_file(conn);
			return;
	}
}

/*
 * Handle a client request on a client connection.
 */
static void handle_client_request(struct connection *conn)
{
	int rc;
	enum connection_state ret_state;
	http_parser h_parser;
	struct stat statbuf;

	ret_state = receive_message(conn);
	if (ret_state != STATE_DATA_RECEIVED)
		return;

	/* Add socket to epoll for out events. */
	rc = w_epoll_update_ptr_out(epollfd, conn->sockfd, conn);
	DIE(rc < 0, "w_epoll_update_ptr_out");

	/* Parse HTTP. */
	http_parser_init(&h_parser, HTTP_REQUEST);

	size_t bytes_parsed = http_parser_execute(&h_parser, &settings_null, conn->recv_buffer,
											  conn->recv_len);
	dlog(LOG_DEBUG, "Parsed HTTP request (bytes: %lu), path: %s\n", bytes_parsed, request_path);

	conn->send_ptr = conn->send_buffer;

	int static_file = strncmp(request_path, AWS_ABS_STATIC_FOLDER, strlen(AWS_ABS_STATIC_FOLDER)); 
	int dynamic_file = strncmp(request_path, AWS_ABS_DYNAMIC_FOLDER, strlen(AWS_ABS_DYNAMIC_FOLDER));
	if (static_file == 0) {
			conn->type = STATIC_FILE;
			goto solve_the_same;
	} else if (dynamic_file == 0) {
			conn->type = DYNAMIC_FILE;
			goto solve_the_same;
	} else {
		goto no_file;
	}

solve_the_same:
	dlog(LOG_DEBUG, "%s is of type %d\n", request_path, conn->type);
	conn->filefd = open(request_path, O_RDONLY);
	if (conn->filefd == -1)
		goto no_file;
	fstat(conn->filefd, &statbuf);
	conn->size = statbuf.st_size;
	conn->offset = 0;
	conn->send_len = sprintf(conn->send_buffer, OK_MSG, statbuf.st_size);
	return;

no_file:
	conn->type = NO_FILE;
	strncat(conn->send_buffer, ERROR_MSG, BUFSIZ);
	conn->send_len = sizeof(ERROR_MSG);
	conn->filefd = -1;
	return;
}

int main(void)
{
	int rc;

	/* Initialise multiplexing. */
	epollfd = w_epoll_create();
	DIE(epollfd < 0, "w_epoll_create");

	/* Create server socket .*/
	listenfd = tcp_create_listener(AWS_LISTEN_PORT, DEFAULT_LISTEN_BACKLOG);
	DIE(listenfd < 0, "tcp_create_listener");

	/* Add event. */
	rc = w_epoll_add_fd_in(epollfd, listenfd);
	DIE(rc < 0, "w_epoll_add_fd_in");

	dlog(LOG_INFO, "Server waiting for connections on port %d\n",
	     AWS_LISTEN_PORT);

	/* Server main loop. */
	while (1) {
		struct epoll_event rev;

		/* Wait for events. */
		rc = w_epoll_wait_infinite(epollfd, &rev);
		DIE(rc < 0, "w_epoll_wait_infinite");

		/*
		 * switch event types; consider
		 *   - new connection requests (on server socket)
		 *   - socket communication (on connection sockets)
		 */

		/* The server receives a socket connection. */
		if (rev.data.fd == listenfd) {
			dlog(LOG_DEBUG, "New connection\n");
			if (rev.events & EPOLLIN)
				/* Receive a new connection. Client made a request to the server
				 * through socket.*/
				handle_new_connection();
		} else {
			/* Pointer to the connexion bits. */
			struct connection *conn = (struct connection *)rev.data.ptr;
			/* Socket communication (on connection sockets). */
			if (conn->type == DYNAMIC_FILE &&
			    (conn->state == STATE_COPYING_FILE || conn->state == STATE_SENDING_FILE)) {
				async_file_send(conn);
			} else if (rev.events & EPOLLIN) {
				dlog(LOG_DEBUG, "New message\n");
				/* Receives a message and puts the event in front, copying the
				 * connection buffer. */
				handle_client_request(conn);
			} else if ((rev.events & EPOLLOUT)) {
				dlog(LOG_DEBUG, "Ready to send message\n");
				/* The client sends a message to the socket. */
				handle_client_reply(conn);
			}
		}
	}

	return 0;
}
