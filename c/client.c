/* This program is a simple OpenSSL HTTP requestor
 * to help verify PQC endpoints.  Specifically, it
 * lets you specify the keygroups to use.
 *
 * Originally written by Jan Schaumann
 * <jschauma@netmeister.org> in June 2025.
 *
 * This code is in the public domain.
 *
 * See this link for more information:
 * https://www.netmeister.org/blog/pqc-pocs.html
 */

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <sys/param.h>

#include <err.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>

extern char *__progname;

#define DEFAULT_GROUPS "X25519:*X25519MLKEM768"

char HOST[MAXHOSTNAMELEN + 1] = { 0 };
/* Max port is 65535 + NULL */
char PORT[5 + 1] = "443";

int
makeSocket() {
	struct addrinfo hints, *res, *p;
	int sock = -1;
	int status;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((status = getaddrinfo(HOST, PORT, &hints, &res)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
		return -1;
	}

	for (p = res; p != NULL; p = p->ai_next) {
		sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (sock < 0) {
			continue;
		}

		if (connect(sock, p->ai_addr, p->ai_addrlen) == 0) {
			break;
		}

		close(sock);
		sock = -1;
	}

	freeaddrinfo(res);

	if (sock == -1) {
		perror("Unable to connect");
	}

	return sock;
}

void
usage() {
	(void)fprintf(stderr,
"Usage: %s [-h] [-g groups] [-p port] -s server\n"
"    -h         print this help and exit\n"
"    -g groups  specify keygroups (default: %s)\n"
"    -s server  connect to this server\n"
"    -p port    use this port (default: %s)\n",
__progname, DEFAULT_GROUPS, PORT);
}

int
main(int argc, char **argv) {
	int ch, n;
	char *groups = DEFAULT_GROUPS;

	while ((ch = getopt(argc, argv, "g:hs:p:")) != -1) {
		switch(ch) {
		case 'g':
			if ((groups = strdup(optarg)) == NULL) {
				err(EXIT_FAILURE, "strdup");
				/* NOTREACHED */
			}
			break;
		case 'h':
			usage();
			break;
		case 's':
			snprintf(HOST, sizeof(HOST), optarg);
			break;
		case 'p':
		       	n = atoi(optarg);
			if ((n <= 0) || (n > 65535)) {
				errx(EXIT_FAILURE, "port must be between 0 and 65535");
				/* NOTREACHED */
			}
			snprintf(PORT, sizeof(PORT), optarg);
			break;
		default:
			usage();
			exit(EXIT_FAILURE);
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (argc > 0) {
		usage();
		exit(EXIT_FAILURE);
		/* NOTREACHED */
	}

	if (strlen(HOST) < 1) {
		usage();
		exit(EXIT_FAILURE);
		/* NOTREACHED */
	}

	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();

	SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
	if (!ctx) {
		ERR_print_errors_fp(stderr);
		return EXIT_FAILURE;
	}

	// Set key exchange groups
	if (SSL_CTX_set1_groups_list(ctx, groups) != 1) {
		fprintf(stderr, "Failed to set groups list\n");
		ERR_print_errors_fp(stderr);
		SSL_CTX_free(ctx);
		return EXIT_FAILURE;
	}

	SSL *ssl = SSL_new(ctx);
	int server = makeSocket();
	if (server < 0) {
		SSL_free(ssl);
		SSL_CTX_free(ctx);
		return EXIT_FAILURE;
	}

	SSL_set_fd(ssl, server);

	if (SSL_connect(ssl) != 1) {
		fprintf(stderr, "TLS handshake failed\n");
		ERR_print_errors_fp(stderr);
	} else {
		char req[BUFSIZ] = { 0 };
		snprintf(req, BUFSIZ, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", HOST);
		SSL_write(ssl, req, strlen(req));

		char buffer[BUFSIZ] = { 0 };
		int bytes;
		while ((bytes = SSL_read(ssl, buffer, sizeof(buffer)-1)) > 0) {
			buffer[bytes] = 0;
			printf("%s", buffer);
		}
	}

	SSL_free(ssl);
	close(server);
	SSL_CTX_free(ctx);
	EVP_cleanup();

	return 0;
}
