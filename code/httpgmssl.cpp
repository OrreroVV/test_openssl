#include "httpgmssl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <iostream>

#define HOST "www.baidu.com"
#define PORT 443

void handle_openssl_error() {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

void ssl_send_data_request(std::string url, std::string cookie, HttpType httpType, std::string post_data, std::string* res) {
    SSL_CTX *ctx;
    SSL *ssl;
    int server;
    struct sockaddr_in addr;

    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD *method = SSLv23_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        std::cerr << "ssl_ctx_new failed" << std::endl;
        handle_openssl_error();
    }

    // Create a new SSL connection
    ssl = SSL_new(ctx);
    if (!ssl) {
        std::cerr << "SSL_new failed" << std::endl;
        handle_openssl_error();
    }

    // Create a socket
    server = socket(AF_INET, SOCK_STREAM, 0);
    if (server < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Set up the server address
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, HOST, &addr.sin_addr) <= 0) {
        perror("Invalid address");
        exit(EXIT_FAILURE);
    }

    // Connect to the server
    if (connect(server, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    // Bind the SSL object to the socket
    SSL_set_fd(ssl, server);

    // Establish the SSL/TLS connection
    if (SSL_connect(ssl) <= 0) {
        handle_openssl_error();
    }

    // Data to send
    const char *data = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    int bytes_sent = SSL_write(ssl, data, strlen(data));
    if (bytes_sent < 0) {
        handle_openssl_error();
    }

    printf("Sent %d bytes.\n", bytes_sent);

    // Clean up and close the connection
    SSL_shutdown(ssl);
    close(server);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    ERR_free_strings();

}