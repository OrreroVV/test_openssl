#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#include <unistd.h>
#include <cstring>
#include <arpa/inet.h>

#define PORT 4433

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX* create_context() {
    const SSL_METHOD* method;
    SSL_CTX* ctx;

    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX* ctx) {
    SSL_CTX_set_ecdh_auto(ctx, 1);

    // 服务器签名证书和私钥
    if (SSL_CTX_use_certificate_file(ctx, "/home/hzh/workspace/test_openssl/crt/server_sign.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "/home/hzh/workspace/test_openssl/crt/server_sign.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // // 服务器加密证书
    // if (SSL_CTX_use_certificate_chain_file(ctx, "/home/hzh/workspace/test_openssl/crt/server_encrypt.crt") <= 0) {
    //     ERR_print_errors_fp(stderr);
    //     exit(EXIT_FAILURE);
    // }

    // 加载 CA 证书
    if (SSL_CTX_load_verify_locations(ctx, "/home/hzh/workspace/test_openssl/crt/ca.crt", NULL) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    // 客户端未验证证书，也不会失败
    // SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER , NULL);
    SSL_CTX_set_verify_depth(ctx, 1);
}

int main() {
    int sock;
    struct sockaddr_in addr;

    init_openssl();
    SSL_CTX* ctx = create_context();
    configure_context(ctx);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    // 设置端口重用选项
    int opt = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);


    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(sock, 1) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    while (1) {
        struct sockaddr_in addr;
        uint len = sizeof(addr);
        int client = accept(sock, (struct sockaddr*)&addr, &len);

        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            const char reply[] = "Hello, client!";
            SSL_write(ssl, reply, strlen(reply));
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);
    }

    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
}
