#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>
#include <cstring>

#define SERVER_IP "127.0.0.1"
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

    method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_3);


     // 获取并检查当前禁用的选项
    long options = SSL_CTX_get_options(ctx);

    std::cout << "Enabled TLS versions:" << std::endl;

    if (!(options & SSL_OP_NO_TLSv1_2)) {
        std::cout << "TLS 1.2 is enabled." << std::endl;
    } else {
        std::cout << "TLS 1.2 is disabled." << std::endl;
    }

    if (!(options & SSL_OP_NO_TLSv1_3)) {
        std::cout << "TLS 1.3 is enabled." << std::endl;
    } else {
        std::cout << "TLS 1.3 is disabled." << std::endl;
    }

    return ctx;
}

void configure_context(SSL_CTX* ctx) {
    // 客户端签名证书和私钥
    if (SSL_CTX_use_certificate_file(ctx, "/home/hzh/workspace/test_openssl/crt/client_sign.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "/home/hzh/workspace/test_openssl/crt/client_sign.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // // 客户端加密证书
    // if (SSL_CTX_use_certificate_chain_file(ctx, "/home/hzh/workspace/test_openssl/crt/client_encrypt.crt") <= 0) {
    //     ERR_print_errors_fp(stderr);
    //     exit(EXIT_FAILURE);
    // }

    // // 加载 CA 证书
    // if (SSL_CTX_load_verify_locations(ctx, "/home/hzh/workspace/test_openssl/crt/ca.crt", NULL) <= 0) {
    //     ERR_print_errors_fp(stderr);
    //     exit(EXIT_FAILURE);
    // }

    // SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    // SSL_CTX_set_verify_depth(ctx, 1);
}

int main() {
    int sock;
    struct sockaddr_in server_addr;

    init_openssl();
    SSL_CTX* ctx = create_context();
    configure_context(ctx);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Unable to connect");
        exit(EXIT_FAILURE);
    }

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    // SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256");


    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        const char* msg = "Hello, Server!";
        SSL_write(ssl, msg, strlen(msg));

        char buffer[1024];
        int bytes = SSL_read(ssl, buffer, sizeof(buffer));
        buffer[bytes] = 0;
         std::cout << "Received: " << buffer << std::endl;
    }

    X509 *cert;
    EVP_PKEY *pubkey;


    // 获取服务器的证书
    cert = SSL_get_peer_certificate(ssl);
    if (cert == NULL) {
        printf("No certificate received from the server.\n");
        SSL_CTX_free(ctx);
        SSL_shutdown(ssl);
        return -1;
    }

    // 从证书中提取公钥
    pubkey = X509_get_pubkey(cert);
    if (pubkey == NULL) {
        printf("Failed to extract public key from certificate.\n");
    } else {
        // 你可以使用 pubkey 进行签名验证或加密操作
        FILE *pubkey_file = fopen("../temp/public_key.pem", "wb");
        PEM_write_PUBKEY(pubkey_file, pubkey);
        fclose(pubkey_file);
        printf("Successfully extracted public key from certificate.\n");
    }
 // 释放证书对象
    X509_free(cert);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
}

