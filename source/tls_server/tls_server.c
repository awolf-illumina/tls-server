
/* the usual suspects */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "tls_server.h"
#include "string.h"
#include "lwip/opt.h"
#include "lwip/init.h"
#include "netif/etharp.h"
#include "lwip/netif.h"
#include "lwip/timeouts.h"
#include "lwip/opt.h"
#include "lwip/api.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"
#include "certs.h"
#include "certificates.h"

/* socket includes */
#include <sys/socket.h>
#include <arpa/inet.h>

/* wolfSSL */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#define DEFAULT_PORT 11111


/* Definitions for tcpTask */
static osThreadId_t _task_handle;
const static osThreadAttr_t _task_attr = {
  .name = "TLS Server",
  .stack_size = 8096 * 4,
  .priority = 1,
};

static void _error_handler()
{
    while (1)
    {
        ;
    }
}

int my_IORecv(WOLFSSL* ssl, char* buff, int sz, void* ctx)
{
    /* By default, ctx will be a pointer to the file descriptor to read from.
     * This can be changed by calling wolfSSL_SetIOReadCtx(). */
    int sockfd = *(int*)ctx;
    int recvd;

    /* Receive message from socket */
    if ((recvd = recv(sockfd, buff, sz, 0)) == -1) {
        /* error encountered. Be responsible and report it in wolfSSL terms */

        printf("IO RECEIVE ERROR: ");
        switch (errno) {
        #if EAGAIN != EWOULDBLOCK
        case EAGAIN: /* EAGAIN == EWOULDBLOCK on some systems, but not others */
        #endif
        case EWOULDBLOCK:
            if (!wolfSSL_dtls(ssl) || wolfSSL_get_using_nonblock(ssl)) {
                printf("would block\n");
                return WOLFSSL_CBIO_ERR_WANT_READ;
            }
            else {
                printf("socket timeout\n");
                return WOLFSSL_CBIO_ERR_TIMEOUT;
            }
        case ECONNRESET:
            printf("connection reset\n");
            return WOLFSSL_CBIO_ERR_CONN_RST;
        case EINTR:
            printf("socket interrupted\n");
            return WOLFSSL_CBIO_ERR_ISR;
        case ECONNREFUSED:
            printf("connection refused\n");
            return WOLFSSL_CBIO_ERR_WANT_READ;
        case ECONNABORTED:
            printf("connection aborted\n");
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        default:
            printf("general error\n");
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
    }
    else if (recvd == 0) {
        printf("Connection closed\n");
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    }

    /* successful receive */
    printf("my_IORecv: received %d bytes from %d\n", sz, sockfd);
    return recvd;
}

int my_IOSend(WOLFSSL* ssl, char* buff, int sz, void* ctx)
{
    /* By default, ctx will be a pointer to the file descriptor to write to.
     * This can be changed by calling wolfSSL_SetIOWriteCtx(). */
    int sockfd = *(int*)ctx;
    int sent;

    /* Receive message from socket */
    if ((sent = send(sockfd, buff, sz, 0)) == -1) {
        /* error encountered. Be responsible and report it in wolfSSL terms */

        printf("IO SEND ERROR: ");
        switch (errno) {
        #if EAGAIN != EWOULDBLOCK
        case EAGAIN: /* EAGAIN == EWOULDBLOCK on some systems, but not others */
        #endif
        case EWOULDBLOCK:
            printf("would block\n");
            return WOLFSSL_CBIO_ERR_WANT_WRITE;
        case ECONNRESET:
            printf("connection reset\n");
            return WOLFSSL_CBIO_ERR_CONN_RST;
        case EINTR:
            printf("socket interrupted\n");
            return WOLFSSL_CBIO_ERR_ISR;
        case EPIPE:
            printf("socket EPIPE\n");
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        default:
            printf("general error\n");
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
    }
    else if (sent == 0) {
        printf("Connection closed\n");
        return 0;
    }

    /* successful send */
    printf("my_IOSend: sent %d bytes to %d\n", sz, sockfd);
    return sent;
}


static int _verify_callback(int x, WOLFSSL_X509_STORE_CTX* ctx)
{
    printf("_verify_callback: error=%d, error_depth=%d, total_certs=%d, domain=%s\n",
            ctx->error, ctx->error_depth, ctx->totalCerts, ctx->domain);
    return 1;
}

/**
 *
 */
static void _run(void *argument)
{
    int                sockfd;
    int                connd;
    struct sockaddr_in servAddr;
    struct sockaddr_in clientAddr;
    socklen_t          size = sizeof(clientAddr);
    char               buff[256];
    size_t             len;
    int                shutdown = 0;
    int                ret;

    /* declare wolfSSL objects */
    WOLFSSL_CTX* ctx;
    WOLFSSL*     ssl;

    /* Initialize wolfSSL */
    wolfSSL_Init();

    wolfSSL_Debugging_ON();

    /* Create a socket that uses an internet IPv4 address,
     * Sets the socket to be stream based (TCP),
     * 0 means choose the default protocol. */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        printf("ERROR: failed to create the socket\n");
        _error_handler();
    }

    /* Create and initialize WOLFSSL_CTX */
    if ((ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method())) == NULL) {
        printf("ERROR: failed to create WOLFSSL_CTX\n");
        _error_handler();
    }

    /* Load root certificates into WOLFSSL_CTX */
    const uint8_t *root_cert = NULL;
    uint32_t root_cer_len = 0u;
    certificates_get_root_cert(&root_cert, &root_cer_len);

    if (wolfSSL_CTX_load_verify_buffer(ctx, (unsigned char *) root_cert, root_cer_len, WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
        printf("ERROR: failed to load verify certificate\n");
        _error_handler();
    }

    /* Load client certificates into WOLFSSL_CTX */
    const uint8_t *server_cert = NULL;
    uint32_t server_cert_len = 0u;
    certificates_get_server_cert(&server_cert, &server_cert_len);

    if (wolfSSL_CTX_use_certificate_buffer(ctx, (unsigned char *) server_cert, server_cert_len, WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
        printf("ERROR: failed to load server certificate\n");
        _error_handler();
    }

    /* Load client keys into WOLFSSL_CTX */    
    const uint8_t *server_key = NULL;
    uint32_t server_key_len = 0u;
    certificates_get_server_key(&server_key, &server_key_len);

    if (wolfSSL_CTX_use_PrivateKey_buffer(ctx, (unsigned char *) server_key, server_key_len, WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
        printf("ERROR: failed to load server key\n");
        _error_handler();
    }

    /* Register callbacks */
    wolfSSL_SetIORecv(ctx, my_IORecv);
    wolfSSL_SetIOSend(ctx, my_IOSend);

    /* Initialize the server address struct with zeros */
    memset(&servAddr, 0, sizeof(servAddr));

    /* Fill in the server address */
    servAddr.sin_family      = AF_INET;             /* using IPv4      */
    servAddr.sin_port        = htons(DEFAULT_PORT); /* on DEFAULT_PORT */
    servAddr.sin_addr.s_addr = INADDR_ANY;          /* from anywhere   */

    /* Bind the server socket to our port */
    if (bind(sockfd, (struct sockaddr*) &servAddr, sizeof(servAddr)) == -1) {
        printf("ERROR: failed to bind\n");
        _error_handler();
    }

    /* Listen for a new connection, allow 5 pending connections */
    if (listen(sockfd, 5) == -1) {
        printf("ERROR: failed to listen\n");
        _error_handler();
    }

    /* Continue to accept clients until shutdown is issued */
    while (!shutdown) {
        printf("Waiting for a connection...\n");

        /* Accept client connections */
        if ((connd = accept(sockfd, (struct sockaddr*)&clientAddr, &size))
            == -1) {
            printf("ERROR: failed to accept the connection\n\n");
            _error_handler();
        }

        /* Create a WOLFSSL object */
        if ((ssl = wolfSSL_new(ctx)) == NULL) {
            printf("ERROR: failed to create WOLFSSL object\n");
            _error_handler();
        }

        wolfSSL_set_verify(ssl, SSL_VERIFY_PEER | WOLFSSL_VERIFY_CLIENT_ONCE, _verify_callback);

        /* Attach wolfSSL to the socket */
        wolfSSL_set_fd(ssl, connd);

        /* Establish TLS connection */
        ret = wolfSSL_accept(ssl);
        if (ret != SSL_SUCCESS) {
            printf("wolfSSL_accept error = %d\n", wolfSSL_get_error(ssl, ret));
            _error_handler();
        }

        printf("Client connected successfully\n");

        /* Read the client data into our buff array */
        memset(buff, 0, sizeof(buff));
        if (wolfSSL_read(ssl, buff, sizeof(buff)-1) == -1) 
        {
            printf("ERROR: failed to read\n");
            _error_handler();
        }

        /* Print to stdout any data the client sends */
        printf("Client: %s\n", buff);

        /* Check for server shutdown command */
        if (strncmp(buff, "shutdown", 8) == 0) {
            printf("Shutdown command issued!\n");
            _error_handler();
        }        

        /* Reply back to the client */
        len = strnlen(buff, sizeof(buff)-1);
        if (wolfSSL_write(ssl, buff, len) != len) {
            printf("ERROR: failed to write\n");
            _error_handler();
        }

        /* Cleanup after this connection */
        wolfSSL_free(ssl);      /* Free the wolfSSL object              */
        close(connd);           /* Close the connection to the client   */
    }

    printf("Shutdown complete\n");

    /* Cleanup and return */
    wolfSSL_CTX_free(ctx);  /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();      /* Cleanup the wolfSSL environment          */
    close(sockfd);          /* Close the socket listening for clients   */

    _error_handler();
}

/**
 *
*/
void tls_server_create(void)
{
  /* creation of tcp task */
  _task_handle = osThreadNew(_run, NULL, &_task_attr);
}
