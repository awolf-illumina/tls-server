#include "certificates.h"
#include "certificates_server_cert.h"
#include "certificates_server_key.h"
#include "certificates_root_cert.h"


const static uint8_t _root_cert[] = ROOT_CERT;
const static uint8_t _server_cert[] = SERVER_CERT;
const static uint8_t _server_key[] = SERVER_KEY;


/**
 * 
*/
void certificates_get_root_cert(const uint8_t **cert, uint32_t *len)
{
    *cert = _root_cert;
    *len = sizeof(_root_cert);
}

/**
 * 
*/
void certificates_get_server_cert(const uint8_t **cert, uint32_t *len)
{
    *cert = _server_cert;
    *len = sizeof(_server_cert);
}

/**
 * 
*/
void certificates_get_server_key(const uint8_t **key, uint32_t *len)
{
    *key = _server_key;
    *len = sizeof(_server_key);
}
