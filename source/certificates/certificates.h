#ifndef CERTIFICATES_H_
#define CERTIFICATES_H_

#include <stdint.h>

/**
 * 
*/
void certificates_get_root_cert(const uint8_t **cert, uint32_t *len);

/**
 * 
*/
void certificates_get_server_cert(const uint8_t **cert, uint32_t *len);

/**
 * 
*/
void certificates_get_server_key(const uint8_t **key, uint32_t *len);

#endif