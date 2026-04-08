#include "../include/crypto.h"
#include "../include/net.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#define NONCE_LEN       crypto_aead_xchacha20poly1305_ietf_NPUBBYTES    /* 24 */
#define MAC_LEN         crypto_aead_xchacha20poly1305_ietf_ABYTES       /* 16 */

bool crypto_do_key_exchange(int32_t fd, Session *s)
{
        uint8_t my_pub[crypto_kx_PUBLICKEYBYTES];
        uint8_t my_sec[crypto_kx_SECRETKEYBYTES];
        crypto_kx_keypair(my_pub, my_sec);
}
