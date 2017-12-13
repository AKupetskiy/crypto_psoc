/* ========================================
 *
 * Copyright YOUR COMPANY, THE YEAR
 * All Rights Reserved
 * UNPUBLISHED, LICENSED SOFTWARE.
 *
 * CONFIDENTIAL AND PROPRIETARY INFORMATION
 * WHICH IS THE PROPERTY OF your company.
 *
 * ========================================
*/

#ifndef _ECC_CRYPTO_H_
#define _ECC_CRYPTO_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
    
void vli_print(uint8_t *vli, unsigned int size);
void testSign();

/*
 pub key should be 33 bytes long,
 priv key - 32 bytes

 IMPORTANT! should be inicialized before passing to method!
*/
unsigned generateKeyPair(uint8_t *compressedPubKey, uint8_t *privateKey);

/*
 pub key should be 33 bytes long,
 signature - 64 bytes,

 IMPORTANT! should be inicialized before passing to method!
*/
unsigned verifySignature(uint8_t *remotePublicKey, uint8_t *signature);

/*
 priv key - 32 bytes,
 pub key - 33 bytes,
 signature - 64 bytes

 IMPORTANT! should be inicialized before passing to method!
*/
unsigned createSignature(uint8_t *localPrivateKey, uint8_t *localPublicKey, uint8_t *signature);

/*
 pub key should be 33 bytes long,
 priv key - 32 bytes,
 signature - 32 bytes

 IMPORTANT! should be inicialized before passing to method!
*/
unsigned calculateSecret(uint8_t *remotePublicKey, uint8_t *localPrivateKey, uint8_t *secret);

#endif

/* [] END OF FILE */
