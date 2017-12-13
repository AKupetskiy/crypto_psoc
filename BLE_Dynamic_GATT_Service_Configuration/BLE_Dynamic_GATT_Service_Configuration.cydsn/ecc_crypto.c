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

#include "ecc_crypto.h"
#include <project.h>
#include "uECC.h"
#include "sha256.h"


void vli_print(uint8_t *vli, unsigned int size) {
    printf("<");
    for(unsigned i=0; i<size; ++i) {
        printf("%02x", (unsigned)vli[i]);
    }
    printf(">\n");
}


unsigned calculateSecret(uint8_t *remotePublicKey, uint8_t *localPrivateKey, uint8_t *secret) {
    printf("\n------------------------- calculating shared secret ------------------------- \n");
    const struct uECC_Curve_t * curve = uECC_secp256r1();
    
    uint8_t uncompressedRemotePubKey[64] = {0};
    uECC_decompress(remotePublicKey,uncompressedRemotePubKey,curve);
    
    printf("\nuncompressed Private key = ");
    vli_print(uncompressedRemotePubKey, 64);
    
    printf("\nlocal Private key = ");
    vli_print(localPrivateKey, 32);
    
    if (!uECC_shared_secret(uncompressedRemotePubKey, localPrivateKey, secret, curve)) {
        return 0;
    }
    
    printf("\n------------------------- SUCCESS!!!! ------------------------- \n");
    
    printf("\nsecret = ");
    vli_print(secret, 32);
    
    return 1;
}


unsigned generateKeyPair(uint8_t *compressedPubKey, uint8_t *privateKey) {
    printf("\n------------------------- generating key pair ------------------------- \n");
    const struct uECC_Curve_t * curve = uECC_secp256r1();
    
    uint8_t uncompressedLocalPubKey[64] = {0};
    if (!uECC_make_key(uncompressedLocalPubKey, privateKey, curve)) {
        return 0;
    }
    
    printf("\nlocal Private key = ");
    vli_print(privateKey, 32);
    
    printf("\nlocal public key = ");
    vli_print(uncompressedLocalPubKey, 64);
    
    uECC_compress(uncompressedLocalPubKey,compressedPubKey,curve);
    
    printf("\ncompressed local public key = ");
    vli_print(compressedPubKey, 33);
    
    printf("\n-------------------------end generating key pair ------------------------- \n");
    return 1;
}

unsigned verifySignature(uint8_t *remotePublicKey, uint8_t *signature) {
    printf("\n------------------------- verifying signature ------------------------- \n");
    const struct uECC_Curve_t * curve = uECC_secp256r1();
    
    printf("\ncompressed remote public key = ");
    vli_print(remotePublicKey, 33);
    
    uint8_t uncompressedRemotePubKey[64] = {0};
    uECC_decompress(remotePublicKey,uncompressedRemotePubKey,curve);
    
    printf("\nuncompressed remote public key = ");
    vli_print(uncompressedRemotePubKey, 64);
    
    uint8_t pubKeyHash[32] = {0};
    sha256_t hash;
    sha256_init(&hash);
    sha256_update(&hash, uncompressedRemotePubKey, 64);
    sha256_final(&hash, pubKeyHash);
    
    printf("\nremote public key hash = ");
    vli_print(pubKeyHash,32);
    
    printf("\nremote signature = ");
    vli_print(signature,64);
    
    unsigned value = uECC_verify(uncompressedRemotePubKey,pubKeyHash,32,signature,curve);
    
    printf("\n-------------------------end verifying signature ------------------------- \n");
    return value;
}

unsigned createSignature(uint8_t *localPrivateKey, uint8_t *localPublicKey, uint8_t *signature) {
    printf("\n------------------------- creating signature ------------------------- \n");
    const struct uECC_Curve_t * curve = uECC_secp256r1();

    
    printf("\ncompressed local public key = ");
    vli_print(localPublicKey, 33);
    
    uint8_t pubKeyHash[32] = {0};
    sha256_t hash;
    sha256_init(&hash);
    sha256_update(&hash, localPublicKey, 33);
    sha256_final(&hash, pubKeyHash);
    
    printf("\nlocal public key hash = ");
    vli_print(pubKeyHash,32);

    unsigned value = uECC_sign(localPrivateKey,pubKeyHash,32,signature,curve);
    
    printf("\nlocal signature = ");
    vli_print(signature,64);
    
    printf("\n-------------------------end creating signature ------------------------- \n");
    
    return value;
}

/* [] END OF FILE */
