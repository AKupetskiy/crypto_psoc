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
    printf(">\r\n");
}


unsigned calculateSecret(uint8_t *remotePublicKey, uint8_t *localPrivateKey, uint8_t *secret) {
    printf("\r\n------------------------- calculating shared secret ------------------------- \r\n");
    const struct uECC_Curve_t * curve = uECC_secp256r1();
    
    uint8_t uncompressedRemotePubKey[64] = {0};
    uECC_decompress(remotePublicKey,uncompressedRemotePubKey,curve);
    
    printf("\r\nuncompressed Private key = ");
    vli_print(uncompressedRemotePubKey, 64);
    
    printf("\r\nlocal Private key = ");
    vli_print(localPrivateKey, 32);
    
    if (!uECC_shared_secret(uncompressedRemotePubKey, localPrivateKey, secret, curve)) {
        return 0;
    }
    
    printf("\r\n------------------------- SUCCESS!!!! ------------------------- \r\n");
    
    //#warning DEBUG!!!!!!!
    //uint8_t *secret1 = (uint8_t *)"\x61\xf3\xd9\xdd\xe5\x90\x9b\x35\x92\x88\x39\x39\xfd\x07\xf2\x25\xd3\x0a\x0f\xfe\x7b\x52\x7e\x35\xc4\xbe\xe2\xd4\x10\x65\x81\xfa";
    //memcpy(secret,secret1,32);
    
    printf("\r\nsecret = ");
    vli_print(secret, 32);
    
    return 1;
}


unsigned generateKeyPair(uint8_t *compressedPubKey, uint8_t *privateKey) {
    printf("\r\n------------------------- generating key pair ------------------------- \r\n");
    const struct uECC_Curve_t * curve = uECC_secp256r1();
    
    uint8_t uncompressedLocalPubKey[64] = {0};
    if (!uECC_make_key(uncompressedLocalPubKey, privateKey, curve)) {
        return 0;
    }
    
    //DEBUG ONLY - BEGIN
    //privateKey = (uint8_t *)"\xd5\x5b\x1d\x5a\x3c\x55\xe4\x76\xad\xca\x88\xa9\x19\x2a\xb1\x63\x12\x4a\x76\x1d\x30\xbe\xbb\x5e\xc4\x17\x46\x2e\xa1\xc1\x97\x50";
    //compressedPubKey = (uint8_t *)"\x03\xc2\x8f\xc9\xcf\xb2\x15\x59\xcc\xdf\x73\x4d\xda\xc4\x79\x40\xdc\x52\x91\xfd\x6d\x0d\x87\x8c\x7d\xa1\xb7\x76\x7b\xbc\x0c\x8b\xe4";
    // END
    
    printf("\r\nlocal Private key = ");
    vli_print(privateKey, 32);
    
    printf("\r\nlocal public key = ");
    vli_print(uncompressedLocalPubKey, 64);
    
    uECC_compress(uncompressedLocalPubKey,compressedPubKey,curve);
    
    printf("\r\ncompressed local public key = ");
    vli_print(compressedPubKey, 33);
    
    printf("\r\n-------------------------end generating key pair ------------------------- \r\n");
    return 1;
}

unsigned verifySignature(uint8_t *remotePublicKey, uint8_t *signature) {
    printf("\r\n------------------------- verifying signature ------------------------- \r\n");
    const struct uECC_Curve_t * curve = uECC_secp256r1();
    
    printf("\r\ncompressed remote public key = ");
    vli_print(remotePublicKey, 33);
    
    uint8_t uncompressedRemotePubKey[64] = {0};
    uECC_decompress(remotePublicKey,uncompressedRemotePubKey,curve);
    
    printf("\r\nuncompressed remote public key = ");
    vli_print(uncompressedRemotePubKey, 64);
    
    uint8_t pubKeyHash[32] = {0};
    sha256_t hash;
    sha256_init(&hash);
    sha256_update(&hash, uncompressedRemotePubKey, 64);
    sha256_final(&hash, pubKeyHash);
    
    printf("\r\nremote public key hash = ");
    vli_print(pubKeyHash,32);
    
    printf("\r\nremote signature = ");
    vli_print(signature,64);
    
    unsigned value = uECC_verify(uncompressedRemotePubKey,pubKeyHash,32,signature,curve);
    
    printf("\r\n-------------------------end verifying signature ------------------------- \r\n");
    return value;
}

unsigned createSignature(uint8_t *localPrivateKey, uint8_t *localPublicKey, uint8_t *signature) {
    printf("\r\n------------------------- creating signature ------------------------- \r\n");
    const struct uECC_Curve_t * curve = uECC_secp256r1();

    printf("\r\ncompressed local public key = ");
    vli_print(localPublicKey, 33);
    
    uint8_t pubKeyHash[32] = {0};
    sha256_t hash;
    sha256_init(&hash);
    sha256_update(&hash, localPublicKey, 33);
    sha256_final(&hash, pubKeyHash);
    
    printf("\r\nlocal public key hash = ");
    vli_print(pubKeyHash,32);

    unsigned value = uECC_sign(localPrivateKey,pubKeyHash,32,signature,curve);
    printf("\r\nlocal signature = ");
    vli_print(signature,64);
    
    printf("\r\n-------------------------end creating signature ------------------------- \r\n");
    
    return value;
}

/* [] END OF FILE */
