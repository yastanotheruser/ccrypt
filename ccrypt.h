#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

#define BLOCK_SIZE 32
#define BLOCK_BITS (BLOCK_SIZE * 8)
#define CIPHERTEXT_PTABLE_LENGTH (BLOCK_BITS + 8)
#define CIPHERTEXT_HEADER_LENGTH (CIPHERTEXT_PTABLE_LENGTH * 2)
#define CIPHERTEXT_BLOCK_SIZE (BLOCK_SIZE + 2)
#define CIPHERTEXT_PADDING_BYTES 2

typedef struct {
    const uint8_t *key;
    const size_t *text_ptable;
    const size_t *key_ptable;
    int wrote_header;
    uint8_t *plaintext;
    size_t ptsize;
} CCryptCipher;

typedef struct {
    const uint8_t *key;
    int section;
    const size_t *text_rptable;
    const size_t *key_ptable;
    uint8_t *ciphertext;
    size_t ctsize;
} CCryptDecipher;

typedef enum {
    CCRYPT_DECIPHER_NO_ERROR,
    CCRYPT_DECIPHER_INVALID_HEADER,
    CCRYPT_DECIPHER_INVALID_LENGTH,
    CCRYPT_DECIPHER_PADDING_ERROR
} CCryptDecipherResult;

CCryptCipher *CreateCCryptCipher(const uint8_t *key, size_t ksize);
void DestroyCCryptCipher(CCryptCipher *cipher);
uint8_t *UpdateCCryptCipher(
    CCryptCipher *cipher,
    const uint8_t *plaintext,
    size_t ptsize,
    size_t *szptr
);
uint8_t *EndCCryptCipher(
    CCryptCipher *cipher,
    const uint8_t *plaintext,
    size_t ptsize,
    size_t *szptr
);

CCryptDecipher *CreateCCryptDecipher(const uint8_t *key, size_t ksize);
void DestroyCCryptDecipher(CCryptDecipher *decipher);
CCryptDecipherResult UpdateCCryptDecipher(
    CCryptDecipher *decipher,
    const uint8_t *ciphertext,
    size_t ctsize,
    uint8_t **dest_ptr,
    size_t *szptr
);
CCryptDecipherResult EndCCryptDecipher(
    CCryptDecipher *decipher,
    const uint8_t *ciphertext,
    size_t ctsize,
    uint8_t **dest_ptr,
    size_t *szptr,
    uint8_t *padding_ptr
);

#endif
