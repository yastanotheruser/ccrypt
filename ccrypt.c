#include "ccrypt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib/bytes.h"
#include "lib/debug.h"

static const uint8_t *NormalizeKey(const uint8_t *key, size_t ksize) {
    uint8_t *nkey = sfmalloc(sizeof(*nkey) * BLOCK_SIZE);
    size_t blocks = ksize / BLOCK_SIZE;
    if (ksize % BLOCK_SIZE > 0) {
        blocks++;
    } 

    for (int i = 0; i < BLOCK_SIZE; i++) {
        uint8_t kb = 0;
        for (size_t j = 0; j < blocks; j++) {
            size_t bi = j * BLOCK_SIZE + i;
            kb ^= CircularShift(bi < ksize ? key[bi] : 92, j);
        }
        nkey[i] = kb;
    }

    return (const uint8_t*) nkey;
}

static const size_t *CreatePermutationTable() {
    size_t slen = BLOCK_BITS;
    size_t *seq = sfmalloc(sizeof(*seq) * slen);
    size_t *ptable = sfmalloc(sizeof(*ptable) * slen);
    size_t *ptval = ptable;
    for (size_t i = 0; i < slen; i++) {
        seq[i] = i;
    }

    while (slen > 0) {
        size_t index = random_word() % slen;
        size_t val = seq[index];
        *ptval++ = val;
        for (size_t i = index; i < slen; i++) {
            seq[i] = seq[i + 1];
        }
        slen--;
    }

    free(seq);
    return (const size_t*) ptable;
}

static void PutPermutationTable(
    uint8_t **dest_ptr,
    const size_t *ptable,
    const uint8_t *key
) {
    uint8_t *dest = *dest_ptr;
    uint8_t *ckey = sfmalloc(sizeof(*ckey) * BLOCK_SIZE);
    memcpy(ckey, key, BLOCK_SIZE);

    for (size_t i = 0; i < 8; i++) {
        uint8_t nonce = random_word() % 256;
        uint8_t fbit = ckey[0] >> 7;
        size_t ptindex = BLOCK_SIZE * i;
        *dest++ = nonce;
        for (int j = 0; j < BLOCK_SIZE; j++) {
            uint8_t adjbit = j < BLOCK_SIZE - 1 ? ckey[j + 1] >> 7 : fbit;
            ckey[j] ^= nonce++;
            ckey[j] = ((ckey[j] & 127) << 1) | adjbit;
            *dest++ = ptable[ptindex + j] ^ ckey[j];
        }
    }

    *dest_ptr = dest;
    free(ckey);
} 

static uint8_t GetPaddingLengthMask(const uint8_t *key, uint8_t nonce) {
    size_t key_blocks = BLOCK_SIZE / 4;
    uint8_t nmask = nonce;
    uint8_t padding_mask = 0;

    for (size_t i = 0; i < key_blocks; i++) {
        uint8_t j = i * 4;
        uint8_t bit = i % 8;
        uint8_t mbyte = key[j] ^ key[j + 1] ^ key[j + 2] ^ key[j + 3];
        nmask = CircularShift(nmask, 1) + 1;
        mbyte ^= nmask;
        padding_mask ^= mbyte ^ ((nonce & (1 << bit)) >> bit);
    }

    return padding_mask;
}

static void WritePaddingByte(
    uint8_t *dest_ptr,
    uint8_t padlen,
    const uint8_t *key
) {
    uint8_t nonce = random_word() % 256;
    uint8_t padding_mask = GetPaddingLengthMask(key, nonce);
    *dest_ptr++ = nonce;
    *dest_ptr++ = padlen ^ padding_mask;
}

static void ObscureCipherBlock(uint8_t *dest, uint8_t *key) {
    int randw = random_word();
    uint8_t mask_nonce = randw >> 8;
    uint8_t rot_nonce = randw & 255;
    uint8_t rot = 1;
    uint8_t rot_bit_mask = 128;
    *dest++ = mask_nonce;
    *dest++ = rot_nonce;

    for (int i = 0; i < BLOCK_SIZE; i++) {
        uint8_t byte = *dest;
        byte = CircularShift(byte, rot_nonce & rot_bit_mask ? rot++ : -rot);
        byte ^= mask_nonce ^ key[i];
        *dest++ = byte;
        key[i] ^= mask_nonce;
        mask_nonce++;
        rot = (rot + 1) % 8;
        if (rot_bit_mask > 0) {
            rot_bit_mask >>= 1;
        } else {
            rot_bit_mask = 128;
        }
    }
}

CCryptCipher *CreateCCryptCipher(const uint8_t *key, size_t ksize) {
    CCryptCipher *cipher = sfmalloc(sizeof(*cipher));
    cipher->key = NormalizeKey(key, ksize);
    cipher->text_ptable = CreatePermutationTable();
    cipher->key_ptable = CreatePermutationTable();
    cipher->wrote_header = FALSE;
    cipher->plaintext = NULL;
    cipher->ptsize = 0;
    return cipher;
}

void DestroyCCryptCipher(CCryptCipher *cipher) {
    free((uint8_t*) cipher->key);
    free((size_t*) cipher->text_ptable);
    free((size_t*) cipher->key_ptable);
    free((uint8_t*) cipher->plaintext);
    free(cipher);
}

static void CCryptBlockCipher(
    CCryptCipher *cipher,
    const uint8_t *plaintext,
    uint8_t *dest,
    size_t blocks
) {
    for (size_t i = 0; i < blocks; i++) {
        size_t block_index = BLOCK_SIZE * i;
        uint8_t *pkey = PermutateBits(
            cipher->key,
            BLOCK_SIZE,
            cipher->key_ptable,
            BLOCK_BITS
        );
        const uint8_t *pblock = NULL;

        for (size_t j = 0; j < BLOCK_SIZE; j++) {
            size_t ptindex = block_index + j;
            *(dest + 2 + j) = plaintext[ptindex] ^ pkey[j];
        }

        ObscureCipherBlock(dest, pkey);
        pblock = PermutateBits(
            dest + 2,
            BLOCK_SIZE,
            cipher->text_ptable,
            BLOCK_BITS
        );
        memcpy(dest + 2, pblock, BLOCK_SIZE);
        dest += CIPHERTEXT_BLOCK_SIZE;
        free((uint8_t*) pblock);
        free((uint8_t*) cipher->key);
        cipher->key = pkey;
    }
}

uint8_t *UpdateCCryptCipher(
    CCryptCipher *cipher,
    const uint8_t *plaintext,
    size_t ptsize,
    size_t *szptr
) {
    uint8_t *input = NULL;
    uint8_t *inptr = NULL;
    size_t input_size = cipher->ptsize + ptsize;
    size_t blocks = 0;
    size_t rest = 0;
    size_t ctsize = 0;
    uint8_t *output = NULL;
    uint8_t *outptr = NULL;

    *szptr = 0;
    if (!cipher->wrote_header) {
        output = sfmalloc(sizeof(*output) * CIPHERTEXT_HEADER_LENGTH);
        outptr = output;
        PutPermutationTable(&outptr, cipher->text_ptable, cipher->key);
        PutPermutationTable(&outptr, cipher->key_ptable, cipher->key);
        *szptr += CIPHERTEXT_PTABLE_LENGTH * 2;
        cipher->wrote_header = TRUE;
    }

    if (input_size < BLOCK_SIZE) {
        return output;
    }

    blocks = input_size / BLOCK_SIZE;
    rest = input_size % BLOCK_SIZE;
    input = sfmalloc(sizeof(*input) * input_size);
    inptr = input;

    if (cipher->ptsize > 0) {
        memcpy(inptr, cipher->plaintext, sizeof(*input) * cipher->ptsize);
        inptr += cipher->ptsize;
        free(cipher->plaintext);
        cipher->plaintext = NULL;
        cipher->ptsize = 0;
    }
    memcpy(inptr, plaintext, sizeof(*input) * ptsize);

    if (rest > 0) {
        cipher->plaintext = sfmalloc(sizeof(*cipher->plaintext) * rest);
        cipher->ptsize = rest;
        memcpy(
            cipher->plaintext,
            input + input_size - rest,
            sizeof(*input) * rest
        );
    }

    ctsize = blocks * CIPHERTEXT_BLOCK_SIZE;
    output = sfrealloc(output, sizeof(*output) * (*szptr + ctsize));
    outptr = output + *szptr;
    *szptr += ctsize;
    CCryptBlockCipher(cipher, input, outptr, blocks);
    free(input);
    return output;
}

uint8_t *EndCCryptCipher(
    CCryptCipher *cipher,
    const uint8_t *plaintext,
    size_t ptsize,
    size_t *szptr
) {
    size_t input_size = cipher->ptsize + ptsize;
    size_t padding_size = 0;
    uint8_t *input = NULL;
    uint8_t *output = NULL;

    if (input_size % BLOCK_SIZE > 0) {
        padding_size = BLOCK_SIZE - input_size % BLOCK_SIZE;
    }

    input = sfmalloc(sizeof(*input) * (ptsize + padding_size));
    memcpy(input, plaintext, sizeof(*input) * ptsize);
    if (padding_size > 0) {
        for (size_t i = 0; i < padding_size; i++) {
            *(input + ptsize + i) = 54;
        }
    }

    output = UpdateCCryptCipher(cipher, input, ptsize + padding_size, szptr);
    output = sfrealloc(output, sizeof(*output) * (*szptr + CIPHERTEXT_PADDING_BYTES));
    WritePaddingByte(output + (*szptr), padding_size, cipher->key);
    *szptr += CIPHERTEXT_PADDING_BYTES;
    free(input);
    DestroyCCryptCipher(cipher);
    return output;
}

static int TestPermutationTable(const size_t *ptable) {
    size_t slen = BLOCK_BITS;
    size_t *seq = sfcalloc(slen, sizeof(*seq));
    size_t i = 0;
    int zero_worn = 0;

    for ( ; i < slen; i++) {
        size_t bit = ptable[i];
        if (bit >= slen) {
            break;
        }

        if (bit == 0) {
            if (zero_worn) {
                break;
            }
            zero_worn = 1;
        } else if (seq[bit] != 0) {
            break;
        }

        seq[bit] = bit;
    }

    free(seq);
    return i == slen;
}

static const size_t *DecipherPermutationTable(
    uint8_t **ct_ptr,
    const uint8_t *key
) {
    uint8_t *ct = *ct_ptr;
    size_t *ptable = sfmalloc(sizeof(*ptable) * BLOCK_BITS);
    uint8_t *ckey = sfmalloc(sizeof(*key) * BLOCK_SIZE);
    memcpy(ckey, key, BLOCK_SIZE);

    for (size_t i = 0; i < 8; i++) {
        uint8_t nonce = *ct++;
        uint8_t fbit = ckey[0] >> 7;
        size_t ptindex = BLOCK_SIZE * i;
        for (int j = 0; j < BLOCK_SIZE; j++) {
            uint8_t adjbit = j < BLOCK_SIZE - 1 ? ckey[j + 1] >> 7 : fbit;
            ckey[j] ^= nonce++;
            ckey[j] = ((ckey[j] & 127) << 1) | adjbit;
            ptable[ptindex + j] = *ct++ ^ ckey[j];
        }
    }

    *ct_ptr = ct;
    free(ckey);
    return ptable;
}

static const size_t *ReversePermutationTable(const size_t *ptable) {
    size_t *rptable = sfmalloc(sizeof(*rptable) * BLOCK_BITS);
    for (int i = 0; i < BLOCK_BITS; i++) {
        rptable[ptable[i]] = i;
    }
    return (const size_t*) rptable;
}

static uint8_t DecipherPaddingByte(
    const uint8_t *ct_ptr,
    const uint8_t *key
) {
    uint8_t nonce = *ct_ptr++;
    uint8_t masked_padlen = *ct_ptr++;
    uint8_t padding_mask = GetPaddingLengthMask(key, nonce);
    return masked_padlen ^ padding_mask;
}

static void ClearCipherBlock(
    uint8_t *dest,
    uint8_t mask_nonce,
    uint8_t rot_nonce,
    uint8_t *key
) {
    uint8_t rot = 1;
    uint8_t rot_bit_mask = 128;

    for (int i = 0; i < BLOCK_SIZE; i++) {
        uint8_t byte = *dest;
        byte ^= mask_nonce++ ^ key[i];
        byte = CircularShift(byte, rot_nonce & rot_bit_mask ? -rot++ : rot);
        *dest++ = byte;
        rot = (rot + 1) % 8;
        if (rot_bit_mask > 0) {
            rot_bit_mask >>= 1;
        } else {
            rot_bit_mask = 128;
        }
    }
}

CCryptDecipher *CreateCCryptDecipher(const uint8_t *key, size_t ksize) {
    CCryptDecipher *decipher = sfmalloc(sizeof(*decipher));
    decipher->key = NormalizeKey(key, ksize);
    decipher->section = 0;
    decipher->text_rptable = NULL;
    decipher->key_ptable = NULL;
    decipher->ciphertext = NULL;
    decipher->ctsize = 0;
    return decipher;
}

void DestroyCCryptDecipher(CCryptDecipher *decipher) {
    free((uint8_t*) decipher->key);
    free((size_t*) decipher->text_rptable);
    free((size_t*) decipher->key_ptable);
    free(decipher->ciphertext);
    free(decipher);
}

static void CCryptBlockDecipher(
    CCryptDecipher *decipher,
    const uint8_t *ciphertext,
    uint8_t *dest,
    size_t blocks
) {
    for (size_t i = 0; i < blocks; i++) {
        uint8_t *pkey = PermutateBits(
            decipher->key,
            BLOCK_SIZE,
            decipher->key_ptable,
            BLOCK_BITS
        );
        uint8_t *block = PermutateBits(
            ciphertext + 2,
            BLOCK_SIZE,
            decipher->text_rptable,
            BLOCK_BITS
        );
        uint8_t mask_nonce = *ciphertext++;
        uint8_t rot_nonce = *ciphertext++;

        ClearCipherBlock(block, mask_nonce, rot_nonce, pkey);
        for (int j = 0; j < BLOCK_SIZE; j++) {
            block[j] ^= pkey[j]; 
            pkey[j] ^= mask_nonce + j;
        }

        memcpy(dest, block, BLOCK_SIZE);
        dest += BLOCK_SIZE;
        ciphertext += BLOCK_SIZE;
        free((uint8_t*) decipher->key);
        free(block);
        decipher->key = pkey;
    }
}

CCryptDecipherResult UpdateCCryptDecipher(
    CCryptDecipher *decipher,
    const uint8_t *ciphertext,
    size_t ctsize,
    uint8_t **dest_ptr,
    size_t *szptr
) {
    CCryptDecipherResult result = CCRYPT_DECIPHER_NO_ERROR;
    int section = decipher->section;
    uint8_t *input = NULL;
    uint8_t *inptr = NULL;
    size_t input_size = decipher->ctsize + ctsize;
    size_t left_bytes = input_size;
    uint8_t *output = NULL;
    uint8_t reading_header = section == 0 || section == 1;

    *dest_ptr = NULL;
    *szptr = 0;
    if (
        (reading_header && input_size < CIPHERTEXT_PTABLE_LENGTH) ||
        (!reading_header && input_size < CIPHERTEXT_BLOCK_SIZE)
    ) {
        return CCRYPT_DECIPHER_NO_ERROR;
    }

    input = sfmalloc(sizeof(*input) * input_size);
    inptr = input;

    if (decipher->ctsize > 0) {
        memcpy(inptr, decipher->ciphertext, sizeof(*input) * decipher->ctsize);
        inptr += decipher->ctsize;
        free(decipher->ciphertext);
        decipher->ciphertext = NULL;
        decipher->ctsize = 0;
    }
    memcpy(inptr, ciphertext, sizeof(*input) * ctsize);
    inptr = input;

    if (reading_header) {
        const size_t *ptable = DecipherPermutationTable(&inptr, decipher->key);
        if (TestPermutationTable(ptable)) {
            left_bytes -= CIPHERTEXT_PTABLE_LENGTH;
            section++;
            if (section == 1) {
                decipher->text_rptable = ReversePermutationTable(ptable);
                free((size_t*) ptable);
                if (left_bytes >= CIPHERTEXT_PTABLE_LENGTH) {
                    ptable = DecipherPermutationTable(&inptr, decipher->key);
                    if (TestPermutationTable(ptable)) {
                        left_bytes -= CIPHERTEXT_PTABLE_LENGTH;
                        section++;
                        decipher->key_ptable = ptable;
                    } else {
                        result = CCRYPT_DECIPHER_INVALID_HEADER;
                    }
                }
            } else {
                decipher->key_ptable = ptable;
            }
        } else {
            result = CCRYPT_DECIPHER_INVALID_HEADER;
        }
    }

    if (result == CCRYPT_DECIPHER_NO_ERROR) {
        if (section == 2 && left_bytes >= CIPHERTEXT_BLOCK_SIZE) {
            size_t ctblocks = left_bytes / CIPHERTEXT_BLOCK_SIZE;
            *szptr = BLOCK_SIZE * ctblocks;
            output = sfmalloc(sizeof(*output) * (*szptr));
            CCryptBlockDecipher(decipher, inptr, output, ctblocks);
            inptr += left_bytes - left_bytes % CIPHERTEXT_BLOCK_SIZE;
            left_bytes %= CIPHERTEXT_BLOCK_SIZE;
        }

        if (left_bytes > 0) {
            decipher->ciphertext = sfmalloc(sizeof(*decipher->ciphertext) * left_bytes);
            decipher->ctsize = left_bytes;
            memcpy(decipher->ciphertext, inptr, sizeof(*input) * left_bytes);
        }

        decipher->section = section;
    } else {
        DestroyCCryptDecipher(decipher);
    }

    *dest_ptr = output;
    free(input);
    return result;
}

CCryptDecipherResult EndCCryptDecipher(
    CCryptDecipher *decipher,
    const uint8_t *ciphertext,
    size_t ctsize,
    uint8_t **dest_ptr,
    size_t *szptr,
    uint8_t *padding_ptr
) {
    CCryptDecipherResult result = CCRYPT_DECIPHER_NO_ERROR;
    CCryptDecipherResult uresult = CCRYPT_DECIPHER_NO_ERROR;
    int section = decipher->section;
    uint8_t *input = NULL;
    size_t input_size = decipher->ctsize + ctsize;
    size_t req_size = 0;
    uint8_t *output = NULL;
    int destroyed = FALSE;

    *dest_ptr = NULL;
    *szptr = 0;
    *padding_ptr = 0;
    if (section == 0 || section == 1) {
        req_size = (2 - section) * CIPHERTEXT_PTABLE_LENGTH;
    }

    if (input_size >= req_size) {
        size_t rest = (input_size - req_size) % CIPHERTEXT_BLOCK_SIZE;
        if (rest != CIPHERTEXT_PADDING_BYTES) {
            result = CCRYPT_DECIPHER_PADDING_ERROR;
        }

        if (ctsize > rest) {
            input_size = ctsize - rest;
            input = sfmalloc(sizeof(*input) * input_size);
            memcpy(input, ciphertext, sizeof(*input) * input_size);

            uresult = UpdateCCryptDecipher(
                decipher,
                input,
                input_size,
                &output,
                szptr
            );

            if (uresult != CCRYPT_DECIPHER_NO_ERROR) {
                destroyed = TRUE;
            }

            if (result == CCRYPT_DECIPHER_NO_ERROR) {
                result = uresult;
                ciphertext += input_size;
                ctsize = rest;
            }
        }

        if (result == CCRYPT_DECIPHER_NO_ERROR) {
            size_t left_bytes = ctsize + decipher->ctsize;
            uint8_t *padding_bytes = \
                sfmalloc(sizeof(*padding_bytes) * left_bytes);
            uint8_t *pbptr = padding_bytes;
            uint8_t padlen = 0;

            if (decipher->ctsize > 0) {
                memcpy(
                    pbptr,
                    decipher->ciphertext,
                    sizeof(*padding_bytes) * decipher->ctsize
                );
                pbptr += decipher->ctsize;
                free(decipher->ciphertext);
                decipher->ciphertext = NULL;
                decipher->ctsize = 0;
            }

            if (ctsize > 0) {
                memcpy(pbptr, ciphertext, sizeof(*padding_bytes) * ctsize);
            }

            padlen = DecipherPaddingByte(padding_bytes, decipher->key);
            if (padlen < BLOCK_SIZE) {
                *padding_ptr = padlen;
            } else {
                result = CCRYPT_DECIPHER_PADDING_ERROR;
            }
        }
    } else {
        result = CCRYPT_DECIPHER_INVALID_LENGTH;
    }

    if (!destroyed) {
        DestroyCCryptDecipher(decipher);
    }
    *dest_ptr = output;
    free(input);
    return result;
}
