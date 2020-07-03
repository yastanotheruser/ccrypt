#ifndef IO_H
#define IO_H

#include <gio/gio.h>

#define FILE_BLOCK_SIZE 65536

typedef enum {
    FILE_ENC_ENCRYPTED,
    FILE_ENC_READ_ERROR,
    FILE_ENC_WRITE_ERROR,
    FILE_ENC_ENCRYPT_ERROR,
    FILE_ENC_CANCELLED
} file_enc_result;

typedef enum {
    FILE_DEC_DECRYPTED,
    FILE_DEC_READ_ERROR,
    FILE_DEC_WRITE_ERROR,
    FILE_DEC_INVALID_FORMAT,
    FILE_DEC_PADDING_ERROR,
    FILE_DEC_CANCELLED
} file_dec_result;

guint8 *read_whole_file(GFile *file, gsize *size_ptr);
gboolean write_file(GFile *file, const guint8 *buffer, gsize size);
file_enc_result encrypt_file(
    GFile *file,
    GFile *dst_file,
    const guint8 *key,
    gsize ksize,
    void (*progress_callback)(goffset, goffset),
    GCancellable *cancellable
);
file_dec_result decrypt_file(
    GFile *file,
    GFile *dst_file,
    const guint8 *key,
    gsize ksize,
    void (*progress_callback)(goffset, goffset),
    GCancellable *cancellable
);

#endif 
