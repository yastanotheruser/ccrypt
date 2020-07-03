#include "io.h"
#include <stdio.h>
#include <stdlib.h>
#include <gio/gio.h>
#include "ccrypt.h"
#include "lib/bytes.h"

guint8 *read_whole_file(GFile *file, gsize *size_ptr) {
    GInputStream *input = NULL;
    gsize byte_count = 0;
    guint8 *file_bytes = NULL;
    guint8 *block_buf = NULL;
    gboolean had_error = FALSE;

    input = G_INPUT_STREAM(g_file_read(file, NULL, NULL));
    if (input == NULL) {
        return NULL;
    }

    byte_count = 0;
    file_bytes = g_malloc(0);
    block_buf = g_malloc(FILE_BLOCK_SIZE);

    while (TRUE) {
        gssize bytes_read = g_input_stream_read(
            input,
            block_buf,
            FILE_BLOCK_SIZE,
            NULL,
            NULL
        );

        if (bytes_read > 0) {
            file_bytes = g_realloc(file_bytes, byte_count + bytes_read);
            memcpy(file_bytes + byte_count, block_buf, bytes_read);
            byte_count += bytes_read;
        } else {
            if (bytes_read == -1) {
                had_error = TRUE;
            }
            break;
        }
    }

    g_input_stream_close(input, NULL, NULL);
    g_object_unref(input);
    g_free(block_buf);
    if (had_error) {
        g_free(file_bytes);
        return NULL;
    }

    *size_ptr = byte_count;
    return file_bytes;
}

gboolean write_file(GFile *file, const guint8 *buffer, gsize size) {
    GOutputStream *output = G_OUTPUT_STREAM(g_file_replace(
        file,
        NULL,
        FALSE,
        G_FILE_CREATE_NONE,
        NULL,
        NULL
    ));

    gboolean result = g_output_stream_write(output, buffer, size, NULL, NULL) != -1;
    g_output_stream_close(output, NULL, NULL);
    g_object_unref(output);
    return result;
}

file_enc_result encrypt_file(
    GFile *file,
    GFile *dst_file,
    const guint8 *key,
    gsize ksize,
    void (*progress_callback)(goffset, goffset),
    GCancellable *cancellable
) {
    file_enc_result result = FILE_ENC_ENCRYPTED;
    GInputStream *input = NULL;
    GOutputStream *output = NULL;
    GFileInfo *info = NULL;
    goffset file_size = 0;
    goffset total_read = 0;
    CCryptCipher *cipher = NULL;
    guint8 block_buf[FILE_BLOCK_SIZE];
    guint8 *output_buf = NULL;

    input = G_INPUT_STREAM(g_file_read(file, NULL, NULL));
    if (input == NULL) {
        return FILE_ENC_READ_ERROR;
    }

    info = g_file_input_stream_query_info(
        G_FILE_INPUT_STREAM(input),
        G_FILE_ATTRIBUTE_STANDARD_SIZE,
        NULL,
        NULL
    );

    if (info == NULL) {
        result = FILE_ENC_READ_ERROR;
        goto cleanup_input;
    }

    output = G_OUTPUT_STREAM(g_file_replace(
        dst_file,
        NULL,
        FALSE,
        G_FILE_CREATE_NONE,
        NULL,
        NULL
    ));

    if (output == NULL) {
        result = FILE_ENC_WRITE_ERROR;
        goto cleanup_info;
    }

    file_size = g_file_info_get_size(info);
    cipher = CreateCCryptCipher(key, ksize);

    while (TRUE) {
        gssize read_bytes = g_input_stream_read(
            input,
            block_buf,
            FILE_BLOCK_SIZE,
            NULL,
            NULL
        );
        gsize output_size = 0;
        gssize written_bytes = 0;

        if (read_bytes == -1) {
            result = FILE_ENC_READ_ERROR;
            goto cleanup_cipher;
        } else if (read_bytes != 0) {
            output_buf = UpdateCCryptCipher(
                cipher,
                block_buf,
                read_bytes,
                &output_size
            );
        } else {
            output_buf = EndCCryptCipher(cipher, NULL, 0, &output_size);
        }

        written_bytes = g_output_stream_write(
            output,
            output_buf,
            output_size,
            NULL,
            NULL
        );

        g_free(output_buf);
        if (written_bytes == -1) {
            result = FILE_ENC_WRITE_ERROR;
            goto cleanup_cipher;
        }

        total_read += read_bytes;
        progress_callback(total_read, file_size);

        while (g_main_context_pending(NULL)) {
            g_main_context_iteration(NULL, FALSE);
        }

        if (read_bytes == 0) {
            goto cleanup_output;
        }

        if (g_cancellable_is_cancelled(cancellable)) {
            result = FILE_ENC_CANCELLED;
            goto cleanup_cipher;
        }
    }

    goto cleanup_output;

cleanup_cipher:
    DestroyCCryptCipher(cipher);
    g_file_delete(dst_file, NULL, NULL);
cleanup_output:
    g_output_stream_close(output, NULL, NULL);
    g_object_unref(output);
cleanup_info:
    g_object_unref(info);
cleanup_input:
    g_input_stream_close(input, NULL, NULL);
    g_object_unref(input);
    return result;
}

file_dec_result decrypt_file(
    GFile *file,
    GFile *dst_file,
    const guint8 *key,
    gsize ksize,
    void (*progress_callback)(goffset, goffset),
    GCancellable *cancellable
) {
    file_dec_result result = FILE_DEC_DECRYPTED;
    GInputStream *input = NULL;
    GOutputStream *output = NULL;
    GFileInfo *info = NULL;
    goffset file_size = 0;
    goffset total_read = 0;
    CCryptDecipher *decipher = NULL;
    guint8 block_buf[FILE_BLOCK_SIZE];
    guint8 padding_length = 0;

    input = G_INPUT_STREAM(g_file_read(file, NULL, NULL));
    if (input == NULL) {
        return FILE_DEC_READ_ERROR;
    }

    info = g_file_input_stream_query_info(
        G_FILE_INPUT_STREAM(input),
        G_FILE_ATTRIBUTE_STANDARD_SIZE,
        NULL,
        NULL
    );

    if (info == NULL) {
        result = FILE_DEC_READ_ERROR;
        goto cleanup_input;
    }

    output = G_OUTPUT_STREAM(g_file_replace(
        dst_file,
        NULL,
        FALSE,
        G_FILE_CREATE_NONE,
        NULL,
        NULL
    ));

    if (output == NULL) {
        result = FILE_DEC_WRITE_ERROR;
        goto cleanup_info;
    }

    file_size = g_file_info_get_size(info);
    decipher = CreateCCryptDecipher(key, ksize);

    while (TRUE) {
        gssize read_bytes = g_input_stream_read(
            input,
            block_buf,
            FILE_BLOCK_SIZE,
            NULL,
            NULL
        );
        gsize output_size = 0;
        CCryptDecipherResult dec_result = CCRYPT_DECIPHER_NO_ERROR;
        guint8 *output_buf = NULL;
        gssize written_bytes = 0;

        if (read_bytes == -1) {
            result = FILE_DEC_READ_ERROR;
            goto cleanup_decipher;
        } else if (read_bytes != 0) {
            dec_result = UpdateCCryptDecipher(
                decipher,
                block_buf,
                read_bytes,
                &output_buf,
                &output_size
            );
        } else {
            guint8 *dummy_ptr = NULL;
            dec_result = EndCCryptDecipher(
                decipher,
                NULL,
                0,
                &dummy_ptr,
                &output_size,
                &padding_length
            );
        }

        if (
            dec_result == CCRYPT_DECIPHER_INVALID_HEADER ||
            dec_result == CCRYPT_DECIPHER_INVALID_LENGTH
        ) {
            result = FILE_DEC_INVALID_FORMAT;
            goto cleanup_output_file;
        } else if (dec_result == CCRYPT_DECIPHER_PADDING_ERROR) {
            result = FILE_DEC_PADDING_ERROR;
        }

        if (output_size > 0) {
            written_bytes = g_output_stream_write(
                output,
                output_buf,
                output_size,
                NULL,
                NULL
            );
        }

        free(output_buf);
        if (written_bytes == -1) {
            result = FILE_DEC_WRITE_ERROR;
            goto cleanup_decipher;
        }

        total_read += read_bytes;
        progress_callback(total_read, file_size);

        while (g_main_context_pending(NULL)) {
            g_main_context_iteration(NULL, FALSE);
        }

        if (read_bytes == 0) {
            break;
        }

        if (g_cancellable_is_cancelled(cancellable)) {
            result = FILE_DEC_CANCELLED;
            goto cleanup_decipher;
        }
    }

    if (padding_length > 0) {
        GSeekable *seekable = G_SEEKABLE(output);
        goffset offset = g_seekable_tell(seekable);
        g_seekable_truncate(
            seekable,
            offset - padding_length,
            NULL,
            NULL
        );
    }

    goto cleanup_output;

cleanup_decipher:
    DestroyCCryptDecipher(decipher);
cleanup_output_file:
    g_file_delete(dst_file, NULL, NULL);
cleanup_output:
    g_output_stream_close(output, NULL, NULL);
    g_object_unref(output);
cleanup_info:
    g_object_unref(info);
cleanup_input:
    g_input_stream_close(input, NULL, NULL);
    g_object_unref(input);
    return result;
}
