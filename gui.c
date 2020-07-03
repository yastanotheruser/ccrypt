#include "gui.h"
#include <string.h>
#include "io.h"
#include "gtkutils.h"
#include "ccrypt.h"
#include "lib/bytes.h"
#include "lib/debug.h"

struct {
    GtkWindow *window;
    GtkFileChooserNative *dst_native;
    GtkFileChooserNative *src_native;
    GtkClipboard *clipboard;
} shared_objs;

struct {
    GtkEntry *file_entry;
    GtkFileChooser *file_chooser;
    GtkEntry *key_entry;
    GtkButton *enc_button;
    GtkButton *dec_button;
    GtkCheckButton *rmorig_button;
    GtkBox *bottom_box;
    GtkProgressBar *progress_bar;
    GtkGrid *grid;
    GCancellable *cancellable;
} file_enc_objs;

struct {
    GtkTextView *ptext_view;
    GtkTextView *ctext_view;
} text_enc_objs;

typedef enum {
    ENCRYPT,
    DECRYPT
} file_operation;

static void wrap_base64(gchar **data, gint cols) {
    gchar *str = *data;
    gsize length = strlen(str);
    gchar *lfptr = NULL;
    gsize lfct = 0;
    gint l = 0;
    gchar *result = NULL;
    gsize rlen = 0;
    gchar *rptr = NULL;

    lfptr = strchr(str, '\n');
    while (lfptr != NULL) {
        lfct++;
        lfptr = strchr(lfptr + 1, '\n');
    }

    length -= lfct;
    rlen = length + length / cols;
    if (length % cols > 0) {
        rlen++;
    }
    length += lfct;

    result = sfmalloc(sizeof(*result) * (rlen + 1));
    rptr = result;

    for (gsize i = 0; i < length; i++) {
        if (str[i] == '\n') {
            continue;
        }
        *rptr++ = str[i];
        l++;
        if (l == cols) {
            *rptr++ = '\n';
            l = 0;
        }
    }

    *rptr++ = '\0';
    free(str);
    *data = result;
}

static void init_shared_objects(GtkWindow *window) {
    GtkFileChooserNative *dst_native = gtk_file_chooser_native_new(
        "Guardar como",
        window,
        GTK_FILE_CHOOSER_ACTION_SAVE,
        "_Guardar",
        "_Cancelar"
    );
    GtkFileChooserNative *src_native = gtk_file_chooser_native_new(
        "Seleccionar archivo",
        window,
        GTK_FILE_CHOOSER_ACTION_OPEN,
        "_Abrir",
        "_Cancelar"
    );
    GtkFileFilter *filter = gtk_file_filter_new();

    gtk_file_chooser_set_do_overwrite_confirmation(
        GTK_FILE_CHOOSER(dst_native),
        TRUE
    );
    gtk_file_filter_add_pattern(filter, "*");
    gtk_file_chooser_set_filter(GTK_FILE_CHOOSER(dst_native), filter);
    gtk_file_chooser_set_filter(GTK_FILE_CHOOSER(src_native), filter);

    shared_objs.window = window;
    shared_objs.dst_native = dst_native;
    shared_objs.src_native = src_native;
    shared_objs.clipboard = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
}

static void file_enc_update_buttons(void) {
    gboolean nofile = \
        gtk_file_chooser_get_filename(file_enc_objs.file_chooser) == NULL;
    gboolean nokey = \
        gtk_entry_get_text_length(file_enc_objs.key_entry) == 0;
    gboolean sensitive = !nofile && !nokey;
    gtk_widget_set_sensitive(GTK_WIDGET(file_enc_objs.enc_button), sensitive);
    gtk_widget_set_sensitive(GTK_WIDGET(file_enc_objs.dec_button), sensitive);
}

static void file_enc_update_native(file_operation op) {
    static const gchar *default_enc_ext = ".ccrypt";
    static const gchar *default_dec_ext = ".out";
    const gchar *default_ext = \
        op == ENCRYPT ? default_enc_ext : default_dec_ext;
    size_t default_ext_sz = strlen(default_ext) + 1;
    GtkFileChooser *file_chooser = file_enc_objs.file_chooser;
    GtkFileChooser *native = GTK_FILE_CHOOSER(shared_objs.dst_native);
    g_autofree gchar *filename = gtk_file_chooser_get_filename(file_chooser);
    g_autofree gchar *basename = NULL;
    gsize basename_len = 0;

    if (filename == NULL) {
        gtk_file_chooser_unselect_all(native);
        return;
    }

    basename = g_path_get_basename(filename);
    basename_len = strlen(basename);
    if (op == DECRYPT && g_str_has_suffix(basename, default_enc_ext)) {
        gsize nlen = basename_len - strlen(default_enc_ext);
        basename[nlen] = '\0';
        if (strlen(basename) == 0) {
            memcpy(basename, default_ext, default_ext_sz);
        }
    } else {
        basename = g_realloc(basename, basename_len + default_ext_sz);
        memcpy(basename + basename_len, default_ext, default_ext_sz);
    }

    gtk_file_chooser_set_current_name(native, basename);
}

static void file_enc_clear_fields(void) {
    gtk_entry_set_text(file_enc_objs.file_entry, "");
    gtk_file_chooser_unselect_all(file_enc_objs.file_chooser);
    gtk_entry_set_text(file_enc_objs.key_entry, "");
}

static void file_entry_focus_out(GtkEntry *file_entry) {
    GtkFileChooser *file_chooser = file_enc_objs.file_chooser;
    g_autofree gchar *path = g_strdup(gtk_entry_get_text(file_entry));
    GFile *file = NULL;

    if (strlen(path) > 0) {
        file = g_file_new_for_path(path);
        if (
            !g_file_query_exists(file, NULL) ||
            g_file_query_file_type(
                file,
                G_FILE_QUERY_INFO_NONE,
                NULL
            ) != G_FILE_TYPE_REGULAR
        ) {
            gtk_entry_set_text(file_entry, "");
            gtk_file_chooser_unselect_all(file_chooser);
            show_message_dialog(GTK_MESSAGE_ERROR, g_strdup_printf(
                "El archivo '%s' no existe o no es un archivo regular",
                path
            ), shared_objs.window);
        } else {
            gtk_file_chooser_set_filename(file_chooser, g_file_get_path(file));
        }

        g_object_unref(file);
    } else {
        gtk_file_chooser_unselect_all(file_chooser);
    }

    file_enc_update_buttons();
}

static void enc_file_set(void) {
    const gchar *path = gtk_file_chooser_get_filename(file_enc_objs.file_chooser);
    gtk_entry_set_text(file_enc_objs.file_entry, path);
    file_enc_update_buttons();
}

static void file_enc_begin(void) {
    GCancellable *cancellable = g_cancellable_new();
    if (file_enc_objs.cancellable != NULL) {
        g_object_unref(file_enc_objs.cancellable);
    }
    file_enc_objs.cancellable = cancellable;
    gtk_widget_set_sensitive(GTK_WIDGET(file_enc_objs.grid), FALSE);
    gtk_progress_bar_set_fraction(
        GTK_PROGRESS_BAR(file_enc_objs.progress_bar),
        0.0
    );
    gtk_widget_show_all(GTK_WIDGET(file_enc_objs.bottom_box));
}

static void file_enc_end(void) {
    if (file_enc_objs.cancellable != NULL) {
        g_object_unref(file_enc_objs.cancellable);
        file_enc_objs.cancellable = NULL;
    }
    gtk_widget_hide(GTK_WIDGET(file_enc_objs.bottom_box));
    gtk_widget_set_sensitive(GTK_WIDGET(file_enc_objs.grid), TRUE);
}

static void file_enc_progress(goffset read, goffset total) {
    gtk_progress_bar_set_fraction(
        file_enc_objs.progress_bar,
        (double) read / total
    );
}

static void file_enc_button_clicked(void) {
    GtkFileChooserNative *native;
    gint res;
    const gchar *key;
    GFile *file;
    GFile *dst_file;
    file_enc_result result;
    gboolean rmorig;
    const gchar *message;

    native = shared_objs.dst_native;
    file_enc_update_native(ENCRYPT);
    res = gtk_native_dialog_run(GTK_NATIVE_DIALOG(native));
    if (res != GTK_RESPONSE_ACCEPT) {
        return;
    }

    file_enc_begin();
    key = gtk_entry_get_text(file_enc_objs.key_entry);
    file = gtk_file_chooser_get_file(file_enc_objs.file_chooser);
    dst_file = gtk_file_chooser_get_file(GTK_FILE_CHOOSER(native));
    result = encrypt_file(
        file,
        dst_file,
        (const guint8*) key,
        strlen(key),
        &file_enc_progress,
        file_enc_objs.cancellable
    );

    rmorig = gtk_toggle_button_get_active(
        GTK_TOGGLE_BUTTON(file_enc_objs.rmorig_button)
    );
    if (result == FILE_ENC_ENCRYPTED && rmorig) {
        g_file_delete(file, NULL, NULL);
    }

    switch (result) {
        case FILE_ENC_ENCRYPTED:
            message = "El archivo fue encriptado";
            file_enc_clear_fields();
            break;
        case FILE_ENC_READ_ERROR:
            message = "No fue posible leer el archivo";
            break;
        case FILE_ENC_ENCRYPT_ERROR:
            message = "No fue posible encriptar el archivo";
            break;
        case FILE_ENC_WRITE_ERROR:
            message = "No fue posible guardar el archivo";
            break;
        default:
            break;
    }

    if (result != FILE_ENC_CANCELLED) {
        show_message_dialog(
            result == FILE_ENC_ENCRYPTED ? GTK_MESSAGE_INFO : GTK_MESSAGE_ERROR,
            message,
            shared_objs.window
        );
    }

    file_enc_end();
}

static void file_dec_button_clicked(void) {
    GtkFileChooserNative *native;
    gint res;
    const gchar *key;
    GFile *file;
    GFile *dst_file;
    file_dec_result result;
    gboolean success;
    gboolean rmorig;
    const gchar *message;

    native = shared_objs.dst_native;
    file_enc_update_native(DECRYPT);
    res = gtk_native_dialog_run(GTK_NATIVE_DIALOG(native));
    if (res != GTK_RESPONSE_ACCEPT) {
        return;
    }

    file_enc_begin();
    key = gtk_entry_get_text(file_enc_objs.key_entry);
    file = gtk_file_chooser_get_file(file_enc_objs.file_chooser);
    dst_file = gtk_file_chooser_get_file(GTK_FILE_CHOOSER(native));
    result = decrypt_file(
        file,
        dst_file,
        (const guint8*) key,
        strlen(key),
        file_enc_progress,
        file_enc_objs.cancellable
    );

    success = result == FILE_DEC_DECRYPTED || result == FILE_DEC_PADDING_ERROR;
    rmorig = gtk_toggle_button_get_active(
        GTK_TOGGLE_BUTTON(file_enc_objs.rmorig_button)
    );
    if (success && rmorig) {
        g_file_delete(file, NULL, NULL);
    }

    switch (result) {
        case FILE_DEC_DECRYPTED:
            message = "El archivo fue desencriptado";
            break;
        case FILE_DEC_PADDING_ERROR:
            message = "El archivo fue desencriptado, es posible que contenga bytes adicionales";
            break;
        case FILE_DEC_READ_ERROR:
            message = "No fue posible leer el archivo";
            break;
        case FILE_DEC_INVALID_FORMAT:
            message = "No fue posible desencriptar el archivo, archivo o clave inválidos";
            break;
        case FILE_DEC_WRITE_ERROR:
            message = "No fue posible guardar el archivo";
            break;
        default:
            break;
    }

    if (success) {
        file_enc_clear_fields();
    }

    if (result != FILE_DEC_CANCELLED) {
        show_message_dialog(
            success ? GTK_MESSAGE_INFO : GTK_MESSAGE_ERROR,
            message,
            shared_objs.window
        );
    }

    file_enc_end();
}

static void file_enc_cancel(void) {
    if (file_enc_objs.cancellable != NULL) {
        g_cancellable_cancel(file_enc_objs.cancellable);
    }
}

static void init_file_enc_tab(GtkWidget *notebook) {
    GtkWidget *tab_label = gtk_label_new("Encriptar y desencriptar archivos");
    GtkWidget *tab_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *grid = gtk_grid_new();
    GtkWidget *bottom_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);

    GtkWidget *file_entry_label = gtk_label_new("Ruta del archivo");
    GtkWidget *file_entry = gtk_entry_new();
    GtkFileFilter *filter = gtk_file_filter_new();
    GtkWidget *file_chooser = gtk_file_chooser_button_new(
        "Seleccionar archivo",
        GTK_FILE_CHOOSER_ACTION_OPEN
    );

    GtkWidget *key_entry_label = gtk_label_new("Clave de encriptación");
    GtkWidget *key_entry = gtk_entry_new();

    GtkWidget *button_box = gtk_button_box_new(GTK_ORIENTATION_HORIZONTAL);
    GtkWidget *enc_button = gtk_button_new_with_label("Encriptar");
    GtkWidget *dec_button = gtk_button_new_with_label("Desencriptar");

    GtkWidget *rmorig_button = \
        gtk_check_button_new_with_label("Eliminar archivo original al finalizar");

    GtkWidget *progress_bar = gtk_progress_bar_new();
    GtkWidget *cancel_button = gtk_button_new_with_label("Cancelar");

    gtk_widget_set_valign(tab_box, GTK_ALIGN_CENTER);
    g_object_set(grid, "margin", 10, NULL);
    gtk_grid_set_row_spacing(GTK_GRID(grid), 10);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);

    gtk_widget_set_halign(file_entry_label, GTK_ALIGN_END);
    gtk_widget_set_size_request(file_entry, 300, -1);
    gtk_file_filter_add_pattern(filter, "*");
    gtk_file_chooser_set_filter(GTK_FILE_CHOOSER(file_chooser), filter);
    gtk_file_chooser_set_current_folder(
        GTK_FILE_CHOOSER(file_chooser),
        g_get_current_dir()
    );
    gtk_widget_set_focus_on_click(file_chooser, FALSE);

    gtk_widget_set_halign(key_entry_label, GTK_ALIGN_END);
    gtk_entry_set_visibility(GTK_ENTRY(key_entry), FALSE);

    gtk_button_box_set_layout(GTK_BUTTON_BOX(button_box), GTK_BUTTONBOX_EXPAND);
    gtk_box_pack_start(GTK_BOX(button_box), enc_button, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(button_box), dec_button, TRUE, TRUE, 0);
    gtk_widget_set_sensitive(enc_button, FALSE);
    gtk_widget_set_sensitive(dec_button, FALSE);

    gtk_box_pack_start(GTK_BOX(bottom_box), progress_bar, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(bottom_box), cancel_button, TRUE, TRUE, 0);
    gtk_progress_bar_set_show_text(GTK_PROGRESS_BAR(progress_bar), TRUE);
    gtk_widget_set_focus_on_click(cancel_button, FALSE);
    gtk_widget_set_can_focus(cancel_button, FALSE);

    gtk_grid_attach(GTK_GRID(grid), file_entry_label, 1, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), file_entry, 2, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), file_chooser, 3, 1, 1, 1);

    gtk_grid_attach(GTK_GRID(grid), key_entry_label, 1, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), key_entry, 2, 2, 2, 1);

    gtk_grid_attach(GTK_GRID(grid), rmorig_button, 1, 3, 3, 1);

    gtk_grid_attach(GTK_GRID(grid), button_box, 1, 4, 3, 1);

    gtk_box_pack_start(GTK_BOX(tab_box), grid, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(tab_box), bottom_box, TRUE, TRUE, 0);
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), tab_box, tab_label);

    file_enc_objs.file_entry = GTK_ENTRY(file_entry);
    file_enc_objs.file_chooser = GTK_FILE_CHOOSER(file_chooser);
    file_enc_objs.key_entry = GTK_ENTRY(key_entry);
    file_enc_objs.enc_button = GTK_BUTTON(enc_button);
    file_enc_objs.dec_button = GTK_BUTTON(dec_button);
    file_enc_objs.rmorig_button = GTK_CHECK_BUTTON(rmorig_button);
    file_enc_objs.bottom_box = GTK_BOX(bottom_box);
    file_enc_objs.progress_bar = GTK_PROGRESS_BAR(progress_bar);
    file_enc_objs.grid = GTK_GRID(grid);
    file_enc_objs.cancellable = NULL;

    g_signal_connect_after(
        file_entry,
        "focus-out-event",
        G_CALLBACK(file_entry_focus_out),
        NULL
    );
    g_signal_connect(
        file_chooser,
        "file-set",
        G_CALLBACK(enc_file_set),
        NULL
    );

    g_signal_connect(
        key_entry,
        "changed",
        G_CALLBACK(file_enc_update_buttons),
        NULL
    );

    g_signal_connect_after(
        enc_button,
        "clicked",
        G_CALLBACK(file_enc_button_clicked),
        NULL
    );

    g_signal_connect_after(
        dec_button,
        "clicked",
        G_CALLBACK(file_dec_button_clicked),
        NULL
    );

    g_signal_connect_after(
        cancel_button,
        "clicked",
        G_CALLBACK(file_enc_cancel),
        NULL
    );
}

static void text_enc_key_entry_changed(
    GtkEntry *key_entry,
    GtkWidget *accept_button
) {
    guint16 key_length = gtk_entry_get_text_length(key_entry);
    gtk_widget_set_sensitive(accept_button, key_length > 0);
}

static const gchar *text_enc_read_key(GtkWindow *parent) {
    gint result = 0;
    const gchar *key = NULL;
    GtkWidget *key_dialog = gtk_dialog_new_with_buttons(
        "CCrypt",
        parent,
        GTK_DIALOG_MODAL,
        "Continuar",
        GTK_RESPONSE_ACCEPT,
        "Cancelar",
        GTK_RESPONSE_REJECT,
        NULL
    );
    GtkWidget *key_dialog_content = \
        gtk_dialog_get_content_area(GTK_DIALOG(key_dialog));
    GtkWidget *key_dialog_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    GtkWidget *key_entry_label = gtk_label_new("Clave de encriptación");
    GtkWidget *key_entry = gtk_entry_new();
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    GtkWidget *key_dialog_action = \
        gtk_dialog_get_action_area(GTK_DIALOG(key_dialog));
#pragma GCC diagnostic pop
    GtkWidget *accept_button = gtk_dialog_get_widget_for_response(
        GTK_DIALOG(key_dialog),
        GTK_RESPONSE_ACCEPT
    );

    g_object_set(key_dialog_content, "margin", 10, NULL);
    gtk_box_pack_start(
        GTK_BOX(key_dialog_box),
        key_entry_label,
        TRUE,
        TRUE,
        0
    );
    gtk_box_pack_start(
        GTK_BOX(key_dialog_box),
        key_entry,
        TRUE,
        TRUE,
        0
    );
    gtk_entry_set_visibility(GTK_ENTRY(key_entry), FALSE);
    gtk_widget_set_size_request(key_entry, 300, -1);
    gtk_container_add(GTK_CONTAINER(key_dialog_content), key_dialog_box);
    g_object_set(key_dialog_action, "margin-top", 10, NULL);
    gtk_widget_set_halign(key_dialog_action, GTK_ALIGN_CENTER);
    gtk_widget_set_sensitive(accept_button, FALSE);

    g_signal_connect(
        key_entry,
        "changed",
        G_CALLBACK(text_enc_key_entry_changed),
        accept_button
    );

    gtk_widget_show_all(key_dialog);
    result = gtk_dialog_run(GTK_DIALOG(key_dialog));
    if (result == GTK_RESPONSE_ACCEPT) {
        key = g_strdup(gtk_entry_get_text(GTK_ENTRY(key_entry)));
    }
    gtk_widget_destroy(key_dialog);
    return key;
}

static void text_enc_button_clicked(void) {
    g_autofree const gchar *key = NULL;
    g_autofree gchar *plaintext = NULL;
    gsize text_length = 0;
    g_autofree const guint8 *ciphertext = NULL;
    gsize ctsize = 0;
    g_autofree gchar *encoded_ctext = NULL;
    CCryptCipher *cipher = NULL;

    key = text_enc_read_key(shared_objs.window);
    if (key == NULL) {
        return;
    }

    plaintext = get_text_view_text(text_enc_objs.ptext_view, &text_length);
    cipher = CreateCCryptCipher((const guint8*) key, strlen(key));
    ciphertext = EndCCryptCipher(
        cipher,
        (uint8_t*) plaintext,
        text_length,
        &ctsize
    );
    encoded_ctext = g_base64_encode(ciphertext, ctsize);
    wrap_base64(&encoded_ctext, BASE64_TEXTVIEW_COLS);
    set_text_view_text(text_enc_objs.ctext_view, encoded_ctext, -1);
}

static void text_dec_button_clicked(void) {
    g_autofree const gchar *key = NULL;
    g_autofree const gchar *encoded_ctext = NULL;
    gsize encoded_ctext_length = 0;
    g_autofree const guint8 *ciphertext = NULL;
    gsize ctsize = 0;
    CCryptDecipherResult result = CCRYPT_DECIPHER_NO_ERROR;
    g_autofree guint8 *plaintext = NULL;
    gsize ptsize = 0;
    guint8 padlen = 0;
    CCryptDecipher *decipher = NULL;

    key = text_enc_read_key(shared_objs.window);
    if (key == NULL) {
        return;
    }

    encoded_ctext = get_text_view_text(
        text_enc_objs.ctext_view,
        &encoded_ctext_length
    );
    ciphertext = g_base64_decode(encoded_ctext, &ctsize);
    decipher = CreateCCryptDecipher((const guint8*) key, strlen(key));
    result = EndCCryptDecipher(
        decipher,
        (const guint8*) ciphertext,
        ctsize,
        &plaintext,
        &ptsize,
        &padlen
    );

    if (
        result != CCRYPT_DECIPHER_NO_ERROR &&
        result != CCRYPT_DECIPHER_PADDING_ERROR
    ) {
        show_message_dialog(
            GTK_MESSAGE_ERROR,
            "No fue posible desencriptar el texto, el formato o la clave son inválidos",
            shared_objs.window
        );
        return;
    }

    set_text_view_text(
        text_enc_objs.ptext_view,
        (const gchar*) plaintext,
        ptsize - padlen
    );
}

static gchar *text_enc_read_file(gsize *size_ptr) {
    GFile *src_file = get_native_file(shared_objs.src_native, NULL);
    if (src_file == NULL) {
        return NULL;
    }

    return (gchar*) read_whole_file(src_file, size_ptr);
}

static void text_enc_copy(const gchar *text, gsize size) {
    gtk_clipboard_set_text(shared_objs.clipboard, text, size);
}

static void text_enc_save(const gchar *text, gsize size) {
    GFile *dst_file = get_native_file(shared_objs.dst_native, "");
    if (dst_file == NULL) {
        return;
    }

    if (write_file(dst_file, (const guint8*) text, size)) {
        show_message_dialog(
            GTK_MESSAGE_INFO,
            "El texto fue guardado",
            shared_objs.window
        );
    } else {
        show_message_dialog(
            GTK_MESSAGE_ERROR,
            "No fue posible guardar el texto",
            shared_objs.window
        );
    }
}

static void text_enc_plain_import(void) {
    gsize size = 0;
    g_autofree gchar *data = text_enc_read_file(&size);
    if (data == NULL) {
        return;
    }
    set_text_view_text(text_enc_objs.ptext_view, data, size);
}

static void text_enc_plain_copy(void) {
    gsize ptsize = 0;
    g_autofree gchar *plaintext = get_text_view_text(
        text_enc_objs.ptext_view,
        &ptsize
    );
    text_enc_copy(plaintext, ptsize);
}

static void text_enc_plain_save(void) {
    gsize ptsize = 0;
    g_autofree gchar *plaintext = \
        get_text_view_text(text_enc_objs.ptext_view, &ptsize);
    text_enc_save(plaintext, ptsize);
}

static void text_enc_cipher_import(void) {
    gsize size = 0;
    g_autofree gchar *data = text_enc_read_file(&size);
    if (data == NULL) {
        return;
    }
    wrap_base64(&data, BASE64_TEXTVIEW_COLS);
    set_text_view_text(text_enc_objs.ctext_view, data, -1);
}

static void text_enc_cipher_copy(void) {
    gsize ctsize = 0;
    g_autofree gchar *ciphertext = get_text_view_text(
        text_enc_objs.ctext_view,
        &ctsize
    );
    wrap_base64(&ciphertext, BASE64_OUTPUT_COLS);
    text_enc_copy(ciphertext, -1);
}

static void text_enc_cipher_save(void) {
    gsize ctsize = 0;
    g_autofree gchar *ciphertext = \
        get_text_view_text(text_enc_objs.ctext_view, &ctsize);
    wrap_base64(&ciphertext, BASE64_OUTPUT_COLS);
    text_enc_save(ciphertext, strlen(ciphertext));
}

static void init_text_enc_tab(GtkWidget *notebook) {
    GtkWidget *tab_label = gtk_label_new("Encriptar texto");
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);

    GtkWidget *left_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *ptext_label = gtk_label_new("Texto plano");
    GtkWidget *ptext_scroll = gtk_scrolled_window_new(NULL, NULL);
    GtkWidget *ptext_view = gtk_text_view_new();
    GtkWidget *enc_grid = gtk_grid_new();
    GtkWidget *enc_button = gtk_button_new_with_label("Encriptar");
    GtkWidget *enc_import = gtk_button_new_with_label("Importar");
    GtkWidget *enc_copy = gtk_button_new_with_label("Copiar");
    GtkWidget *enc_save = gtk_button_new_with_label("Guardar");

    GtkWidget *right_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *ctext_label = gtk_label_new("Texto cifrado (base64)");
    GtkWidget *ctext_scroll = gtk_scrolled_window_new(NULL, NULL);
    GtkWidget *ctext_view = gtk_text_view_new();
    GtkWidget *dec_grid = gtk_grid_new();
    GtkWidget *dec_button = gtk_button_new_with_label("Desencriptar");
    GtkWidget *dec_import = gtk_button_new_with_label("Importar");
    GtkWidget *dec_copy = gtk_button_new_with_label("Copiar");
    GtkWidget *dec_save = gtk_button_new_with_label("Guardar");

    gtk_widget_set_valign(box, GTK_ALIGN_CENTER);

    gtk_container_add(GTK_CONTAINER(ptext_scroll), ptext_view);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(ptext_view), GTK_WRAP_WORD_CHAR);
    gtk_widget_set_size_request(ptext_scroll, 250, 100);
    gtk_grid_set_column_homogeneous(GTK_GRID(enc_grid), TRUE);
    gtk_grid_attach(GTK_GRID(enc_grid), enc_button, 1, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(enc_grid), enc_import, 2, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(enc_grid), enc_copy, 1, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(enc_grid), enc_save, 2, 2, 1, 1);

    gtk_container_add(GTK_CONTAINER(ctext_scroll), ctext_view);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(ctext_view), GTK_WRAP_WORD_CHAR);
    gtk_widget_set_size_request(ctext_scroll, 250, 100);
    gtk_grid_set_column_homogeneous(GTK_GRID(dec_grid), TRUE);
    gtk_grid_attach(GTK_GRID(dec_grid), dec_button, 1, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(dec_grid), dec_import, 2, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(dec_grid), dec_copy, 1, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(dec_grid), dec_save, 2, 2, 1, 1);

    gtk_box_pack_start(GTK_BOX(left_box), ptext_label, FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(left_box), ptext_scroll, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(left_box), enc_grid, TRUE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(right_box), ctext_label, FALSE, FALSE, 5);
    gtk_box_pack_start(GTK_BOX(right_box), ctext_scroll, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(right_box), dec_grid, TRUE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(box), left_box, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(box), right_box, TRUE, TRUE, 0);
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), box, tab_label);

    text_enc_objs.ptext_view = GTK_TEXT_VIEW(ptext_view);
    text_enc_objs.ctext_view = GTK_TEXT_VIEW(ctext_view);

    g_signal_connect_after(
        enc_button,
        "clicked",
        G_CALLBACK(text_enc_button_clicked),
        NULL
    );
    g_signal_connect_after(
        dec_button,
        "clicked",
        G_CALLBACK(text_dec_button_clicked),
        NULL
    );

    g_signal_connect_after(
        enc_import,
        "clicked",
        G_CALLBACK(text_enc_plain_import),
        NULL
    );
    g_signal_connect_after(
        dec_import,
        "clicked",
        G_CALLBACK(text_enc_cipher_import),
        NULL
    );

    g_signal_connect(
        enc_copy,
        "clicked",
        text_enc_plain_copy,
        NULL
    );
    g_signal_connect(
        enc_save,
        "clicked",
        text_enc_plain_save,
        NULL
    );

    g_signal_connect(
        dec_copy,
        "clicked",
        text_enc_cipher_copy,
        NULL
    );
    g_signal_connect(
        dec_save,
        "clicked",
        text_enc_cipher_save,
        NULL
    );
}

static void hide_widgets(void) {
    gtk_widget_hide(GTK_WIDGET(file_enc_objs.bottom_box));
}

static void init_app(GtkWidget *window) {
    GtkWidget *notebook = gtk_notebook_new();
    init_shared_objects(GTK_WINDOW(window));
    init_file_enc_tab(notebook);
    init_text_enc_tab(notebook);
    gtk_container_add(GTK_CONTAINER(window), notebook);
}

static void activate(GtkApplication *app) {
    GtkWidget *window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(window), "CCrypt");
    gtk_window_set_default_size(GTK_WINDOW(window), -1, -1);
    gtk_window_set_resizable(GTK_WINDOW(window), FALSE);
    gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER);

    init_app(window);

    gtk_widget_show_all(window);
    hide_widgets();
}

int init_gui(int argc, char **argv) {
    GtkApplication *app;
    int status;

    gtk_init(&argc, &argv);
    app = gtk_application_new("org.ccrypt.gccrypt", G_APPLICATION_FLAGS_NONE);
    g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);
    status = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);

    return status;
}
