#include "gtkutils.h"
#include "lib/bytes.h"

void show_message_dialog(
    GtkMessageType type,
    const gchar *message,
    GtkWindow *parent
) {
    const gchar *text = NULL;
    switch (type) {
        case GTK_MESSAGE_INFO:
            text = "Información";
            break;
        case GTK_MESSAGE_WARNING:
            text = "Advertencia";
            break;
        case GTK_MESSAGE_ERROR:
            text = "Error";
            break;
        default:
            break;
    }

    GtkWidget *error_dialog = gtk_message_dialog_new(
        parent,
        GTK_DIALOG_MODAL,
        type,
        GTK_BUTTONS_CLOSE,
        text
    );
    gtk_message_dialog_format_secondary_text(
        GTK_MESSAGE_DIALOG(error_dialog),
        message
    );

    gtk_dialog_run(GTK_DIALOG(error_dialog));
    gtk_widget_destroy(error_dialog);
}

gchar *get_text_view_text(GtkTextView *text_view, gsize *length_ptr) {
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(text_view);
    GtkTextIter start;
    GtkTextIter end;
    gchar *text = NULL;
    gtk_text_buffer_get_bounds(buffer, &start, &end);
    *length_ptr = gtk_text_iter_get_offset(&end) - gtk_text_iter_get_offset(&start);
    text = gtk_text_buffer_get_text(buffer, &start, &end, FALSE);
    return text;
}

void set_text_view_text(GtkTextView *text_view, const gchar *text, gssize size) {
    GtkTextBuffer *text_buffer = gtk_text_view_get_buffer(text_view);
    gtk_text_buffer_set_text(text_buffer, text, size);
}


GFile *get_native_file(GtkFileChooserNative *native, const gchar *name) {
    GtkFileChooserAction action = \
        gtk_file_chooser_get_action(GTK_FILE_CHOOSER(native));
    gint res = -1;
    if (
        name != NULL &&
        (
            action == GTK_FILE_CHOOSER_ACTION_SAVE ||
            action == GTK_FILE_CHOOSER_ACTION_CREATE_FOLDER
        )
    ) {
        gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(native), "");
    }
    res = gtk_native_dialog_run(GTK_NATIVE_DIALOG(native));
    if (res != GTK_RESPONSE_ACCEPT) {
        return NULL;
    }
    return gtk_file_chooser_get_file(GTK_FILE_CHOOSER(native));
}
