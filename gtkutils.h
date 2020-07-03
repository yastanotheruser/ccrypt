#ifndef GTK_UTILS_H
#define GTK_UTILS_H

#include <gtk/gtk.h>

void show_message_dialog(
    GtkMessageType type,
    const gchar *message,
    GtkWindow *parent
);
gchar *get_text_view_text(GtkTextView *text_view, gsize *length_ptr);
void set_text_view_text(GtkTextView *text_view, const gchar *text, gssize size);
GFile *get_native_file(GtkFileChooserNative *native, const gchar *name);

#endif
