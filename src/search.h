#pragma once

#include <glib.h>
#include <gio/gio.h>

G_BEGIN_DECLS

G_GNUC_INTERNAL
gboolean find_firefox_cdm (const gchar *root, gchar **cdm_path, GCancellable *cancellable, GError **error);

G_GNUC_INTERNAL
gboolean find_chromium_cdm (const gchar *root, gchar **cdm_path, GCancellable *cancellable, GError **error);

G_GNUC_INTERNAL
gboolean find_chrome_cdm (const gchar *root, gchar **cdm_path, GCancellable *cancellable, GError **error);

G_END_DECLS
