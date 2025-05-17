#include <glib.h>
#include <gio/gio.h>

#define CDM_BLOB "libwidevinecdm.so"
#define ATTRS G_FILE_ATTRIBUTE_STANDARD_TYPE "," G_FILE_ATTRIBUTE_STANDARD_NAME

static GFileInfo *
next_dir (GFileEnumerator *cwd, GCancellable *cancellable, GError **error)
{
  while (!g_cancellable_is_cancelled (cancellable)) {
    g_autoptr(GFileInfo) info = g_file_enumerator_next_file (cwd, cancellable, error);
    if (error && *error) {
      return NULL;
    }
    if (info == NULL) {
      return NULL;
    }
    if (!g_file_info_has_attribute (info, G_FILE_ATTRIBUTE_STANDARD_TYPE)) {
      continue;
    }
    if (g_file_info_get_file_type (info) != G_FILE_TYPE_DIRECTORY) {
      continue;
    }
    return g_object_ref (info);
  }
  return NULL;
}

static gboolean
check_for_firefox_cdm_blob (GFile *cwd, GFile **cdm_blob, GCancellable *cancellable, GError **error)
{
  g_autoptr(GFileEnumerator) e = g_file_enumerate_children (cwd, ATTRS, (GFileQueryInfoFlags) 0, cancellable, error);
  while (!g_cancellable_is_cancelled (cancellable)) {
    g_autoptr(GFileInfo) info = next_dir(e, cancellable, error);
    if (info == NULL) {
      break;
    }
    g_autoptr(GFile) version_dir = g_file_get_child (cwd, g_file_info_get_name (info));
    g_autoptr(GFile) cdm = g_file_get_child (version_dir, CDM_BLOB);
    if (g_file_query_exists (cdm, cancellable)) {
      *cdm_blob = g_object_ref (cdm);
      return TRUE;
    }
  }
  return FALSE;
}

static gboolean
walk_firefox (GFile *cwd, guint depth, guint max_depth, GFile **cdm_path, GCancellable *cancellable, GError **error)
{
  if (depth >= max_depth) {
    return TRUE;
  }
  if (g_cancellable_is_cancelled (cancellable)) {
    return FALSE;
  }
  g_autoptr(GFileEnumerator) e = g_file_enumerate_children (cwd, ATTRS, (GFileQueryInfoFlags) 0, cancellable, error);
  if (error && *error) {
    return FALSE;
  }
  while (!g_cancellable_is_cancelled (cancellable)) {
    g_autoptr(GFileInfo) info = next_dir (e, cancellable, error);
    if (error && *error) {
      return FALSE;
    }
    if (info == NULL) {
      return TRUE;
    }

    const gchar *name = g_file_info_get_name (info);
    g_autoptr(GFile) dir = g_file_get_child (cwd, name);
    if (g_strcmp0 (name, "gmp-widevinecdm") == 0) {
      if (check_for_firefox_cdm_blob (dir, cdm_path, cancellable, error)) {
        return TRUE;
      }
    }
    if (!walk_firefox (dir, depth + 1, max_depth, cdm_path, cancellable, error)) {
      return FALSE;
    }
  }

  return FALSE;
}

static gboolean
walk_chrome (GFile *cwd, GFile **cdm_path, GCancellable *cancellable, GError **error)
{
  if (g_cancellable_is_cancelled (cancellable)) {
    return FALSE;
  }
  
  // Direct path for Chrome is /opt/google/chrome/WidevineCdm/_platform_specific/linux_x64/libwidevinecdm.so
  g_autoptr(GFile) widevine_dir = g_file_get_child (cwd, "WidevineCdm");
  if (!g_file_query_exists (widevine_dir, cancellable)) {
    g_debug ("Chrome WidevineCdm directory not found at %s", g_file_get_path (widevine_dir));
    return FALSE;
  }

  g_autoptr(GFile) platform_specific_dir = g_file_get_child (widevine_dir, "_platform_specific");
  if (!g_file_query_exists (platform_specific_dir, cancellable)) {
    g_debug ("Chrome _platform_specific directory not found at %s", g_file_get_path (platform_specific_dir));
    return FALSE;
  }

  g_autoptr(GFile) linux_x64_dir = g_file_get_child (platform_specific_dir, "linux_x64");
  if (!g_file_query_exists (linux_x64_dir, cancellable)) {
    g_debug ("Chrome linux_x64 directory not found at %s", g_file_get_path (linux_x64_dir));
    return FALSE;
  }

  g_autoptr(GFile) cdm_blob = g_file_get_child (linux_x64_dir, CDM_BLOB);
  if (!g_file_query_exists (cdm_blob, cancellable)) {
    g_debug ("Chrome CDM blob not found at %s", g_file_get_path (cdm_blob));
    return FALSE;
  }

  // Found the CDM
  g_debug ("Found Chrome CDM at %s", g_file_get_path (cdm_blob));
  *cdm_path = g_object_ref (cdm_blob);
  return TRUE;
}

gboolean
find_firefox_cdm (const gchar *root, gchar **cdm_path, GCancellable *cancellable, GError **error)
{
  g_autoptr(GFile) cdm_path_file = NULL;
  g_autoptr(GFile) root_file = g_file_new_for_path (root);
  if (!walk_firefox (root_file, 0, 2, &cdm_path_file, cancellable, error)) {
    return FALSE;
  }
  *cdm_path = g_file_get_path (cdm_path_file);
  return TRUE;
}

static gboolean
walk_chromium_platform_dir (GFile *cwd, GFile **cdm_blob, GCancellable *cancellable, GError **error)
{
  g_autoptr(GFileEnumerator) e = g_file_enumerate_children (cwd, ATTRS, (GFileQueryInfoFlags) 0, cancellable, error);
  if (error && *error) {
    return FALSE;
  }
  while (!g_cancellable_is_cancelled (cancellable)) {
    g_autoptr(GFileInfo) info = next_dir (e, cancellable, error);
    if (error && *error) {
      return FALSE;
    }
    if (info == NULL) {
      return TRUE;
    }
    const gchar *name = g_file_info_get_name (info);
    g_autoptr(GFile) dir = g_file_get_child (cwd, name);
    g_autoptr(GFile) cdm = g_file_get_child (dir, CDM_BLOB);
    if (g_file_query_exists (cdm, cancellable)) {
      *cdm_blob = g_object_ref (cdm);
      return TRUE;
    }
  }

  return FALSE;
}

static gboolean
check_for_chromium_cdm_blob (GFile *cwd, GFile **cdm_blob, GCancellable *cancellable, GError **error)
{
  g_autoptr(GFileEnumerator) e = g_file_enumerate_children (cwd, ATTRS, (GFileQueryInfoFlags) 0, cancellable, error);
  while (!g_cancellable_is_cancelled (cancellable)) {
    g_autoptr(GFileInfo) info = next_dir (e, cancellable, error);
    if (info == NULL) {
      return FALSE;
    }
    g_autoptr(GFile) version_dir = g_file_get_child (cwd, g_file_info_get_name (info));
    g_autoptr(GFile) platform_specific_dir = g_file_get_child (version_dir, "_platform_specific");
    if (walk_chromium_platform_dir (platform_specific_dir, cdm_blob, cancellable, error)) {
      return TRUE;
    }
  }
  return FALSE;
}

static gboolean
walk_chromium (GFile *cwd, GFile **cdm_path, GCancellable *cancellable, GError **error)
{
  if (g_cancellable_is_cancelled (cancellable)) {
    return FALSE;
  }
  g_autoptr(GFileEnumerator) e = g_file_enumerate_children (cwd, ATTRS, (GFileQueryInfoFlags) 0, cancellable, error);
  if (error && *error) {
    return FALSE;
  }
  while (!g_cancellable_is_cancelled (cancellable)) {
    g_autoptr(GFileInfo) info = next_dir (e, cancellable, error);
    if (error && *error) {
      return FALSE;
    }
    if (info == NULL) {
      return TRUE;
    }

    const gchar *name = g_file_info_get_name (info);
    g_autoptr(GFile) dir = g_file_get_child (cwd, name);
    if (g_strcmp0 (name, "WidevineCdm") == 0) {
      if (check_for_chromium_cdm_blob (dir, cdm_path, cancellable, error)) {
        return TRUE;
      }
    }
  }

  return FALSE;
}

gboolean
find_chromium_cdm (const gchar *root, gchar **cdm_path, GCancellable *cancellable, GError **error)
{
  g_autoptr(GFile) cdm_path_file = NULL;
  g_autoptr(GFile) root_file = g_file_new_for_path (root);
  if (!walk_chromium (root_file, &cdm_path_file, cancellable, error)) {
    return FALSE;
  }
  *cdm_path = g_file_get_path (cdm_path_file);
  return TRUE;
}
