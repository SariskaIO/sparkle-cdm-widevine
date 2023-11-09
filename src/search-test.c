#include <glib.h>
#include <gio/gio.h>

#include "search.h"

static void
test_firefox (void)
{
  g_autoptr(GError) error = NULL;
  g_autofree gchar *cdm_path = NULL;
  g_autofree gchar *root =
      g_strdup_printf ("%s/.mozilla/firefox", g_get_home_dir ());
  find_firefox_cdm (root, &cdm_path, NULL, &error);
  g_assert_no_error (error);
  g_assert (cdm_path);
}

static void
test_chromium (void)
{
  g_autoptr(GError) error = NULL;
  g_autofree gchar *cdm_path = NULL;
  g_autofree gchar *root =
      g_strdup_printf ("%s/.config/chromium", g_get_home_dir ());
  find_chromium_cdm (root, &cdm_path, NULL, &error);
  g_assert_no_error (error);
  g_assert (cdm_path);
}

gint
main (gint argc, gchar **argv)
{
  test_firefox ();
  test_chromium ();
  return 0;
}
