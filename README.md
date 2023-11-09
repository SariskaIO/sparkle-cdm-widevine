# sparkle-cdm-widevine

This is an OpenCDM module for [Sparkle CDM](https://github.com/Sparkle-CDM/sparkle-cdm)
for Linux systems that wraps the Widevine L3 blob downloaded by Firefox and
Chromium browsers. It is intended to be used with a GStreamer pipeline to play
back protected media.

By default it will look for the library in the environment variable
`$WIDEVINE_CDM_BLOB` or somewhere within your Firefox or Chromium home
directory (`$HOME/.mozilla/firefox/` and `$XDG_CONFIG_DIR/.chromium/`),
whichever comes first. Finally, it will check for `"libwidevinecdm"` using the
rules specified in
[`g_module_open_full()`](https://docs.gtk.org/gmodule/type_func.Module.open_full.html).
