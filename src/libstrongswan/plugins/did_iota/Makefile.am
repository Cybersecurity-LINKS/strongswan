AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-did-iota.la
else
plugin_LTLIBRARIES = libstrongswan-did-iota.la
endif

libstrongswan_did_iota_la_SOURCES = \
	did_iota.h did_iota.c \
	did_iota_plugin.h did_iota_plugin.c

libstrongswan_did_iota_la_LDFLAGS = -module -avoid-version