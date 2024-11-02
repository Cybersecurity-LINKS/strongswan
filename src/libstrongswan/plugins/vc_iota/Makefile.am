AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-vc-iota.la
else
plugin_LTLIBRARIES = libstrongswan-vc-iota.la
endif

libstrongswan_vc_iota_la_SOURCES = \
	vc_iota.h vc_iota.c \
	identity.h did_iota.h did_iota.c \
	vc_iota_plugin.h vc_iota_plugin.c 

libstrongswan_vc_iota_la_LDFLAGS = -module -avoid-version