AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-vc.la
else
plugin_LTLIBRARIES = libstrongswan-vc.la
endif

libstrongswan_vc_la_SOURCES = \
	vc.h vc.c \
	identity.h did_iota.h did_iota.c \
	vc_plugin.h vc_plugin.c 

libstrongswan_vc_la_LDFLAGS = -module -avoid-version