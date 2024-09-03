AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-ssi.la
else
plugin_LTLIBRARIES = libstrongswan-ssi.la
endif

libstrongswan_ssi_la_SOURCES = \
	ssi_vc.h ssi_vc.c \
	ssi_plugin.h ssi_plugin.c \
    ssi_did.h ssi_did.c

libstrongswan_ssi_la_LDFLAGS = -module -avoid-version