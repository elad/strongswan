AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libcharon

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-pipe.la
else
plugin_LTLIBRARIES = libstrongswan-pipe.la
endif

libstrongswan_pipe_la_SOURCES = \
	pipe_plugin.h pipe_plugin.c \
	pipe_provider.h pipe_provider.c

libstrongswan_pipe_la_LDFLAGS = -module -avoid-version
