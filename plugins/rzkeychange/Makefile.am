MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CFLAGS = -I$(srcdir) \
    -I$(top_srcdir)/src \
    -I$(top_srcdir)/isc \
    $(SECCOMPFLAGS)

LIBRARY_VERSION=1

#if LDNS
pkglib_LTLIBRARIES = rzkeychange.la
rzkeychange_la_SOURCES = rzkeychange.c hashtbl.c
dist_rzkeychange_la_SOURCES = hashtbl.h
rzkeychange_la_LDFLAGS = -module # -version-info $(LIBRARY_VERSION)
rzkeychange_la_LIBADD = -lldns
#endif
