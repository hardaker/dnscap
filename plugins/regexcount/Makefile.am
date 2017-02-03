MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CFLAGS = -I$(srcdir) \
    -I$(top_srcdir)/src \
    -I$(top_srcdir)/isc \
    $(SECCOMPFLAGS)

pkglib_LTLIBRARIES = regexcount.la
regexcount_la_SOURCES = regexcount.c
regexcount_la_LDFLAGS = -module -avoid-version
