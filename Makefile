MODULE_big = sslutils
OBJS = sslutils.o
DATA_built = sslutils.sql uninstall_sslutils.sql
DATA = sslutils--1.1.sql sslutils--unpackaged--1.0.sql sslutils--1.0--1.1.sql
SHLIB_LINK += -lcrypto -lssl

EXTENSION = sslutils

ifndef USE_PGXS
top_builddir = ../..
makefile_global = $(top_builddir)/src/Makefile.global
ifeq "$(wildcard $(makefile_global))" ""
USE_PGXS = 1    # use pgxs if not in contrib directory
endif
endif

ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = contrib/$(MODULE_big)
include $(makefile_global)
include $(top_srcdir)/contrib/contrib-global.mk
endif

# remove dependency to libxml2, libxslt & libkrb5
LIBS := $(filter-out -lxml2, $(LIBS))
LIBS := $(filter-out -lxslt, $(LIBS))
LIBS := $(filter-out -lkrb5, $(LIBS))

