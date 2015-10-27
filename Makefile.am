AM_CPPFLAGS = -DNP_STATE_DIR_PREFIX=\"$(localstatedir)\" -D_GNU_SOURCE=1
AM_CPPFLAGS += @AM_CPPFLAGS@
AM_CFLAGS = @AM_CFLAGS@
ALL_CFLAGS = $(AM_CFLAGS) $(AM_CPPFLAGS)

libexec_PROGRAMS=\
	src/check_snmp_disk \
	src/check_snmp_cpu \
	src/check_snmp_load_avg \
	src/check_snmp_memory \
	src/check_snmp_procs

LIBS = $(SNMPLIBS)
COMMON_SOURCES = \
	src/utils_base.c src/utils_base.h \
	src/utils.c src/utils.h \
	src/sha1.c src/sha1.h \
	src/utils_snmp.c src/utils_snmp.h \
	src/rbtree.c src/rbtree.h \
	src/common.h

TAPSOURCES = $(COMMON_SOURCES) tap/tap.c
TAPCPPFLAGS = $(ALL_CFLAGS) $(CPPFLAGS) -I$(abs_srcdir)/tap

src_check_snmp_disk_SOURCES=\
	src/check_snmp_disk.c \
	$(COMMON_SOURCES)

src_check_snmp_cpu_SOURCES=\
	src/check_snmp_cpu.c \
	$(COMMON_SOURCES)

src_check_snmp_load_avg_SOURCES=\
	src/check_snmp_load_avg.c \
	$(COMMON_SOURCES)

src_check_snmp_memory_SOURCES=\
	src/check_snmp_memory.c \
	$(COMMON_SOURCES)

src_check_snmp_procs_SOURCES=\
	src/check_snmp_procs.c \
	$(COMMON_SOURCES)

check_PROGRAMS = \
	src/test/check_snmp_disk \
	src/test/check_snmp_cpu

src_test_check_snmp_cpu_SOURCES = src/test/check_snmp_cpu.c $(TAPSOURCES)
src_test_check_snmp_cpu_CPPFLAGS = $(TAPCPPFLAGS)
src_test_check_snmp_cpu_LDADD = $(TAPLDADD)

src_test_check_snmp_disk_SOURCES = src/test/check_snmp_disk.c $(TAPSOURCES)
src_test_check_snmp_disk_CPPFLAGS = $(TAPCPPFLAGS)
src_test_check_snmp_disk_LDADD = $(TAPLDADD)

check: $(check_PROGRAMS)
	@for i in $(check_PROGRAMS); do $$i; done
