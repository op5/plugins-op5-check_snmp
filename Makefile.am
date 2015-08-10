libexec_PROGRAMS=\
	src/check_snmp_disk \
	src/check_snmp_cpu \
	src/check_snmp_memory \
	src/check_snmp_procs

AM_CPPFLAGS = -DNP_STATE_DIR_PREFIX=\"$(localstatedir)\"
LIBS = $(SNMPLIBS)
COMMON_SOURCES = \
	src/utils_base.c src/utils_base.h \
	src/utils.c src/utils.h \
	src/sha1.c src/sha1.h \
	src/utils_snmp.c src/utils_snmp.h \
	src/common.h

src_check_snmp_disk_SOURCES=\
	src/check_snmp_disk.c \
	$(COMMON_SOURCES)
	
src_check_snmp_cpu_SOURCES=\
	src/check_snmp_cpu.c \
	$(COMMON_SOURCES)

src_check_snmp_memory_SOURCES=\
	src/check_snmp_memory.c \
	$(COMMON_SOURCES)

src_check_snmp_procs_SOURCES=\
	src/check_snmp_procs.c \
	$(COMMON_SOURCES)
src_check_snmp_procs_LDADD=\
	$(naemon_LIBS)
src_check_snmp_procs_CFLAGS=\
	$(naemon_CFLAGS)

check:
	phpunit $(top_srcdir)/test/
