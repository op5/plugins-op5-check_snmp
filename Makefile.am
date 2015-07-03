libexec_PROGRAMS=\
	src/check_snmp_disk

AM_CPPFLAGS = -DNP_STATE_DIR_PREFIX=\"$(localstatedir)\"
AM_LDFLAGS = $(SNMPLIBS)

src_check_snmp_disk_SOURCES=\
	src/check_snmp_disk.c \
	src/utils_base.c src/utils_base.h \
	src/utils.c src/utils.h \
	src/sha1.c src/sha1.h \
	src/utils_snmp.c src/utils_snmp.h \
	src/common.h
