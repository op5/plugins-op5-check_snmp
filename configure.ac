AC_INIT([check_snmp], m4_esyscmd([./generate_version_number.sh]))
AM_INIT_AUTOMAKE([subdir-objects])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_RANLIB

AM_CPPFLAGS=""
PKG_CHECK_MODULES([naemon], [naemon])

# START SNMP STUFF
AC_PATH_PROG(NETSNMPCONFIG,net-snmp-config)
AC_ARG_WITH(net-snmp-config,
                ACX_HELP_STRING([--with-net-snmp-config=PATH],
                                        [sets path to the net-snmp-config executable]),
                        with_net_snmp_config=$withval,with_net_snmp_config=$NETSNMPCONFIG)
AC_SUBST(NETSNMPCONFIG, $with_net_snmp_config)
dnl Detect Net-SNMP
ac_save_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="$CPPFLAGS `$NETSNMPCONFIG --cflags`"
AC_CHECK_HEADERS(net-snmp/net-snmp-config.h)
if test "x$ac_cv_header_net_snmp_net_snmp_config_h" = "xyes"; then
        SNMPLIBS=`$NETSNMPCONFIG --libs`
        AC_DEFINE(HAVE_NET_SNMP, 1, [Define to enable support for Net-SNMP])
fi
CPPFLAGS=$ac_save_CPPFLAGS
AC_SUBST(SNMPLIBS)
# END SNMP STUFF

AX_CHECK_COMPILE_FLAG([-Wall], AM_CPPFLAGS+=" -Wall")
AX_CHECK_COMPILE_FLAG([-Werror], AM_CPPFLAGS+=" -Werror")

AC_SUBST([AM_CPPFLAGS])

AC_CONFIG_FILES([
	Makefile
	])
AC_OUTPUT
