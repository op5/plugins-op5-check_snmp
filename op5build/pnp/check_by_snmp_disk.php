<?php
#
# Copyright (c) 2006-2010 Joerg Linge (http://www.pnp4nagios.org)
# Default Template used if no other template is found.
# Don`t delete this file ! 
#
# Define some colors ..
#
$_WARNRULE = '#FFFF00';
$_CRITRULE = '#FF0000';
$_AREA     = '#256aef';
$_LINE     = '#000000';
$color_list = array(
	1  => "#5C74D5", // Blue
	2  => "#BD5CD5", // Purple
	3  => "#D55C99", // Red
	4  => "#0F0551", // Grey
	5  => "#D5A15C", // Brown
	6  => "#5CD58C", // Green
);
#
# Initial Logic ...
#

foreach ($this->DS as $KEY=>$VAL) {

	$maximum  = "";
	$minimum  = "";
	$critical = "";
	$crit_min = "";
	$crit_max = "";
	$warning  = "";
	$warn_max = "";
	$warn_min = "";
	$vlabel   = " ";
	$lower    = "";
	$upper    = "";
	
	if ($VAL['WARN'] != "" && is_numeric($VAL['WARN']) ){
		$warning = $VAL['WARN'];
	}
	if ($VAL['WARN_MAX'] != "" && is_numeric($VAL['WARN_MAX']) ) {
		$warn_max = $VAL['WARN_MAX'];
	}
	if ( $VAL['WARN_MIN'] != "" && is_numeric($VAL['WARN_MIN']) ) {
		$warn_min = $VAL['WARN_MIN'];
	}
	if ( $VAL['CRIT'] != "" && is_numeric($VAL['CRIT']) ) {
		$upper = " --upper=" . ($VAL['CRIT'] + 1);
		$critical = $VAL['CRIT'];
	}
	if ( $VAL['CRIT_MAX'] != "" && is_numeric($VAL['CRIT_MAX']) ) {
		$crit_max = $VAL['CRIT_MAX'];
	}
	if ( $VAL['CRIT_MIN'] != "" && is_numeric($VAL['CRIT_MIN']) ) {
		$crit_min = $VAL['CRIT_MIN'];
	}
	if ( $VAL['MIN'] != "" && is_numeric($VAL['MIN']) ) {
		$lower = " --lower=" . $VAL['MIN'];
		$minimum = $VAL['MIN'];
	}
	if ( $VAL['MAX'] != "" && is_numeric($VAL['MAX']) ) {
		$maximum = $VAL['MAX'];
	}
	if ($VAL['UNIT'] == "%%") {
		$vlabel = "%";
		$upper = " --upper=101 ";
		$lower = " --lower=0 ";
	}
	else {
		$vlabel = $VAL['UNIT'];
	}

	$opt[$KEY] = '--vertical-label "' . $vlabel . '" --title "' . $this->MACRO['DISP_HOSTNAME'] . ' / ' . $this->MACRO['DISP_SERVICEDESC'] . '"' . $upper . $lower;
	$ds_name[$KEY] = $VAL['LABEL'];
	$def[$KEY]  = rrd::def     ("var1", $VAL['RRDFILE'], $VAL['DS'], "AVERAGE");
	//$def[$KEY] .= rrd::line1   ("var1", $_LINE );
	$def[$KEY] .= rrd::cdef("var_b1", "var1,1,*");
	$def[$KEY] .= rrd::area("var_b1", "$color_list[6]70",
	           rrd::cut(ucfirst($ds_name[$KEY]),12), 'STACK' );
	$def[$KEY] .= rrd::gprint  ("var1", array("LAST","MAX","AVERAGE"), "%3.4lf %S".$VAL['UNIT']);

	if ($warning != "") {
		$def[$KEY] .= rrd::hrule($warning, $_WARNRULE, "Warning  $warning \\n");
	}
	if ($warn_min != "") {
		$def[$KEY] .= rrd::hrule($warn_min, $_WARNRULE, "Warning  (min)  $warn_min \\n");
	}
	if ($warn_max != "") {
		$def[$KEY] .= rrd::hrule($warn_max, $_WARNRULE, "Warning  (max)  $warn_max \\n");
	}
	if ($critical != "") {
		$def[$KEY] .= rrd::hrule($critical, $_CRITRULE, "Critical $critical \\n");
	}
	if ($crit_min != "") {
		$def[$KEY] .= rrd::hrule($crit_min, $_CRITRULE, "Critical (min)  $crit_min \\n");
	}
	if ($crit_max != "") {
		$def[$KEY] .= rrd::hrule($crit_max, $_CRITRULE, "Critical (max)  $crit_max MiB\\n");
	}
	$def[$KEY] .= rrd::comment("SNMP Disk Template\\r");
	$def[$KEY] .= rrd::comment("Command " . $VAL['TEMPLATE'] . "\\r");
}
?>
