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
# gprint uses a function to convert bytes to a human readable form, hrule does
# not have this functionality so implementing that type of function here.
# gprint uses SI units with base 1000 so use it here as well instead of 1024.
#
function bytes_to_string($bytes) {
	$units = array("B", "kB", "MB", "GB", "TB", "PB");
	$bytes = (float)$bytes;
	$pow = 0;
	while($bytes >= 1000.0 && isset($units[$pow+1])) {
		$pow++;
		$bytes /= 1000.0;
	}
	return sprintf("%8.3f %s",$bytes, $units[$pow]);
}

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
		$vlabel = "Percent";
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
	$def[$KEY] .= rrd::gprint("var1", array("LAST","MAX","AVERAGE"), "%8.3lf %S".$VAL['UNIT']);

	if ($warning != "") {
		$def[$KEY] .= rrd::hrule($warning, $_WARNRULE, sprintf("Warning  %s \\n", bytes_to_string($warning)));
	}
	if ($warn_min != "") {
		$def[$KEY] .= rrd::hrule($warn_min, $_WARNRULE, sprintf("Warning  (min) %s \\n", bytes_to_string($warn_min)));
	}
	if ($warn_max != "") {
		$def[$KEY] .= rrd::hrule($warn_max, $_WARNRULE, sprintf("Warning  (max) %s \\n", bytes_to_string($warn_max)));
	}
	if ($critical != "") {
		$def[$KEY] .= rrd::hrule($critical, $_CRITRULE, sprintf("Critical %s \\n", bytes_to_string($critical)));
	}
	if ($crit_min != "") {
		$def[$KEY] .= rrd::hrule($crit_min, $_CRITRULE, sprintf("Critical (min) %s \\n", bytes_to_string($crit_min)));
	}
	if ($crit_max != "") {
		$def[$KEY] .= rrd::hrule($crit_max, $_CRITRULE, sprintf("Critical (max) %s\\n", bytes_to_string($crit_max)));
	}
	$def[$KEY] .= rrd::comment("SNMP Disk Template\\r");
	$def[$KEY] .= rrd::comment("Command " . $VAL['TEMPLATE'] . "\\r");
}
