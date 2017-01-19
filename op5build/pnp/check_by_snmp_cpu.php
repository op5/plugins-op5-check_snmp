<?php
#
# Copyright (c) 2006-2010 Joerg Linge (http://www.pnp4nagios.org)
#
# Define some colors ..
#
$_WARNRULE = '#FFFF00';
$_CRITRULE = '#FF0000';
$color_list = array(
	1  => "#e382ffff", // Grey
	2  => "#674ea7ff", // Black
	3  => "#8FCB7F", // Green
	4  => "#3BA2C6", // Blue
	5  => "#1A262C", // Dark grey
	6  => "#F37A20", // Orange
);
#
# The graph showing thresholds goes into $def[1]
# The rest of them except for total and idle goes into $def[2]
#
$opt[1] = '';
$opt[2] = '--vertical-label Percent ' .
          '--title "CPU usage" -u 100 -l 0 ' .
          '--border 0';
$ds_name[1] = '';
$ds_name[2] = '';
$def[1] = '';
$def[2] = '';
$coloridx = 1;
for($i=1; $i <= sizeof($DS); $i++) {
	$maximum  = "";
	$minimum  = "";
	$critical = "";
	$crit_min = "";
	$crit_max = "";
	$warning  = "";
	$warn_max = "";
	$warn_min = "";

	if (is_numeric($WARN[$i]) ){
		$warning = $WARN[$i];
	}
	if (is_numeric($WARN_MAX[$i]) ) {
		$warn_max = $WARN_MAX[$i];
	}
	if (is_numeric($WARN_MIN[$i]) ) {
		$warn_min = $WARN_MIN[$i];
	}
	if (is_numeric($CRIT[$i]) ) {
		$critical = $CRIT[$i];
	}
	if (is_numeric($CRIT_MAX[$i]) ) {
		$crit_max = $CRIT_MAX[$i];
	}
	if (is_numeric($CRIT_MIN[$i]) ) {
		$crit_min = $CRIT_MIN[$i];
	}
	if (is_numeric($MIN[$i]) ) {
		$minimum = $MIN[$i];
	}
	if (is_numeric($MAX[$i]) ) {
		$maximum = $MAX[$i];
	}

	if ($coloridx == count($color_list)) {
		$coloridx = 1;
	} else {
		$coloridx++;
	}
	if ((isset($WARN[$i]) && $WARN[$i] != "") ||
	    (isset($CRIT[$i]) && $CRIT[$i] != ""))
	{
		$ds_name[1] .= $LABEL[$i];
		$opt[1] .= '--vertical-label Percent ' .
		           '--title "CPU ' . $LABEL[$i] . ' usage" -u 100 -l 0 ' .
		           '--border 0';
		$def[1] .=  rrd::def("var1", $RRDFILE[$i], $DS[$i], "AVERAGE");
		$def[1] .=  rrd::gradient("var1", '#2f809c', $color_list[4],
		            ucfirst($LABEL[$i]), 12);
		$def[1] .=  rrd::gprint("var1", array("LAST", "MIN", "MAX", "AVERAGE"),
		            "%4.0lf" . "%%");
		$def[1] .=  rrd::line1("var1", "#000000");

		if ($warning != "") {
			$def[1] .= rrd::hrule($warning, $_WARNRULE, "Warning  $warning \\n");
		}
		if ($warn_min != "") {
			$def[1] .= rrd::hrule($warn_min, $_WARNRULE, "Warning  (min)  $warn_min \\n");
		}
		if ($warn_max != "") {
			$def[1] .= rrd::hrule($warn_max, $_WARNRULE, "Warning  (max)  $warn_max \\n");
		}
		if ($critical != "") {
			$def[1] .= rrd::hrule($critical, $_CRITRULE, "Critical $critical \\n");
		}
		if ($crit_min != "") {
			$def[1] .= rrd::hrule($crit_min, $_CRITRULE, "Critical (min)  $crit_min \\n");
		}
		if ($crit_max != "") {
			$def[1] .= rrd::hrule($crit_max, $_CRITRULE, "Critical (max)  $crit_max MiB\\n");
		}
	}

	if ((isset($LABEL[$i]) && $LABEL[$i] != "idle") &&
	    (isset($LABEL[$i]) && $LABEL[$i] != "total"))
	{
		$ds_name[2] .= $LABEL[$i] . " ";
		$def[2] .= rrd::def("var$i", $RRDFILE[$i], $DS[$i] , "AVERAGE") ;
		$def[2] .= rrd::area("var$i", $color_list[$coloridx],
		           rrd::cut(ucfirst($LABEL[$i]),12), 'STACK' );
		$def[2] .= rrd::gprint("var$i", array('LAST', 'MIN', 'MAX', 'AVERAGE'),
		           "%4.0lf" . "%%");
	}
}
?>
