<?php
#
# The graph showing thresholds goes into $def[1]
# The rest of them except for total and idle goes into $def[2]
#
$color_list = array(
	1  => "#e382ffff", // Grey
	2  => "#674ea7ff", // Black
	3  => "#8FCB7F", // Green
	4  => "#3BA2C6", // Blue
	5  => "#1A262C", // Dark grey
	6  => "#F37A20", // Orange
);
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

		$def[1] .= rrd::hrule($WARN[$i], "#FFFF00", "Warning  " . $WARN[$i] .
		           "%\\n");
		$def[1] .= rrd::hrule($CRIT[$i], "#FF0000", "Critical " . $CRIT[$i] .
		           "%\\n");
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
