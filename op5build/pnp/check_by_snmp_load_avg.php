<?php
#
# The graph showing thresholds goes into $def[1]
# The rest of them except for total and idle goes into $def[1]
#
$color_list = array(
	1  => "#5C74D5", // Blue
	2  => "#BD5CD5", // Purple
	3  => "#D55C99", // Red
	4  => "#0F0551", // Grey
	5  => "#D5A15C", // Brown
	6  => "#5CD58C", // Green
);

$opt[1] = '--vertical-label "System load" ' .
          '--title "System load" ' .
          '--border 0 ' .
          '--slope-mode -l 0';
$ds_name[1] = '';
$def[1] = '';
$coloridx = 1;
for($i=1; $i <= sizeof($DS); $i++) {
	if ($coloridx == count($color_list)) {
		$coloridx = 1;
	} else {
		$coloridx++;
	}

	if ((isset($LABEL[$i]) && $LABEL[$i] != "") ||
	    (isset($LABEL[$i]) && $LABEL[$i] != ""))
	{
		$ds_name[1] .= $LABEL[$i] . " ";
		$def[1] .= rrd::def("var$i", $RRDFILE[$i], $DS[$i] , "AVERAGE") ;
		$def[1] .= rrd::area("var$i", "#00000040");
		$def[1] .= rrd::line1("var$i", "$color_list[$coloridx]",
		           rrd::cut(ucfirst($LABEL[$i]),12), '' );
		$def[1] .= rrd::gprint("var$i", array('LAST', 'MIN', 'MAX', 'AVERAGE'),
		           "%4.0lf" . "");
	}
	if ((isset($WARN[$i]) && $WARN[$i] != "") ||
	    (isset($CRIT[$i]) && $CRIT[$i] != ""))
	{
		$def[1] .= rrd::hrule($WARN[$i], "#FFFF00", "Warning  " . $WARN[$i] .
		           "\\n");
		$def[1] .= rrd::hrule($CRIT[$i], "#FF0000", "Critical " . $CRIT[$i] .
		           "\\n");
	}
}
?>
