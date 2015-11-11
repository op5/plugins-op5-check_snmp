<?php
#
# The graph showing thresholds goes into $def[1]
# The rest of them except for total and idle goes into $def[2]
#
$color_list = array(
	1  => "#5C74D5", // Blue
	2  => "#BD5CD5", // Purple
	3  => "#D55C99", // Red
	4  => "#0F0551", // Grey
	5  => "#D5A15C", // Brown
	6  => "#5CD58C", // Green
);

$BYTEPREFIX = 1048576; // 1024*1024=>MiB
$opt[1] = '--vertical-label Byte ' .
          '--title "Memory usage" ' .
          '--border 0' .
          '--slope-mode --units-exponent 9 -l 0 --base 1024';
$opt[2] = $opt[1];
$ds_name[1] = '';
$ds_name[2] = '';
$def[1] = '';
$def[2] = '';
$coloridx = 0;
for($i=1; $i <= sizeof($DS); $i++) {
	if ($coloridx == count($color_list)) {
		$coloridx = 1;
	} else {
		$coloridx++;
	}

	if ((isset($LABEL[$i]) && $LABEL[$i] != "RAM Cached") &&
	    (isset($LABEL[$i]) && $LABEL[$i] != "RAM Buffered")) {
		if ($LABEL[$i] == "RAM Used" || $LABEL[$i] == "Swap Used")
			$coloridx = 1;
		if ($LABEL[$i] == "RAM Free" || $LABEL[$i] == "Swap Free")
			$coloridx = 6;
		$ds_name[1] .= $LABEL[$i] . " ";
		$def[1] .= rrd::def("var$i", $RRDFILE[$i], $DS[$i] , "AVERAGE") ;
		$def[1] .= rrd::cdef("var_b$i", "var$i,1,*");
		$def[1] .= rrd::cdef("var_m$i", "var$i,$BYTEPREFIX,/");
		$def[1] .= rrd::area("var_b$i", "$color_list[$coloridx]70",
		           rrd::cut(ucfirst($LABEL[$i]),12), 'STACK' );
		$def[1] .= rrd::gprint("var_m$i", array('LAST', 'MIN', 'MAX', 'AVERAGE'),
		           "%2.0lf" . "MiB");
	} else {
		$coloridx--;
	}
	if ((isset($WARN[$i]) && $WARN[$i] != "") ||
	    (isset($CRIT[$i]) && $CRIT[$i] != ""))
	{
		$warning  = sprintf('%d', $WARN[$i] / $BYTEPREFIX);
		$critical = sprintf('%d', $CRIT[$i] / $BYTEPREFIX);
		$def[1] .= rrd::hrule($WARN[$i], "#FFFF00", "Warning  " . $warning .
		           "MiB\\n");
		$def[1] .= rrd::hrule($CRIT[$i], "#FF0000", "Critical " . $critical.
		           "MiB\\n");
	}
}
$coloridx = 0;
for($i=1; $i <= sizeof($DS); $i++) {
	if ($coloridx == count($color_list)) {
		$coloridx = 1;
	} else {
		$coloridx++;
	}
	if (isset($LABEL[$i]) && $LABEL[$i] != "RAM Free") {
		if ($LABEL[$i] == "RAM Used")
			$coloridx = 1;
		if ($LABEL[$i] == "RAM Cached")
			$coloridx = 5;
		if ($LABEL[$i] == "RAM Buffered")
			$coloridx = 2;
		$ds_name[2] .= $LABEL[$i] . " ";
		$def[2] .= rrd::def("var$i", $RRDFILE[$i], $DS[$i] , "AVERAGE") ;
		$def[2] .= rrd::cdef("var_b$i", "var$i,1,*");
		$def[2] .= rrd::cdef("var_m$i", "var$i,$BYTEPREFIX,/");
		$def[2] .= rrd::area("var_b$i", "$color_list[$coloridx]70",
		           rrd::cut(ucfirst($LABEL[$i]),12), 'STACK' );
		$def[2] .= rrd::gprint("var_m$i", array('LAST', 'MIN', 'MAX', 'AVERAGE'),
		           "%2.0lf" . "MiB");
	} else {
		$coloridx--;
	}
}
?>
