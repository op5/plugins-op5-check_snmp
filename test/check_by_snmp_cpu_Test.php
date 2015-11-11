<?php
require_once('test_helper.php');
class Check_Snmp_Cpu_Test extends test_helper
{
	public $plugin = 'check_by_snmp_cpu';
	public $snmp_community = 'mycommunity';
	public $snmpdata = <<<EOF
.3.6.1.4.1.2021.10.1.5.1|2|2
1.3.6.1.4.1.2021.10.1.5.2|2|3
1.3.6.1.4.1.2021.10.1.5.3|2|0
1.3.6.1.4.1.2021.11.1.0|2|1
1.3.6.1.4.1.2021.11.2.0|4|systemStats
1.3.6.1.4.1.2021.11.3.0|2|0
1.3.6.1.4.1.2021.11.4.0|2|0
1.3.6.1.4.1.2021.11.5.0|2|75
1.3.6.1.4.1.2021.11.6.0|2|0
1.3.6.1.4.1.2021.11.7.0|2|152
1.3.6.1.4.1.2021.11.8.0|2|275
1.3.6.1.4.1.2021.11.9.0|2|0
1.3.6.1.4.1.2021.11.10.0|2|0
1.3.6.1.4.1.2021.11.11.0|2|99
1.3.6.1.4.1.2021.11.50.0|65|252827
1.3.6.1.4.1.2021.11.51.0|65|15711
1.3.6.1.4.1.2021.11.52.0|65|132929
1.3.6.1.4.1.2021.11.53.0|65|103504746
1.3.6.1.4.1.2021.11.54.0|65|23152
1.3.6.1.4.1.2021.11.55.0|65|0
1.3.6.1.4.1.2021.11.56.0|65|14750
1.3.6.1.4.1.2021.11.57.0|65|55333616
1.3.6.1.4.1.2021.11.58.0|65|9511986
1.3.6.1.4.1.2021.11.59.0|65|147516546
1.3.6.1.4.1.2021.11.60.0|65|270819396
1.3.6.1.4.1.2021.11.61.0|65|3314
1.3.6.1.4.1.2021.11.62.0|65|29110
1.3.6.1.4.1.2021.11.63.0|65|54902
1.3.6.1.4.1.2021.11.64.0|65|0

1.3.6.1.2.1.25.3.3.1.1.768|6|0.0
1.3.6.1.2.1.25.3.3.1.2.768|2|1

1.3.6.1.2.1.25.3.4.1.1.1025|2|1
1.3.6.1.2.1.25.3.4.1.1.1026|2|2
1.3.6.1.2.1.25.3.4.1.1.1027|2|3
1.3.6.1.2.1.25.3.6.1.1.1552|2|1
1.3.6.1.2.1.25.3.6.1.1.1553|2|1
1.3.6.1.2.1.25.3.6.1.2.1552|2|2
1.3.6.1.2.1.25.3.6.1.2.1553|2|2
1.3.6.1.2.1.25.3.6.1.3.1552|2|2
1.3.6.1.2.1.25.3.6.1.3.1553|2|2
EOF;

	public function setUp() {
		$this->snmp_community = md5(uniqid());
	}

/**
 * CPU testing needs to initialize a tempfile which is located in localstatedir,
 * to run local tests you can specify a custom dir with:
 * MP_STATE_PATH=/tmp/lalala
 * After running the tests you need to remove the tempfiles in order to re-run
 * the tests successfullly.
 */
	public function test_cpu_default_OK() {
		// First run, no inital database
		$this->assertCommand("-H @endpoint@ -C @community@", array(
			"1.3.6.1.4.1.2021.11.53.0" => array(65,103504746), /* idle */
			"1.3.6.1.4.1.2021.11.50.0" => array(65,252827) /* user */
		), array(
			"UNKNOWN: No previous state, initializing database. Re-run the plugin"
		), 3);

		// No new values since first execution
		$this->assertCommand("-H @endpoint@ -C @community@", array(
			"1.3.6.1.4.1.2021.11.53.0" => array(65,103504746),
			"1.3.6.1.4.1.2021.11.50.0" => array(65,252827)
		), array(
			"UNKNOWN: No difference in SNMP counters since first execution, please re-run the plugin in a few seconds"
		), 3);

		// Add some new values
		$this->assertCommand("-H @endpoint@ -C @community@", array(
			"1.3.6.1.4.1.2021.11.53.0" => array(65,103504746+1),
			"1.3.6.1.4.1.2021.11.50.0" => array(65,252827)
		), array(
			"OK: total CPU usage at 0.00% | total=0.00%;100.0;100.0 user=0.00% system=0.00% iowait=0.00% kernel=0.00% steal=0.00% nice=0.00% idle=100.00%"
		), 0);

		// Simulate retry before net-snmpd have updated the counters (reuse same values)
		$this->assertCommand("-H @endpoint@ -C @community@", array(
			"1.3.6.1.4.1.2021.11.53.0" => array(65,103504746+1),
			"1.3.6.1.4.1.2021.11.50.0" => array(65,252827)
		), array(
			"OK: total CPU usage at 0.00% | total=0.00%;100.0;100.0 user=0.00% system=0.00% iowait=0.00% kernel=0.00% steal=0.00% nice=0.00% idle=100.00%"
		), 0);


		// Update values, and verify that it saves the previous state, and uses new values
		$this->assertCommand("-H @endpoint@ -C @community@", array(
			"1.3.6.1.4.1.2021.11.53.0" => array(65,103504746+1),
			"1.3.6.1.4.1.2021.11.50.0" => array(65,252827+1)
		), array(
			"OK: total CPU usage at 100.00% | total=100.00%;100.0;100.0 user=100.00% system=0.00% iowait=0.00% kernel=0.00% steal=0.00% nice=0.00% idle=0.00%"
		), 0);
	}
	public function test_cpu_default_initial_WARNING() {
		$this->assertCommand("-H @endpoint@ -C @community@ -w 55: -c 90", array(
		), array(
			"UNKNOWN: No previous state, initializing database. Re-run the plugin"
		), 3);

		$this->assertCommand("-H @endpoint@ -C @community@ -w 55: -c 90", array(
			"1.3.6.1.4.1.2021.11.53.0" => array(65,103504746+1), /* last idle + 1 */
			"1.3.6.1.4.1.2021.11.50.0" => array(65,252827+1)  /* last sys + 1 */
		), array(
			"WARNING: total CPU usage at 50.00% | total=50.00%;55:;90 user=50.00% system=0.00% iowait=0.00% kernel=0.00% steal=0.00% nice=0.00% idle=50.00%"
		), 1);
	}
	public function test_cpu_default_initial_CRITICAL() {
		$this->assertCommand("-H @endpoint@ -C @community@ -w 55: -c~:90", array(
		), array(
			"UNKNOWN: No previous state, initializing database. Re-run the plugin"
		), 3);

		$this->assertCommand("-H @endpoint@ -C @community@ -w 55: -c~:90", array(
			"1.3.6.1.4.1.2021.11.50.0" => array(65,252827+1)  /* last usr + 1 */
		), array(
			"CRITICAL: total CPU usage at 100.00% | total=100.00%;55:;~:90 user=100.00% system=0.00% iowait=0.00% kernel=0.00% steal=0.00% nice=0.00% idle=0.00%"
		), 2);
	}
/**
 * Test some values for all perfdata
 */
	public function test_cpu_perfdata_same_amounts_of_ticks_initial_run_OK() {
		$this->assertCommand("-H @endpoint@ -C @community@ -w 50:90 -c 80:95", array(
		), array(
			"UNKNOWN: No previous state, initializing database. Re-run the plugin"
		), 3);

		$this->assertCommand("-H @endpoint@ -C @community@ -w 50:90 -c 80:95", array(
			"1.3.6.1.4.1.2021.11.50.0" => array(65,252827+1), /* user */
			"1.3.6.1.4.1.2021.11.51.0" => array(65,15711+1), /* nice */
			"1.3.6.1.4.1.2021.11.52.0" => array(65,132929+1), /* system */
			"1.3.6.1.4.1.2021.11.53.0" => array(65,103504746+1), /* idle */
			"1.3.6.1.4.1.2021.11.54.0" => array(65,23152+1), /* wait */
			"1.3.6.1.4.1.2021.11.55.0" => array(65,0), /* kernel */
			"1.3.6.1.4.1.2021.11.64.0" => array(65,0+1) /* steal */
		), array(
			"OK: total CPU usage at 83.33% | total=83.33%;50:90;80:95 user=16.67% system=16.67% iowait=16.67% kernel=0.00% steal=16.67% nice=16.67% idle=16.67%"
		), 0);
	}
	public function test_cpu_perfdata_initial_run_OK() {
		$this->assertCommand("-H @endpoint@ -C @community@ -w 50:95 -c 80:95", array(
		), array(
			"UNKNOWN: No previous state, initializing database. Re-run the plugin"
		), 3);

		$this->assertCommand("-H @endpoint@ -C @community@ -w 50:95 -c 80:95", array(
			"1.3.6.1.4.1.2021.11.50.0" => array(65,252827+1), /* user */
			"1.3.6.1.4.1.2021.11.51.0" => array(65,15711+2), /* nice */
			"1.3.6.1.4.1.2021.11.52.0" => array(65,132929+3), /* system */
			"1.3.6.1.4.1.2021.11.53.0" => array(65,103504746+4), /* idle */
			"1.3.6.1.4.1.2021.11.54.0" => array(65,23152+5), /* wait */
			"1.3.6.1.4.1.2021.11.55.0" => array(65,0), /* kernel */
			"1.3.6.1.4.1.2021.11.64.0" => array(65,0+6) /* steal */
		), array(
			"OK: total CPU usage at 80.95% | total=80.95%;50:95;80:95 user=4.76% system=14.29% iowait=23.81% kernel=0.00% steal=28.57% nice=9.52% idle=19.05%"
		), 0);
	}
/**
 * Test check on all perfdata
 */
	public function test_cpu_initial_run_UNKNOWN() {
		$this->assertCommand("-H @endpoint@ -C @community@ -T user -w 90 -c 95", array(
		), array(
			"UNKNOWN: No previous state, initializing database. Re-run the plugin"
		), 3);
		$this->assertCommand("-H @endpoint@ -C @community@ -T user -w 90 -c 95", array(
		), array(
			"UNKNOWN: No difference in SNMP counters since first execution, please re-run the plugin in a few seconds"
		), 3);

		$this->assertCommand("-H @endpoint@ -C @community@ -T user -w 90 -c 95", array(
			"1.3.6.1.4.1.2021.11.50.0" => array(65,252827+1), /* user */
			"1.3.6.1.4.1.2021.11.53.0" => array(65,103504746+1), /* idle */
		), array(
			"OK: user CPU usage at 50.00% | total=50.00% user=50.00%;90;95 system=0.00% iowait=0.00% kernel=0.00% steal=0.00% nice=0.00% idle=50.00%"
		), 0);

		$this->assertCommand("-H @endpoint@ -C @community@ -T user -w 90 -c 95", array(
			"1.3.6.1.4.1.2021.11.50.0" => array(65,252828+1), /* user */
			"1.3.6.1.4.1.2021.11.51.0" => array(65,15711+1), /* nice */
			"1.3.6.1.4.1.2021.11.53.0" => array(65,103504747+2), /* idle */
		), array(
			"OK: user CPU usage at 25.00% | total=50.00% user=25.00%;90;95 system=0.00% iowait=0.00% kernel=0.00% steal=0.00% nice=25.00% idle=50.00%"
		), 0);
	}
/**
 * Could not fetch the values
 */
	public function test_cpu_could_not_fetch_the_value_UNKNOWN() {
		$this->assertCommandIncorrectSnmp("-H @endpoint@ -C @community@", array(
			"UNKNOWN: Could not fetch the values at .1.3.6.1.4.1.2021.11. Please check your config file for SNMP and make sure you have access"
		), 3);
	}
/**
 * No arguments, usage and help
 */
	public function test_no_arguments() {
		$this->assertCommand("", array(
		), array(
			'check_by_snmp_cpu: Could not parse arguments',
			'Usage:',
			'check_by_snmp_cpu -H <ip_address> -C <snmp_community>',
			'[-w <warn_range>] [-c <crit_range>] [-t <timeout>] [-T <type>]',
			'([-P snmp version] [-N context] [-L seclevel] [-U secname]',
			'[-a authproto] [-A authpasswd] [-x privproto] [-X privpasswd])'
		), 3);
	}
	public function disable_test_help() {
		$this->assertCommand("-h", array(
		), array(
			''
		), 0);
	}
}
