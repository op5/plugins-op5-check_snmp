<?php
class Check_Snmp_Load_Avg_Test extends PHPUnit_Framework_TestCase {

	private static $snmpsimroot = "/tmp/check_by_snmp_load_avg_test/";
	private $snmpsimroot_current = false;

	private function start_snmpsim($snmpdata) {
		if ($this->snmpsimroot_current !== false) {
			$this->stop_snmpsim();
		}
		$this->snmpsimroot_current = static::$snmpsimroot.md5(uniqid())."/";
		@mkdir($this->snmpsimroot_current, 0777, true);
		@mkdir($this->snmpsimroot_current."data", 0777, true);
		file_put_contents($this->snmpsimroot_current."data/mycommunity.snmprec", $snmpdata);

		$command="snmpsimd.py".
		" --daemonize".
		" --pid-file=".$this->snmpsimroot_current . "pidfile".
		" --agent-udpv4-endpoint=127.0.0.1:21161".
		" --device-dir=".$this->snmpsimroot_current . "data";
		system($command, $returnval);
	}

	private function stop_snmpsim() {
		if ($this->snmpsimroot_current === false) {
			return;
		}
		posix_kill(intval(file_get_contents($this->snmpsimroot_current . "pidfile")), SIGINT);
		$this->snmpsimroot_current = false;
	}

	public function tearDown() {
		$this->stop_snmpsim();
	}

	public function run_command($args, &$output, &$return) {
		$check_command = __DIR__ . "/../../../opt/plugins/check_by_snmp_load_avg";
		return exec($check_command . " " . $args, $output, $return);
	}

	private function generate_snmpdata($snmpdata_diff) {
		$snmpdata = <<<EOF
1.3.6.1.4.1.2021.10.1.5.1|2|2
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
		$snmpdata_arr = array();
		foreach( explode("\n", $snmpdata) as $line) {
			if($line == "")
				continue;
			list($oid, $type, $value) = explode("|", $line, 3);
			$snmpdata_arr[$oid] = array($type, $value);
		}

		foreach($snmpdata_diff as $oid => $newval) {
			if($newval === false)
				unset($snmpdata_arr[$oid]);
			else
				$snmpdata_arr[$oid] = $newval;
		}

		$out_snmpdata = array();
		foreach($snmpdata_arr as $oid => $valarr) {
			list($type, $value) = $valarr;
			$out_snmpdata[] = "$oid|$type|$value";
		}
		natsort($out_snmpdata);
		return implode("\n", $out_snmpdata)."\n";
	}

	public function assertCommand($args, $snmpdata_diff, $expectedoutput, $expectedreturn){
		$this->start_snmpsim($this->generate_snmpdata($snmpdata_diff));
		$this->run_command(str_replace("@endpoint@","127.0.0.1:21161",$args), $output, $return);

		if(is_array($expectedoutput))
			$expectedoutput = implode("\n", $expectedoutput)."\n";
		$output = implode("\n", $output)."\n";

		$this->assertEquals($expectedoutput, $output);
		$this->assertEquals($expectedreturn, $return);
	}
/**
 * Testing load default
 */
	public function test_default_without_parameters() {
		$this->assertCommand("-H @endpoint@ -C mycommunity", array(
			"1.3.6.1.4.1.2021.10.1.5.3" => array(2,4)
		), array(
			"OK: 1, 5, 15 min load average: 0.02, 0.03, 0.04 |'Load1'=0.02;; 'Load5'=0.03;; 'Load15'=0.04;;"
		), 0);
	}
/**
 * Load
 */
	public function test_load_default_OK() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -T load", array(
			"1.3.6.1.4.1.2021.10.1.5.3" => array(2,4)
		), array(
			"OK: 1, 5, 15 min load average: 0.02, 0.03, 0.04 |'Load1'=0.02;; 'Load5'=0.03;; 'Load15'=0.04;;"
		), 0);
	}
	public function test_load_OK() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -T load -w 1.1,1.2,1.3 -c 2.1,2.2,2.3", array(
			"1.3.6.1.4.1.2021.10.1.5.3" => array(2,4)
		), array(
			"OK: 1, 5, 15 min load average: 0.02, 0.03, 0.04 |'Load1'=0.02;1.1;2.1 'Load5'=0.03;1.2;2.2 'Load15'=0.04;1.3;2.3"
		), 0);
	}
	public function test_load_WARNING() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -T load -w 1.1,1.2,1.3 -c 2.1,2.2,2.3", array(
			"1.3.6.1.4.1.2021.10.1.5.1" => array(2,200)
		), array(
			"WARNING: 1, 5, 15 min load average: 2.00, 0.03, 0.00 |'Load1'=2.00;1.1;2.1 'Load5'=0.03;1.2;2.2 'Load15'=0.00;1.3;2.3"
		), 1);
	}
	public function test_load_CRITICAL() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -T load -w 1.1,1.2,1.3 -c 2.1,2.2,2.3", array(
			"1.3.6.1.4.1.2021.10.1.5.2" => array(2,222)
		), array(
			"CRITICAL: 1, 5, 15 min load average: 0.02, 2.22, 0.00 |'Load1'=0.02;1.1;2.1 'Load5'=2.22;1.2;2.2 'Load15'=0.00;1.3;2.3"
		), 2);
	}
/**
 * Load thresholds with incorrect input
 */
	public function test_load_with_two_warning_and_critical_arguments() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -T load -w 1.1,1.2 -c 2.1,2.2", array(
			"1.3.6.1.4.1.2021.10.1.5.3" => array(2,4)
		), array(
			"OK: 1, 5, 15 min load average: 0.02, 0.03, 0.04 |'Load1'=0.02;1.1;2.1 'Load5'=0.03;1.2;2.2 'Load15'=0.04;;"
		), 0);
	}
	public function test_load_uneven_amount_of_warning_and_critical_arguments() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -T load -w 1.1,1.2 -c 2.1", array(
			"1.3.6.1.4.1.2021.10.1.5.3" => array(2,4)
		), array(
			"OK: 1, 5, 15 min load average: 0.02, 0.03, 0.04 |'Load1'=0.02;1.1;2.1 'Load5'=0.03;1.2; 'Load15'=0.04;;"
		), 0);
	}
	public function test_load_only_warning_arguments() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -T load -w 1.1,1.2,1.3", array(
			"1.3.6.1.4.1.2021.10.1.5.3" => array(2,4)
		), array(
			"OK: 1, 5, 15 min load average: 0.02, 0.03, 0.04 |'Load1'=0.02;1.1; 'Load5'=0.03;1.2; 'Load15'=0.04;1.3;"
		), 0);
	}
	public function test_load_only_critical_arguments() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -T load -c 2.1,2.2,2.3", array(
			"1.3.6.1.4.1.2021.10.1.5.3" => array(2,4)
		), array(
			"OK: 1, 5, 15 min load average: 0.02, 0.03, 0.04 |'Load1'=0.02;;2.1 'Load5'=0.03;;2.2 'Load15'=0.04;;2.3"
		), 0);
	}
	public function test_load_too_many_warning_arguments() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -T load -w 1.1,1.2,1.3,1.4 -c 2.1,2.2,2.3", array(
			"1.3.6.1.4.1.2021.10.1.5.3" => array(2,4)
		), array(
			"Too many arguments for warning and critical thresholds"
		), 3);
	}
	public function test_load_too_many_critical_arguments() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -T load -w 1.1,1.2,1.3 -c 2.1,2.2,2.3,2.4", array(
			"1.3.6.1.4.1.2021.10.1.5.3" => array(2,4)
		), array(
			"Too many arguments for warning and critical thresholds"
		), 3);
	}
/**
 * Could not fetch the values
 */
	public function test_load_could_not_fetch_the_value_for_load1_UNKNOWN() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -T load", array(
			"1.3.6.1.4.1.2021.10.1.5.1" => array(2,"")
		), array(
			"UNKNOWN: Could not fetch the values at 1.3.6.1.4.1.2021.10.1.5. Please check your config file for SNMP and make sure you have access"
		), 3);
	}
	public function test_load_could_not_fetch_the_value_for_load5_UNKNOWN() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -T load", array(
			"1.3.6.1.4.1.2021.10.1.5.2" => array(2,"")
		), array(
			"UNKNOWN: Could not fetch the values at 1.3.6.1.4.1.2021.10.1.5. Please check your config file for SNMP and make sure you have access"
		), 3);
	}
	public function test_load_could_not_fetch_the_value_for_load15_UNKNOWN() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -T load", array(
			"1.3.6.1.4.1.2021.10.1.5.3" => array(2,"")
		), array(
			"UNKNOWN: Could not fetch the values at 1.3.6.1.4.1.2021.10.1.5. Please check your config file for SNMP and make sure you have access"
		), 3);
	}
/**
 * No arguments, usage and help
 */
	public function test_no_arguments() {
		$this->assertCommand("", array(
		), array(
			'check_by_snmp_load_avg: Could not parse arguments',
			'Usage:',
			'check_by_snmp_load_avg -H <ip_address> -C <snmp_community>',
			'[-w<warn_range>] [-c<crit_range>] [-t <timeout>] [-T <type>]',
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
