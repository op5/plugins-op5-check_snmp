<?php
require_once('test_helper.php');
class Check_Snmp_Load_Avg_Test extends test_helper
{
	public $plugin = 'check_by_snmp_load_avg';
	public function get_snmp_data() {
		$snmpdata = "1.3.6.1.4.1.2021.10.1.5.1|2|2
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
			1.3.6.1.2.1.25.3.6.1.3.1553|2|2";
		$snmpdata = preg_replace("#^\s+#", "", $snmpdata);
		return $snmpdata;
	}
	/**
	 * Testing load default
	 *
	 * @dataProvider snmpArgsProvider
	 */
	public function test_default_without_parameters($conn_args) {
		$this->assertCommand($conn_args, "", array(
			"1.3.6.1.4.1.2021.10.1.5.3" => array(2,4)
		), array(
			"OK: 1, 5, 15 min load average: 0.02, 0.03, 0.04 |'Load1'=0.02;; 'Load5'=0.03;; 'Load15'=0.04;;"
		), 0);
	}

	/**
	 * Load
	 *
	 * @dataProvider snmpArgsProvider
	 */
	public function test_load_default_OK($conn_args) {
		$this->assertCommand($conn_args, "-T load", array(
			"1.3.6.1.4.1.2021.10.1.5.3" => array(2,4)
		), array(
			"OK: 1, 5, 15 min load average: 0.02, 0.03, 0.04 |'Load1'=0.02;; 'Load5'=0.03;; 'Load15'=0.04;;"
		), 0);
	}

	/**
	 * @dataProvider snmpArgsProvider
	 */
	public function test_load_OK($conn_args) {
		$this->assertCommand($conn_args, "-T load -w 1.1,1.2,1.3 -c 2.1,2.2,2.3", array(
			"1.3.6.1.4.1.2021.10.1.5.3" => array(2,4)
		), array(
			"OK: 1, 5, 15 min load average: 0.02, 0.03, 0.04 |'Load1'=0.02;1.1;2.1 'Load5'=0.03;1.2;2.2 'Load15'=0.04;1.3;2.3"
		), 0);
	}

	/**
	 * @dataProvider snmpArgsProvider
	 */
	public function test_load_WARNING($conn_args) {
		$this->assertCommand($conn_args, "-T load -w 1.1,1.2,1.3 -c 2.1,2.2,2.3", array(
			"1.3.6.1.4.1.2021.10.1.5.1" => array(2,200)
		), array(
			"WARNING: 1, 5, 15 min load average: 2.00, 0.03, 0.00 |'Load1'=2.00;1.1;2.1 'Load5'=0.03;1.2;2.2 'Load15'=0.00;1.3;2.3"
		), 1);
	}

	/**
	 * @dataProvider snmpArgsProvider
	 */
	public function test_load_CRITICAL($conn_args) {
		$this->assertCommand($conn_args, "-T load -w 1.1,1.2,1.3 -c 2.1,2.2,2.3", array(
			"1.3.6.1.4.1.2021.10.1.5.2" => array(2,222)
		), array(
			"CRITICAL: 1, 5, 15 min load average: 0.02, 2.22, 0.00 |'Load1'=0.02;1.1;2.1 'Load5'=2.22;1.2;2.2 'Load15'=0.00;1.3;2.3"
		), 2);
	}

	/**
	 * Load thresholds with incorrect input
	 *
	 * @dataProvider snmpArgsProvider
	 */
	public function test_load_with_two_warning_and_critical_arguments($conn_args) {
		$this->assertCommand($conn_args, "-T load -w 1.1,1.2 -c 2.1,2.2", array(
			"1.3.6.1.4.1.2021.10.1.5.3" => array(2,4)
		), array(
			"OK: 1, 5, 15 min load average: 0.02, 0.03, 0.04 |'Load1'=0.02;1.1;2.1 'Load5'=0.03;1.2;2.2 'Load15'=0.04;;"
		), 0);
	}

	/**
	 * @dataProvider snmpArgsProvider
	 */
	public function test_load_uneven_amount_of_warning_and_critical_arguments($conn_args) {
		$this->assertCommand($conn_args, "-T load -w 1.1,1.2 -c 2.1", array(
			"1.3.6.1.4.1.2021.10.1.5.3" => array(2,4)
		), array(
			"OK: 1, 5, 15 min load average: 0.02, 0.03, 0.04 |'Load1'=0.02;1.1;2.1 'Load5'=0.03;1.2; 'Load15'=0.04;;"
		), 0);
	}

	/**
	 * @dataProvider snmpArgsProvider
	 */
	public function test_load_only_warning_arguments($conn_args) {
		$this->assertCommand($conn_args, "-T load -w 1.1,1.2,1.3", array(
			"1.3.6.1.4.1.2021.10.1.5.3" => array(2,4)
		), array(
			"OK: 1, 5, 15 min load average: 0.02, 0.03, 0.04 |'Load1'=0.02;1.1; 'Load5'=0.03;1.2; 'Load15'=0.04;1.3;"
		), 0);
	}

	/**
	 * @dataProvider snmpArgsProvider
	 */
	public function test_load_only_critical_arguments($conn_args) {
		$this->assertCommand($conn_args, "-T load -c 2.1,2.2,2.3", array(
			"1.3.6.1.4.1.2021.10.1.5.3" => array(2,4)
		), array(
			"OK: 1, 5, 15 min load average: 0.02, 0.03, 0.04 |'Load1'=0.02;;2.1 'Load5'=0.03;;2.2 'Load15'=0.04;;2.3"
		), 0);
	}

	/**
	 * @dataProvider snmpArgsProvider
	 */
	public function test_load_too_many_warning_arguments($conn_args) {
		$this->assertCommand($conn_args, "-T load -w 1.1,1.2,1.3,1.4 -c 2.1,2.2,2.3", array(
			"1.3.6.1.4.1.2021.10.1.5.3" => array(2,4)
		), array(
			"Too many arguments for warning and critical thresholds"
		), 3);
	}

	/**
	 * @dataProvider snmpArgsProvider
	 */
	public function test_load_too_many_critical_arguments($conn_args) {
		$this->assertCommand($conn_args, "-T load -w 1.1,1.2,1.3 -c 2.1,2.2,2.3,2.4", array(
			"1.3.6.1.4.1.2021.10.1.5.3" => array(2,4)
		), array(
			"Too many arguments for warning and critical thresholds"
		), 3);
	}

	/**
	 * Could not fetch the values
	 *
	 * @dataProvider snmpArgsProvider
	 */
	public function test_load_could_not_fetch_the_value_for_load1_UNKNOWN($conn_args) {
		$this->assertCommand($conn_args, "-T load", array(
			"1.3.6.1.4.1.2021.10.1.5.1" => array(2,"")
		), array(
			"UNKNOWN: Could not fetch the values at 1.3.6.1.4.1.2021.10.1.5. Please check your config file for SNMP and make sure you have access"
		), 3);
	}

	/**
	 * @dataProvider snmpArgsProvider
	 */
	public function test_load_could_not_fetch_the_value_for_load5_UNKNOWN($conn_args) {
		$this->assertCommand($conn_args, "-T load", array(
			"1.3.6.1.4.1.2021.10.1.5.2" => array(2,"")
		), array(
			"UNKNOWN: Could not fetch the values at 1.3.6.1.4.1.2021.10.1.5. Please check your config file for SNMP and make sure you have access"
		), 3);
	}

	/**
	 * @dataProvider snmpArgsProvider
	 */
	public function test_load_could_not_fetch_the_value_for_load15_UNKNOWN($conn_args) {
		$this->assertCommand($conn_args, "-T load", array(
			"1.3.6.1.4.1.2021.10.1.5.3" => array(2,"")
		), array(
			"UNKNOWN: Could not fetch the values at 1.3.6.1.4.1.2021.10.1.5. Please check your config file for SNMP and make sure you have access"
		), 3);
	}

	/**
	 * No arguments, usage and help
	 */
	public function test_no_arguments() {
		$this->assertCommand("", "", array(
		), array(
			'check_by_snmp_load_avg: Could not parse arguments',
			'Usage:',
			'check_by_snmp_load_avg [-w <warn_range>] [-c <crit_range>] [-T <type>]',
			$this->snmp_usage,
		), 3);
	}
}
