<?php
require_once('test_helper.php');
class Check_Snmp_Memory_Test extends test_helper
{
	public $plugin = 'check_by_snmp_memory';
	public $snmpdata = <<<EOF
1.3.6.1.4.1.2021.4.1.0|2|0
1.3.6.1.4.1.2021.4.2.0|4|swap
1.3.6.1.4.1.2021.4.3.0|2|1254392
1.3.6.1.4.1.2021.4.4.0|2|1188148
1.3.6.1.4.1.2021.4.5.0|2|603576
1.3.6.1.4.1.2021.4.6.0|2|93204
1.3.6.1.4.1.2021.4.11.0|2|1281352
1.3.6.1.4.1.2021.4.12.0|2|16000
1.3.6.1.4.1.2021.4.14.0|2|52856
1.3.6.1.4.1.2021.4.15.0|2|280968
1.3.6.1.4.1.2021.4.100.0|2|0
1.3.6.1.4.1.2021.4.101.0|4|
EOF;

	/**
	 * Memory testing
	 * Default values
	 *
	 * @dataProvider snmpArgsProvider
	 */
	public function test_default($conn_args) {
		$this->assertCommand($conn_args, "", array(
		), array(
			"OK: Used RAM: 29.25% (172.41MiB) of total 589.43MiB |'RAM Used'=180785152B;0;0;0;618061824 'RAM Buffered'=54124544B;;;0;618061824 'RAM Cached'=287711232B;;;0;618061824 'RAM Free'=437276672B;;;0;618061824"
		), 0);
	}

	/**
	 * @dataProvider snmpArgsProvider
	 */
	public function test_default_with_warn_crit_values($conn_args) {
		$this->assertCommand($conn_args, "-w 90 -c 95", array(
		), array(
			"OK: Used RAM: 29.25% (172.41MiB) of total 589.43MiB |'RAM Used'=180785152B;556255641;587158732;0;618061824 'RAM Buffered'=54124544B;;;0;618061824 'RAM Cached'=287711232B;;;0;618061824 'RAM Free'=437276672B;;;0;618061824"
		), 0);
	}

	/**
	 * Ram used OK, WARNING, CRITICAL
	 *
	 * @dataProvider snmpArgsProvider
	 */
	public function test_option_used_warning_and_critical_OK($conn_args) {
		$this->assertCommand($conn_args, "-T ram_used -w 90 -c 95", array(
		), array(
			"OK: Used RAM: 29.25% (172.41MiB) of total 589.43MiB |'RAM Used'=180785152B;556255641;587158732;0;618061824 'RAM Buffered'=54124544B;;;0;618061824 'RAM Cached'=287711232B;;;0;618061824 'RAM Free'=437276672B;;;0;618061824"
		), 0);
	}

	/**
	 * @dataProvider snmpArgsProvider
	 */
	public function test_option_used_warning_and_critical_WARNING($conn_args) {
		$this->assertCommand($conn_args, "-T ram_used -w 20.50 -c 95.00 -m %", array(
		), array(
			"WARNING: Used RAM: 29.25% (172.41MiB) of total 589.43MiB |'RAM Used'=180785152B;126702673;587158732;0;618061824 'RAM Buffered'=54124544B;;;0;618061824 'RAM Cached'=287711232B;;;0;618061824 'RAM Free'=437276672B;;;0;618061824"
		), 1);
	}

	/**
	 * @dataProvider snmpArgsProvider
	 */
	public function test_option_used_warning_and_critical_CRITICAL($conn_args) {
		$this->assertCommand($conn_args, "-T ram_used -m % -w 20.50 -c 29.24", array(
		), array(
			"CRITICAL: Used RAM: 29.25% (172.41MiB) of total 589.43MiB |'RAM Used'=180785152B;126702673;180721277;0;618061824 'RAM Buffered'=54124544B;;;0;618061824 'RAM Cached'=287711232B;;;0;618061824 'RAM Free'=437276672B;;;0;618061824"
		), 2);
	}

	/**
	 * Test thresholds of different types
	 *
	 * @dataProvider snmpArgsProvider
	 */
	public function test_option_m_with_nothing_should_give_error_message($conn_args) {
		$this->assertCommand($conn_args, "-T ram_used -m -w 20.50 -c 29.24", array(
		), array(
			"Wrong parameter for -m"
		), 3);
	}

	/**
	 * @dataProvider snmpArgsProvider
	 */
	public function test_wc_parsing_tilde_and_at_OK($conn_args) {
		$this->assertCommand($conn_args, "-m gib -w~:300 -c@20:400", array(
		), array(
			"OK: Used RAM: 29.25% (172.41MiB) of total 589.43MiB |'RAM Used'=180785152B;322122547200;429496729600;0;618061824 'RAM Buffered'=54124544B;;;0;618061824 'RAM Cached'=287711232B;;;0;618061824 'RAM Free'=437276672B;;;0;618061824"
		), 0);
	}

	/**
	 * @dataProvider snmpArgsProvider
	 */
	public function test_prefix_mb_in_ranges_OK($conn_args) {
		$this->assertCommand($conn_args, "-m mib -w10:300 -c20:400", array(
		), array(
			"OK: Used RAM: 29.25% (172.41MiB) of total 589.43MiB |'RAM Used'=180785152B;314572800;419430400;0;618061824 'RAM Buffered'=54124544B;;;0;618061824 'RAM Cached'=287711232B;;;0;618061824 'RAM Free'=437276672B;;;0;618061824"
		), 0);
	}

	/**
	 * Swap used OK, WARNING, CRITICAL and different threshold types
	 *
	 * @dataProvider snmpArgsProvider
	 */
	public function test_option_swap_warning_and_critical_OK($conn_args) {
		$this->assertCommand($conn_args, "-T swap_used -w 10 -c 20", array(
		), array(
			"OK: Used Swap: 5.28% (64.69MiB) of total 1.20GiB |'Swap Used'=67833856B;128449740;256899481;0;1284497408 'Swap Free'=1216663552B;;;0;1284497408"
		), 0);
	}

	/**
	 * @dataProvider snmpArgsProvider
	 */
	public function test_option_swap_warning_and_critical_gb_OK($conn_args) {
		$this->assertCommand($conn_args, "-T swap_used -m gib -w10 -c20", array(
		), array(
			"OK: Used Swap: 5.28% (64.69MiB) of total 1.20GiB |'Swap Used'=67833856B;10737418240;21474836480;0;1284497408 'Swap Free'=1216663552B;;;0;1284497408"
		), 0);
	}

	/**
	 * @dataProvider snmpArgsProvider
	 */
	public function test_option_swap_warning_and_critical_WARNING($conn_args) {
		$this->assertCommand($conn_args, "-T swap_used -w 1 -c 20", array(
		), array(
			"WARNING: Used Swap: 5.28% (64.69MiB) of total 1.20GiB |'Swap Used'=67833856B;12844974;256899481;0;1284497408 'Swap Free'=1216663552B;;;0;1284497408"
		), 1);
	}

	/**
	 * @dataProvider snmpArgsProvider
	 */
	public function test_option_swap_warning_and_critical_mb_WARNING($conn_args) {
		$this->assertCommand($conn_args, "-T swap_used -m mib -w 10 -c 67.84", array(
		), array(
			"WARNING: Used Swap: 5.28% (64.69MiB) of total 1.20GiB |'Swap Used'=67833856B;10485760;71135395;0;1284497408 'Swap Free'=1216663552B;;;0;1284497408"
		), 1);
	}

	/**
	 * @dataProvider snmpArgsProvider
	 */
	public function test_option_swap_warning_and_critical_CRITICAL($conn_args) {
		$this->assertCommand($conn_args, "-T swap_used -w 1 -c 2", array(
		), array(
			"CRITICAL: Used Swap: 5.28% (64.69MiB) of total 1.20GiB |'Swap Used'=67833856B;12844974;25689948;0;1284497408 'Swap Free'=1216663552B;;;0;1284497408"
		), 2);
	}

	/**
	 * @dataProvider snmpArgsProvider
	 */
	public function test_option_swap_warning_and_critical_mb_CRITICAL($conn_args) {
		$this->assertCommand($conn_args, "-T swap_used -m mib -w10.000 -c64.69", array(
		), array(
			"CRITICAL: Used Swap: 5.28% (64.69MiB) of total 1.20GiB |'Swap Used'=67833856B;10485760;67832381;0;1284497408 'Swap Free'=1216663552B;;;0;1284497408"
		), 2);
	}

	/**
	 * Could not fetch the values
	 *
	 * @dataProvider snmpArgsProvider
	 */
	public function test_memory_could_not_fetch_the_value_for_ram_used_UNKNOWN($conn_args) {
		$this->assertCommandIncorrectSnmp($conn_args, "-T ram_used", array(
			"UNKNOWN: Could not fetch the values at 1.3.6.1.4.1.2021.4. Please check your config file for SNMP and make sure you have access"
		), 3);
	}

	/**
	 * @dataProvider snmpArgsProvider
	 */
	public function test_memory_could_not_fetch_the_value_for_swap_used_UNKNOWN($conn_args) {
		$this->assertCommandIncorrectSnmp($conn_args, "-T swap_used", array(
			"UNKNOWN: Could not fetch the values at 1.3.6.1.4.1.2021.4. Please check your config file for SNMP and make sure you have access"
		), 3);
	}

	/**
	 * @dataProvider snmpArgsProvider
	 */
	public function test_memory_could_not_fetch_the_index_value_for_ram_used_UNKNOWN($conn_args) {
		$this->assertCommand($conn_args, "-T ram_used", array(
			"1.3.6.1.4.1.2021.4.1.0" => array(2,""), /* no Index */
		), array(
			"UNKNOWN: Could not fetch the values at 1.3.6.1.4.1.2021.4. Please check your config file for SNMP and make sure you have access"
		), 3);
	}

	/**
	 * @dataProvider snmpArgsProvider
	 */
	public function test_memory_could_not_fetch_the_totalreal_value_for_ram_used_UNKNOWN($conn_args) {
		$this->assertCommand($conn_args, "-T ram_used", array(
			"1.3.6.1.4.1.2021.4.5.0" => array(2,""), /* no TotalReal */
		), array(
			"UNKNOWN: Could not fetch the values at 1.3.6.1.4.1.2021.4. Please check your config file for SNMP and make sure you have access"
		), 3);
	}

	/**
	 * @dataProvider snmpArgsProvider
	 */
	public function test_memory_could_not_fetch_the_buffer_value_for_ram_used_UNKNOWN($conn_args) {
		$this->assertCommand($conn_args, "-T ram_used", array(
			"1.3.6.1.4.1.2021.4.14.0" => array(2,""), /* no buffer */
		), array(
			"UNKNOWN: Could not fetch the values at 1.3.6.1.4.1.2021.4. Please check your config file for SNMP and make sure you have access"
		), 3);
	}

	/**
	 * Overflow test
	 *
	 * @group MON-8645
	 * @dataProvider snmpArgsProvider
	 */
	public function test_overflow_ram_OK($conn_args) {
		$this->assertCommand($conn_args, "-T ram_used", array(
			"1.3.6.1.4.1.2021.4.5.0" => array(2,"603576000"), /* TotalReal */
			"1.3.6.1.4.1.2021.4.6.0" => array(2,"60357600") /* AvailReal */
		), array(
			"OK: Used RAM: 89.94% (517.74GiB) of total 575.61GiB |'RAM Used'=555913805824B;0;0;0;618061824000 'RAM Buffered'=54124544B;;;0;618061824000 'RAM Cached'=287711232B;;;0;618061824000 'RAM Free'=62148018176B;;;0;618061824000"
		), 0);
	}

	/**
	 * @dataProvider snmpArgsProvider
	 */
	public function test_overflow_swap_UNKNOWN($conn_args) {
		$this->assertCommand($conn_args, "-T swap_used", array(
			"1.3.6.1.4.1.2021.4.3.0" => array(2,"60357600")
		), array(
			"OK: Used Swap: 98.03% (56.43GiB) of total 57.56GiB |'Swap Used'=60589518848B;0;0;0;61806182400 'Swap Free'=1216663552B;;;0;61806182400"
		), 0);
	}

	/**
	 * No arguments, usage and help
	 *
	 * @dataProvider snmpArgsProvider
	 */
	public function test_no_arguments($conn_args) {
		$this->assertCommand("", "", array(
		), array(
			'check_by_snmp_memory: Could not parse arguments',
			'Usage:',
			'check_by_snmp_memory [-T <type>] [-m <unit_range>]',
			'   [-w <warn_range>] [-c <crit_range>]',
			$this->snmp_usage,
		), 3);
	}

	/**
	 * @dataProvider snmpArgsProvider
	 */
	public function test_wrong_T_argument($conn_args) {
		$this->assertCommand($conn_args, "-T wrong", array(
		), array(
			"Wrong parameter for -T"
		), 3);
	}
}
