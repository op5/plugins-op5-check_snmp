<?php
class Check_Snmp_Memory_Test extends PHPUnit_Framework_TestCase {

	private static $snmpsimroot = "/tmp/check_snmp_memory_test/";
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
		$check_command = __DIR__ . "/../../../opt/plugins/check_snmp_memory";
		return exec($check_command . " " . $args, $output, $return);
	}

	private function generate_snmpdata($snmpdata_diff) {
		$snmpdata = <<<EOF
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
 * Memory testing
 * Default values
 */
	public function test_default() {
		$this->assertCommand("-H @endpoint@ -C mycommunity", array(
		), array(
			"OK: Used RAM: 29.25% (172.41MiB) of total 589.43MiB |'RAM Used'=180785152B;0;0;0;618061824 'RAM Buffered'=54124544B;;;0;618061824 'RAM Cached'=287711232B;;;0;618061824 'RAM Free'=437276672B;;;0;618061824"
		), 0);
	}
	public function test_default_with_warn_crit_values() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -w 90 -c 95", array(
		), array(
			"OK: Used RAM: 29.25% (172.41MiB) of total 589.43MiB |'RAM Used'=180785152B;556255641;587158732;0;618061824 'RAM Buffered'=54124544B;;;0;618061824 'RAM Cached'=287711232B;;;0;618061824 'RAM Free'=437276672B;;;0;618061824"
		), 0);
	}
/**
 * Ram used OK, WARNING, CRITICAL
 */
	public function test_option_used_warning_and_critical_OK() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -T ram_used -w 90 -c 95", array(
		), array(
			"OK: Used RAM: 29.25% (172.41MiB) of total 589.43MiB |'RAM Used'=180785152B;556255641;587158732;0;618061824 'RAM Buffered'=54124544B;;;0;618061824 'RAM Cached'=287711232B;;;0;618061824 'RAM Free'=437276672B;;;0;618061824"
		), 0);
	}
	public function test_option_used_warning_and_critical_WARNING() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -T ram_used -w 20.50 -c 95.00 -m %", array(
		), array(
			"WARNING: Used RAM: 29.25% (172.41MiB) of total 589.43MiB |'RAM Used'=180785152B;126702673;587158732;0;618061824 'RAM Buffered'=54124544B;;;0;618061824 'RAM Cached'=287711232B;;;0;618061824 'RAM Free'=437276672B;;;0;618061824"
		), 1);
	}
	public function test_option_used_warning_and_critical_CRITICAL() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -T ram_used -m % -w 20.50 -c 29.24", array(
		), array(
			"CRITICAL: Used RAM: 29.25% (172.41MiB) of total 589.43MiB |'RAM Used'=180785152B;126702673;180721277;0;618061824 'RAM Buffered'=54124544B;;;0;618061824 'RAM Cached'=287711232B;;;0;618061824 'RAM Free'=437276672B;;;0;618061824"
		), 2);
	}
/**
 * Test thresholds of different types
 */
	public function test_option_m_with_nothing_should_give_error_message() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -T ram_used -m -w 20.50 -c 29.24", array(
		), array(
			"Wrong parameter for -m"
		), 3);
	}
	public function test_wc_parsing_tilde_and_at_OK() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -m gb -w~:300 -c@20:400", array(
		), array(
			"OK: Used RAM: 29.25% (172.41MiB) of total 589.43MiB |'RAM Used'=180785152B;322122547200;429496729600;0;618061824 'RAM Buffered'=54124544B;;;0;618061824 'RAM Cached'=287711232B;;;0;618061824 'RAM Free'=437276672B;;;0;618061824"
		), 0);
	}
	public function test_prefix_mb_in_ranges_OK() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -m mb -w10:300 -c20:400", array(
		), array(
			"OK: Used RAM: 29.25% (172.41MiB) of total 589.43MiB |'RAM Used'=180785152B;314572800;419430400;0;618061824 'RAM Buffered'=54124544B;;;0;618061824 'RAM Cached'=287711232B;;;0;618061824 'RAM Free'=437276672B;;;0;618061824"
		), 0);
	}
/**
 * Swap used OK, WARNING, CRITICAL and different threshold types
 */
	public function test_option_swap_warning_and_critical_OK() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -T swap_used -w 10 -c 20", array(
		), array(
			"OK: Used Swap: 5.28% (64.69MiB) of total 1.20GiB |'Swap Used'=67833856B;128449740;256899481;0;1284497408 'Swap Free'=1216663552B;;;0;1284497408"
		), 0);
	}
	public function test_option_swap_warning_and_critical_gb_OK() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -T swap_used -m gb -w10 -c20", array(
		), array(
			"OK: Used Swap: 5.28% (64.69MiB) of total 1.20GiB |'Swap Used'=67833856B;10737418240;21474836480;0;1284497408 'Swap Free'=1216663552B;;;0;1284497408"
		), 0);
	}
	public function test_option_swap_warning_and_critical_WARNING() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -T swap_used -w 1 -c 20", array(
		), array(
			"WARNING: Used Swap: 5.28% (64.69MiB) of total 1.20GiB |'Swap Used'=67833856B;12844974;256899481;0;1284497408 'Swap Free'=1216663552B;;;0;1284497408"
		), 1);
	}
	public function test_option_swap_warning_and_critical_mb_WARNING() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -T swap_used -m mb -w 10 -c 67.84", array(
		), array(
			"WARNING: Used Swap: 5.28% (64.69MiB) of total 1.20GiB |'Swap Used'=67833856B;10485760;71135395;0;1284497408 'Swap Free'=1216663552B;;;0;1284497408"
		), 1);
	}
	public function test_option_swap_warning_and_critical_CRITICAL() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -T swap_used -w 1 -c 2", array(
		), array(
			"CRITICAL: Used Swap: 5.28% (64.69MiB) of total 1.20GiB |'Swap Used'=67833856B;12844974;25689948;0;1284497408 'Swap Free'=1216663552B;;;0;1284497408"
		), 2);
	}
	public function test_option_swap_warning_and_critical_mb_CRITICAL() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -T swap_used -m mb -w10.000 -c64.69", array(
		), array(
			"CRITICAL: Used Swap: 5.28% (64.69MiB) of total 1.20GiB |'Swap Used'=67833856B;10485760;67832381;0;1284497408 'Swap Free'=1216663552B;;;0;1284497408"
		), 2);
	}
/**
 * No arguments, usage and help
 */
	public function test_no_arguments() {
		$this->assertCommand("", array(
		), array(
			'check_snmp_memory: Could not parse arguments',
			'Usage:',
			'check_snmp_memory -H <ip_address> -C <snmp_community> [-T <type>]',
			'[-m<unit_range>] [-w<warn_range>] [-c<crit_range>] [-t <timeout>]',
			'([-P snmp version] [-L seclevel] [-U secname]',
			'[-a authproto] [-A authpasswd] [-x privproto] [-X privpasswd])'
		), 3);
	}
	public function test_wrong_T_argument() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -T wrong", array(
		), array(
			"Wrong parameter for -T"
		), 3);
	}
	public function disabled_test_help() {
		$this->assertCommand("-h", array(
		), array(
			''
		), 0);
	}
}
