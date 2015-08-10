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
		
		$command="/usr/bin/snmpsimd.py".
		" --daemonize".
		" --pid-file=".$this->snmpsimroot_current . "pidfile".
		" --agent-udpv4-endpoint=127.0.0.1:21161".
		" --device-dir=".$this->snmpsimroot_current . "data";
		//echo "running: $command\n";
		system($command, $returnval);
		//echo "return: $returnval\n";
		//echo "pid: ".file_get_contents($this->snmpsimroot_current . "pidfile")."\n";
	}
	
	public function stop_snmpsim() {
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
		$check_command = __DIR__ . "/../src/check_snmp_memory";
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
 */
	public function test_default() {
		$this->assertCommand("-H @endpoint@ -C mycommunity", array(
		), array(
			'OK: 84% Ram used'
		), 0);
	}
	public function test_default_with_perf_data_and_warn_crit_values() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -f -w 85 -c 95", array(
		), array(
			"OK: 84% Ram used |'Ram used'=84%;85;95"
		), 0);
	}
/**
 * Ram used OK, WARNING, CRITICAL
 */
	public function test_option_used_warning_and_critical_OK() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -f -T ram_used -w 85 -c 95", array(
		), array(
			"OK: 84% Ram used |'Ram used'=84%;85;95"
		), 0);
	}
	public function test_option_used_warning_and_critical_WARNING() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -f -T ram_used -w 70 -c 95", array(
		), array(
			"WARNING: 84% Ram used |'Ram used'=84%;70;95"
		), 1);
	}
	public function test_option_used_warning_and_critical_CRITICAL() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -f -T ram_used -w 70 -c 80", array(
		), array(
			"CRITICAL: 84% Ram used |'Ram used'=84%;70;80"
		), 2);
	}
/**
 * Ram free OK, WARNING, CRITICAL
 */
	public function test_option_free_warning_and_critical_OK() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -f -T ram_free -w 20 -c 30", array(
		), array(
			"OK: 15% Ram free |'Ram free'=15%;20;30"
		), 0);
	}
	public function test_option_free_warning_and_critical_WARNING() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -f -T ram_free -w 10 -c 30", array(
		), array(
			"WARNING: 15% Ram free |'Ram free'=15%;10;30"
		), 1);
	}
	public function test_option_free_warning_and_critical_CRITICAL() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -f -T ram_free -w 10 -c 15", array(
		), array(
			"CRITICAL: 15% Ram free |'Ram free'=15%;10;15"
		), 2);
	}
/**
 * Swap used OK, WARNING, CRITICAL
 */
	public function test_option_swap_warning_and_critical_OK() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -f -T swap_used -w 10 -c 20", array(
		), array(
			"OK: 5% Swap used |'Swap used'=5%;10;20"
		), 0);
	}
	public function test_option_swap_warning_and_critical_WARNING() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -f -T swap_used -w 1 -c 20", array(
		), array(
			"WARNING: 5% Swap used |'Swap used'=5%;1;20"
		), 1);
	}
	public function test_option_swap_warning_and_critical_CRITICAL() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -f -T swap_used -w 1 -c 2", array(
		), array(
			"CRITICAL: 5% Swap used |'Swap used'=5%;1;2"
		), 2);
	}
/**
 * Buffer OK, WARNING, CRITICAL
 */
	public function test_buffer_in_kb_warning_and_critical_OK() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -f -T buffer_in_kb -w 100000 -c 200000", array(
		), array(
			"OK: 52856KB Memory Buffer |'Memory Buffer'=52856KB;100000;200000"
		), 0);
	}
	public function test_buffer_in_kb_warning_and_critical_WARNING() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -f -T buffer_in_kb -w 20:30 -c 200000", array(
		), array(
			"WARNING: 52856KB Memory Buffer |'Memory Buffer'=52856KB;20:30;200000"
		), 1);
	}
	public function test_buffer_in_kb_warning_and_critical_CRITICAL() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -f -T buffer_in_kb -w 100000 -c \~:10", array(
		), array(
			"CRITICAL: 52856KB Memory Buffer |'Memory Buffer'=52856KB;100000;~:10"
		), 2);
	}
	public function test_buffer_in_mb_warning_and_critical_OK() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -f -T buffer_in_mb -w 100 -c 200", array(
		), array(
			"OK: 51MB Memory Buffer |'Memory Buffer'=51MB;100;200"
		), 0);
	}
	public function test_buffer_in_gb_warning_and_critical_OK() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -f -T buffer_in_gb -w 10 -c 20", array(
		), array(
			"OK: 0GB Memory Buffer |'Memory Buffer'=0GB;10;20"
		), 0);
	}
/**
 * Cache OK, WARNING, CRITICAL
 */
	public function test_cached_warning_and_critical_OK() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -f -T cached_in_kb -w 300000 -c 400000", array(
		), array(
			"OK: 280968KB Memory Cached |'Memory Cached'=280968KB;300000;400000"
		), 0);
	}
	public function test_cached_warning_and_critical_WARNING() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -f -T cached_in_kb -w @280000:290000 -c 400000", array(
		), array(
			"WARNING: 280968KB Memory Cached |'Memory Cached'=280968KB;@280000:290000;400000"
		), 1);
	}
	public function test_cached_warning_and_critical_CRITICAL() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -f -T cached_in_kb -w 200000 -c @280000:290000", array(
		), array(
			"CRITICAL: 280968KB Memory Cached |'Memory Cached'=280968KB;200000;@280000:290000"
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
			'check_snmp_memory -H <ip_address> -C <snmp_community>',
			'[-w <warn_range>] [-c <crit_range>] [-t <timeout>] [-T <type>]',
			'([-P snmp version] [-N context] [-L seclevel] [-U secname]',
			'[-a authproto] [-A authpasswd] [-x privproto] [-X privpasswd])'
		), 3);
	}
	public function test_usage() {
		$this->assertCommand("-u", array(
		), array(
			'Usage:',
			'check_snmp_memory -H <ip_address> -C <snmp_community>',
			'[-w <warn_range>] [-c <crit_range>] [-t <timeout>] [-T <type>]',
			'([-P snmp version] [-N context] [-L seclevel] [-U secname]',
			'[-a authproto] [-A authpasswd] [-x privproto] [-X privpasswd])'
		), 0);
	}
	public function disabled_test_help() {
		$this->assertCommand("-h", array(
		), array(
			''
		), 0);
	}
}
