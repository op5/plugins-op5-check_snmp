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
	public function test_default_warning_and_critical_OK() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -w 85 -c 95", array(
		), array(
			'OK: 84% Ram used'
		), 0);
	}
/**
 * Ram used OK, WARNING, CRITICAL
 */
	public function test_option_used_warning_and_critical_OK() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -f -m r -w 85 -c 95", array(
		), array(
			"OK: 84% Ram used |'Ram used'=84%;85;95"
		), 0);
	}
	public function test_option_used_warning_and_critical_WARNING() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -f -m r -w 70 -c 95", array(
		), array(
			"WARNING: 84% Ram used |'Ram used'=84%;70;95"
		), 1);
	}
	public function test_option_used_warning_and_critical_CRITICAL() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -f -m r -w 70 -c 80", array(
		), array(
			"CRITICAL: 84% Ram used |'Ram used'=84%;70;80"
		), 2);
	}
/**
 * Ram free OK, WARNING, CRITICAL
 */
	public function test_option_free_warning_and_critical_OK() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -f -m f -w 20 -c 30", array(
		), array(
			"OK: 15% Ram free |'Ram free'=15%;20;30"
		), 0);
	}
	public function test_option_free_warning_and_critical_WARNING() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -f -m f -w 10 -c 30", array(
		), array(
			"WARNING: 15% Ram free |'Ram free'=15%;10;30"
		), 1);
	}
	public function test_option_free_warning_and_critical_CRITICAL() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -f -m f -w 10 -c 15", array(
		), array(
			"CRITICAL: 15% Ram free |'Ram free'=15%;10;15"
		), 2);
	}
/**
 * Swap used OK, WARNING, CRITICAL
 */
	public function test_option_swap_warning_and_critical_OK() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -f -m s -w 10 -c 20", array(
		), array(
			"OK: 5% Swap used |'Swap used'=5%;10;20"
		), 0);
	}
	public function test_option_swap_warning_and_critical_WARNING() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -f -m s -w 1 -c 20", array(
		), array(
			"WARNING: 5% Swap used |'Swap used'=5%;1;20"
		), 1);
	}
	public function test_option_swap_warning_and_critical_CRITICAL() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -f -m s -w 1 -c 2", array(
		), array(
			"CRITICAL: 5% Swap used |'Swap used'=5%;1;2"
		), 2);
	}
	/** This test fails because it needs to be fixed
	public function test_valid_index_option_with_perfdata() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -f", array(
		), array(
			"OK: 84% Ram used |'Ram used'=84%;;"
		), 0);
	}
	*/
	
/**
 * No arguments, usage and help
 */
	public function test_no_arguments() {
		$this->assertCommand("", array(
		), array(
			'check_snmp_memory: Could not parse arguments',
			'Usage:',
			'check_snmp_memory -H <ip_address> -C <snmp_community>',
			'[-w <warn_range>] [-c <crit_range>] [-t <timeout>] [-m [r|s|f]]',
			'([-P snmp version] [-N context] [-L seclevel] [-U secname]',
			'[-a authproto] [-A authpasswd] [-x privproto] [-X privpasswd])'
		), 3);
	}
	public function test_usage() {
		$this->assertCommand("-u", array(
		), array(
			'Usage:',
			'check_snmp_memory -H <ip_address> -C <snmp_community>',
			'[-w <warn_range>] [-c <crit_range>] [-t <timeout>] [-m [r|s|f]]',
			'([-P snmp version] [-N context] [-L seclevel] [-U secname]',
			'[-a authproto] [-A authpasswd] [-x privproto] [-X privpasswd])'
		), 0);
	}
	public function disabled_test_help() {
		$this->assertCommand("-h", array(
		), array(
			'check_snmp_memory v1.4.16.624.g304f.dirty (monitoring-plugins 2.1.1)',
			'Copyright (c) 2015 Monitoring Plugins Development Team',
			'	<devel@monitoring-plugins.org>',
			'',
			'Check status of remote machines and obtain system information via SNMP',
			'',
			'',
			'Usage:',
			'check_snmp_memory -H <ip_address> -C <snmp_community>',
			'[-w <warn_range>] [-c <crit_range>] [-t <timeout>] [-m [r|s|f]]',
			'([-P snmp version] [-N context] [-L seclevel] [-U secname]',
			'[-a authproto] [-A authpasswd] [-x privproto] [-X privpasswd])',
			'',
			'Options:',
			' -h, --help',
			'    Print detailed help screen',
			' -V, --version',
			'    Print version information',
			' -v, --verbose',
			'    Show details for command-line debugging (output may be truncated by',
			'    the monitoring system)',
			' -t, --timeout=INTEGER',
			'    Seconds before plugin times out (default: 15)',
			' -H, --hostname=STRING',
			'    IP address to the SNMP server',
			' -C, --community=STRING',
			'	Community string for SNMP communication',
			' -m, --memtype=[r|s|f]',
			'	r - Ram used',
			'	f - Ram free',
			'	s - Swap used',
			' -P, --protocol=[1|2c|3]',
			'    SNMP protocol version',
			' -L, --seclevel=[noAuthNoPriv|authNoPriv|authPriv]',
			'    SNMPv3 securityLevel',
			' -a, --authproto=[MD5|SHA]',
			'    SNMPv3 auth proto',
			' -x, --privproto=[DES|AES]',
			'    SNMPv3 priv proto (default DES)',
			' -U, --secname=USERNAME',
			'    SNMPv3 username',
			' -A, --authpassword=PASSWORD',
			'    SNMPv3 authentication password',
			' -X, --privpasswd=PASSWORD',
			'    SNMPv3 privacy password',
			' -w, --warning=RANGE',
			'    Warning range (format: start:end). Alert if outside this range',
			' -c, --critical=RANGE',
			'    Critical range',
			'',
			'Send email to help@monitoring-plugins.org if you have questions regarding',
			'use of this software. To submit patches or suggest improvements, send email',
			'to devel@monitoring-plugins.org',
			''
		), 0);
	}
}
