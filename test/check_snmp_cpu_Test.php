<?php
class Check_Snmp_Cpu_Test extends PHPUnit_Framework_TestCase {

	private static $snmpsimroot = "/tmp/check_snmp_cpu_test/";
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
		$check_command = __DIR__ . "/../src/check_snmp_cpu";
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
 * Testing
 */
	
	public function test_default_without_parameters() {
		$this->assertCommand("-H @endpoint@ -C mycommunity", array(
		), array(
			'OK: 0.02 CPU load-1'
		), 0);
	}
	
/**
 * No arguments, usage and help
 */
 /*
	public function test_no_arguments() {
		$this->assertCommand("", array(
		), array(
			'check_snmp_disk: Could not parse arguments',
			'Usage:',
			'check_snmp_disk -H <ip_address> -C <snmp_community> -i <index of disk>',
			'[-w <warn_range>] [-c <crit_range>] [-t <timeout>] [-m [1|2|3|4]]',
			'([-P snmp version] [-N context] [-L seclevel] [-U secname]',
			'[-a authproto] [-A authpasswd] [-x privproto] [-X privpasswd])'
		), 3);
	}
	public function test_usage() {
		$this->assertCommand("-u", array(
		), array(
			'Usage:',
			'check_snmp_disk -H <ip_address> -C <snmp_community> -i <index of disk>',
			'[-w <warn_range>] [-c <crit_range>] [-t <timeout>] [-m [1|2|3|4]]',
			'([-P snmp version] [-N context] [-L seclevel] [-U secname]',
			'[-a authproto] [-A authpasswd] [-x privproto] [-X privpasswd])'
		), 0);
	}
	public function test_help() {
		$this->assertCommand("-h", array(
		), array(
			'check_snmp_disk v1.4.16.624.g304f.dirty (monitoring-plugins 2.1.1)',
			'Copyright (c) 2015 Monitoring Plugins Development Team',
			'	<devel@monitoring-plugins.org>',
			'',
			'Check status of remote machines and obtain system information via SNMP',
			'',
			'',
			'Usage:',
			'check_snmp_disk -H <ip_address> -C <snmp_community> -i <index of disk>',
			'[-w <warn_range>] [-c <crit_range>] [-t <timeout>] [-m [1|2|3|4]]',
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
			' -m, --monitordisktype=[1|2|3|4]',
			'	1 - Storage (default)',
			'	2 - I/O',
			' -i, --indexofdisk=<int>',
			'	0 - Storage index list (default)',
			'	<int> - Storage to check',
			' -T, --Type=[1-7]',
			'	1 - Storage percent used (default)',
			'	2 - Storage percent left',
			'	3 - Storage MegaBytes used',
			'	4 - Storage MegaBytes left',
			'	---',
			'	5 - I/O load average 1 min',
			'	6 - I/O load average 5 min',
			'	7 - I/O load average 15 min',
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
	*/
}
