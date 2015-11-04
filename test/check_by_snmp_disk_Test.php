<?php
class Check_Snmp_Disk_Test extends PHPUnit_Framework_TestCase {

	private static $snmpsimroot = "/tmp/check_by_snmp_disk_test/";
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
		$check_command = __DIR__ . "/../../../opt/plugins/check_by_snmp_disk";
		return exec($check_command . " " . $args, $output, $return);
	}

	private function generate_snmpdata($snmpdata_diff) {
		$snmpdata = <<<EOF
1.3.6.1.2.1.25.2.3.1.1.1|2|1
1.3.6.1.2.1.25.2.3.1.1.3|2|3
1.3.6.1.2.1.25.2.3.1.1.6|2|6
1.3.6.1.2.1.25.2.3.1.1.7|2|7
1.3.6.1.2.1.25.2.3.1.1.8|2|8
1.3.6.1.2.1.25.2.3.1.1.10|2|10
1.3.6.1.2.1.25.2.3.1.1.31|2|31
1.3.6.1.2.1.25.2.3.1.1.34|2|34
1.3.6.1.2.1.25.2.3.1.1.40|2|40
1.3.6.1.2.1.25.2.3.1.1.41|2|41
1.3.6.1.2.1.25.2.3.1.1.42|2|42
1.3.6.1.2.1.25.2.3.1.1.43|2|43
1.3.6.1.2.1.25.2.3.1.1.54|2|54
1.3.6.1.2.1.25.2.3.1.2.1|6|1.3.6.1.2.1.25.2.1.2
1.3.6.1.2.1.25.2.3.1.2.3|6|1.3.6.1.2.1.25.2.1.3
1.3.6.1.2.1.25.2.3.1.2.6|6|1.3.6.1.2.1.25.2.1.1
1.3.6.1.2.1.25.2.3.1.2.7|6|1.3.6.1.2.1.25.2.1.1
1.3.6.1.2.1.25.2.3.1.2.8|6|1.3.6.1.2.1.25.2.1.1
1.3.6.1.2.1.25.2.3.1.2.10|6|1.3.6.1.2.1.25.2.1.3
1.3.6.1.2.1.25.2.3.1.2.31|6|1.3.6.1.2.1.25.2.1.4
1.3.6.1.2.1.25.2.3.1.2.34|6|1.3.6.1.2.1.25.2.1.4
1.3.6.1.2.1.25.2.3.1.2.40|6|1.3.6.1.2.1.25.2.1.4
1.3.6.1.2.1.25.2.3.1.2.41|6|1.3.6.1.2.1.25.2.1.4
1.3.6.1.2.1.25.2.3.1.2.42|6|1.3.6.1.2.1.25.2.1.4
1.3.6.1.2.1.25.2.3.1.2.43|6|1.3.6.1.2.1.25.2.1.4
1.3.6.1.2.1.25.2.3.1.2.54|6|1.3.6.1.2.1.25.2.1.4
1.3.6.1.2.1.25.2.3.1.3.1|4|Physical memory
1.3.6.1.2.1.25.2.3.1.3.3|4|Virtual memory
1.3.6.1.2.1.25.2.3.1.3.6|4|Memory buffers
1.3.6.1.2.1.25.2.3.1.3.7|4|Cached memory
1.3.6.1.2.1.25.2.3.1.3.8|4|Shared memory
1.3.6.1.2.1.25.2.3.1.3.10|4|Swap space
1.3.6.1.2.1.25.2.3.1.3.31|4|/
1.3.6.1.2.1.25.2.3.1.3.34|4|/sys/fs/cgroup
1.3.6.1.2.1.25.2.3.1.3.40|4|/run
1.3.6.1.2.1.25.2.3.1.3.41|4|/run/lock
1.3.6.1.2.1.25.2.3.1.3.42|4|/run/shm
1.3.6.1.2.1.25.2.3.1.3.43|4|/run/user
1.3.6.1.2.1.25.2.3.1.3.54|4|/home
1.3.6.1.2.1.25.2.3.1.4.1|2|1024
1.3.6.1.2.1.25.2.3.1.4.3|2|1024
1.3.6.1.2.1.25.2.3.1.4.6|2|1024
1.3.6.1.2.1.25.2.3.1.4.7|2|1024
1.3.6.1.2.1.25.2.3.1.4.8|2|1024
1.3.6.1.2.1.25.2.3.1.4.10|2|1024
1.3.6.1.2.1.25.2.3.1.4.31|2|4096
1.3.6.1.2.1.25.2.3.1.4.34|2|4096
1.3.6.1.2.1.25.2.3.1.4.40|2|4096
1.3.6.1.2.1.25.2.3.1.4.41|2|4096
1.3.6.1.2.1.25.2.3.1.4.42|2|4096
1.3.6.1.2.1.25.2.3.1.4.43|2|4096
1.3.6.1.2.1.25.2.3.1.4.54|2|4096
1.3.6.1.2.1.25.2.3.1.5.1|2|7870368
1.3.6.1.2.1.25.2.3.1.5.3|2|15868828
1.3.6.1.2.1.25.2.3.1.5.6|2|7870368
1.3.6.1.2.1.25.2.3.1.5.7|2|2928588
1.3.6.1.2.1.25.2.3.1.5.8|2|237188
1.3.6.1.2.1.25.2.3.1.5.10|2|7998460
1.3.6.1.2.1.25.2.3.1.5.31|2|5974751
1.3.6.1.2.1.25.2.3.1.5.34|2|1
1.3.6.1.2.1.25.2.3.1.5.40|2|196760
1.3.6.1.2.1.25.2.3.1.5.41|2|1280
1.3.6.1.2.1.25.2.3.1.5.42|2|983796
1.3.6.1.2.1.25.2.3.1.5.43|2|25600
1.3.6.1.2.1.25.2.3.1.5.54|2|49678626
1.3.6.1.2.1.25.2.3.1.6.1|2|5303624
1.3.6.1.2.1.25.2.3.1.6.3|2|5303672
1.3.6.1.2.1.25.2.3.1.6.6|2|120028
1.3.6.1.2.1.25.2.3.1.6.7|2|2928588
1.3.6.1.2.1.25.2.3.1.6.8|2|237188
1.3.6.1.2.1.25.2.3.1.6.10|2|48
1.3.6.1.2.1.25.2.3.1.6.31|2|2656106
1.3.6.1.2.1.25.2.3.1.6.34|2|0
1.3.6.1.2.1.25.2.3.1.6.40|2|412
1.3.6.1.2.1.25.2.3.1.6.41|2|0
1.3.6.1.2.1.25.2.3.1.6.42|2|18019
1.3.6.1.2.1.25.2.3.1.6.43|2|6
1.3.6.1.2.1.25.2.3.1.6.54|2|41870371
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
 * Storage testing
 */
	public function test_list_storage_units() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -D --list", array(
		), array(
			'Physical memory : Ram            1K-blocks    67.39% used of 7.51GiB',
			'Virtual memory  : VirtualMemory  1K-blocks    33.42% used of 15.13GiB',
			'Memory buffers  : Other          1K-blocks     1.53% used of 7.51GiB',
			'Cached memory   : Other          1K-blocks   100.00% used of 2.79GiB',
			'Shared memory   : Other          1K-blocks   100.00% used of 231.63MiB',
			'Swap space      : VirtualMemory  1K-blocks     0.00% used of 7.63GiB',
			'/               : FixedDisk      4K-blocks    44.46% used of 22.79GiB',
			'/sys/fs/cgroup  : FixedDisk      4K-blocks     0.00% used of 4.00KiB',
			'/run            : FixedDisk      4K-blocks     0.21% used of 768.59MiB',
			'/run/lock       : FixedDisk      4K-blocks     0.00% used of 5.00MiB',
			'/run/shm        : FixedDisk      4K-blocks     1.83% used of 3.75GiB',
			'/run/user       : FixedDisk      4K-blocks     0.02% used of 100.00MiB',
			'/home           : FixedDisk      4K-blocks    84.28% used of 189.51GiB',
		), 0);
	}
	public function test_invalid_option() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -f -i /", array(
		), array(
			'',
		), 3);
	}
	public function test_valid_include_name_option() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -i /", array(
		), array(
			"OK: 1/1 OK (/: 44.46% used of 22.79GiB)",
			"|'/_used'=10879410176B;0:;0:;0;24472580096",
		), 0);
	}
	public function test_valid_include_regex_option() {
		$this->assertCommand("-H @endpoint@ -C mycommunity --include-regex '^/$'", array(
		), array(
			"OK: 1/1 OK (/: 44.46% used of 22.79GiB)",
			"|'/_used'=10879410176B;0:;0:;0;24472580096",
		), 0);
	}
	public function test_invalid_include_regex_option() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -e '^/(asd$'", array(
		), array(
			"Failed to compile regular expression: Unmatched ( or \\(",
		), 3);
	}
	public function test_invalid_I_option() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -i invalid", array(
		), array(
			"No storage units match your filters."
		), 3);
	}
	public function test_invalid_T_option() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -i /dev/shm -T this_doesnt_exist", array(
		), array(
			"Invalid type filter: this_doesnt_exist"
		), 3);
	}

/**
 * Storage percent used controlled by warning and critical values
 */
	public function test_percent_storage_used_OK() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -i / -w50 -c75 -m %", array(
		), array(
			"OK: 1/1 OK (/: 44.46% used of 22.79GiB)",
			"|'/_used'=10879410176B;0:12236290048;0:18354435072;0;24472580096",
		), 0);
	}
	public function test_percent_storage_used_WARNING() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -i / -m % -w25 -c75", array(
		), array(
			"WARNING: 1/1 warning (/: 44.46% used of 22.79GiB)",
			"|'/_used'=10879410176B;0:6118145024;0:18354435072;0;24472580096",
		), 1);
	}
	public function test_percent_storage_used_CRITICAL() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -i / -w25:26 -c30:31", array(
		), array(
			"CRITICAL: 1/1 critical (/: 44.46% used of 22.79GiB)",
			"|'/_used'=10879410176B;6118145024:6362870825;7341774029:7586499830;0;24472580096",
		), 2);
	}
	public function test_sum_storage_used_CRITICAL() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -D -S -w 25:26 -c30:31", array(
		), array(
			"CRITICAL: 13 storage units selected. Sum total: 71.08% used of 257.70GiB",
			"|'total_used'=196682547200B;69175566336:71942588989;83010679603:85777702257;0;276702265344",
		), 2);
	}

/**
 * Storage prefixedbytes used controlled by warning and critical values
 */
	public function test_gb_prefix_OK() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -i / -m gib -w30 -c40", array(
		), array(
			"OK: 1/1 OK (/: 44.46% used of 22.79GiB)",
			"|'/_used'=10879410176B;0:32212254720;0:42949672960;0;24472580096",
		), 0);
	}
/**
 * Could not fetch the values
 */
	public function test_disk_could_not_fetch_the_value_for_size() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -i /", array(
			"1.3.6.1.2.1.25.2.3.1.5.31" => array(2,"")
		), array(
			"Failed to read data for storage unit 31 (/). Please check your SNMP configuration",
		), 3);
	}
	public function test_disk_could_not_fetch_the_value_for_used() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -i /", array(
			"1.3.6.1.2.1.25.2.3.1.6.31" => array(2,"")
		), array(
			"Failed to read data for storage unit 31 (/). Please check your SNMP configuration",
		), 3);
	}
	public function test_disk_could_not_fetch_the_value_for_descr() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -i /", array(
			"1.3.6.1.2.1.25.2.3.1.3.31" => array(2,"")
		), array(
			"Failed to read description for storage unit with index 31. Please check your SNMP configuration"
		), 3);
	}
}
