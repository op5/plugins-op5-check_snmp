<?php
class Check_Snmp_Disk_Test extends PHPUnit_Framework_TestCase {

	private static $snmpsimroot = "/tmp/check_snmp_disk_test/";
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
		$check_command = __DIR__ . "/../src/check_snmp_disk";
		return exec($check_command . " " . $args, $output, $return);
	}

	private function generate_snmpdata($snmpdata_diff) {
		$snmpdata = <<<EOF
1.3.6.1.2.1.25.2.3.1.1.1|2|1
1.3.6.1.2.1.25.2.3.1.1.3|2|3
1.3.6.1.2.1.25.2.3.1.1.6|2|6
1.3.6.1.2.1.25.2.3.1.1.7|2|7
1.3.6.1.2.1.25.2.3.1.1.10|2|10
1.3.6.1.2.1.25.2.3.1.1.31|2|31
1.3.6.1.2.1.25.2.3.1.1.35|2|35
1.3.6.1.2.1.25.2.3.1.2.1|6|1.3.6.1.2.1.25.2.1.2
1.3.6.1.2.1.25.2.3.1.2.3|6|1.3.6.1.2.1.25.2.1.3
1.3.6.1.2.1.25.2.3.1.2.6|6|1.3.6.1.2.1.25.2.1.1
1.3.6.1.2.1.25.2.3.1.2.7|6|1.3.6.1.2.1.25.2.1.1
1.3.6.1.2.1.25.2.3.1.2.10|6|1.3.6.1.2.1.25.2.1.3
1.3.6.1.2.1.25.2.3.1.2.31|6|1.3.6.1.2.1.25.2.1.4
1.3.6.1.2.1.25.2.3.1.2.35|6|1.3.6.1.2.1.25.2.1.4
1.3.6.1.2.1.25.2.3.1.3.1|4|Physical memory
1.3.6.1.2.1.25.2.3.1.3.3|4|Virtual memory
1.3.6.1.2.1.25.2.3.1.3.6|4|Memory buffers
1.3.6.1.2.1.25.2.3.1.3.7|4|Cached memory
1.3.6.1.2.1.25.2.3.1.3.10|4|Swap space
1.3.6.1.2.1.25.2.3.1.3.31|4|/
1.3.6.1.2.1.25.2.3.1.3.35|4|/dev/shm
1.3.6.1.2.1.25.2.3.1.4.1|2|1024
1.3.6.1.2.1.25.2.3.1.4.3|2|1024
1.3.6.1.2.1.25.2.3.1.4.6|2|1024
1.3.6.1.2.1.25.2.3.1.4.7|2|1024
1.3.6.1.2.1.25.2.3.1.4.10|2|1024
1.3.6.1.2.1.25.2.3.1.4.31|2|4096
1.3.6.1.2.1.25.2.3.1.4.35|2|4096
1.3.6.1.2.1.25.2.3.1.5.1|2|603576
1.3.6.1.2.1.25.2.3.1.5.3|2|1857968
1.3.6.1.2.1.25.2.3.1.5.6|2|603576
1.3.6.1.2.1.25.2.3.1.5.7|2|326152
1.3.6.1.2.1.25.2.3.1.5.10|2|1254392
1.3.6.1.2.1.25.2.3.1.5.31|2|2063982
1.3.6.1.2.1.25.2.3.1.5.35|2|75447
1.3.6.1.2.1.25.2.3.1.6.1|2|512500
1.3.6.1.2.1.25.2.3.1.6.3|2|567808
1.3.6.1.2.1.25.2.3.1.6.6|2|40156
1.3.6.1.2.1.25.2.3.1.6.7|2|326152
1.3.6.1.2.1.25.2.3.1.6.10|2|55308
1.3.6.1.2.1.25.2.3.1.6.31|2|672710
1.3.6.1.2.1.25.2.3.1.6.35|2|0

1.3.6.1.4.1.2021.13.15.1.1.1.1|2|1
1.3.6.1.4.1.2021.13.15.1.1.1.2|2|2
1.3.6.1.4.1.2021.13.15.1.1.1.3|2|3
1.3.6.1.4.1.2021.13.15.1.1.1.4|2|4
1.3.6.1.4.1.2021.13.15.1.1.1.5|2|5
1.3.6.1.4.1.2021.13.15.1.1.1.6|2|6
1.3.6.1.4.1.2021.13.15.1.1.1.7|2|7
1.3.6.1.4.1.2021.13.15.1.1.1.8|2|8
1.3.6.1.4.1.2021.13.15.1.1.1.9|2|9
1.3.6.1.4.1.2021.13.15.1.1.1.10|2|10
1.3.6.1.4.1.2021.13.15.1.1.1.11|2|11
1.3.6.1.4.1.2021.13.15.1.1.1.12|2|12
1.3.6.1.4.1.2021.13.15.1.1.1.13|2|13
1.3.6.1.4.1.2021.13.15.1.1.1.14|2|14
1.3.6.1.4.1.2021.13.15.1.1.1.15|2|15
1.3.6.1.4.1.2021.13.15.1.1.1.16|2|16
1.3.6.1.4.1.2021.13.15.1.1.1.17|2|17
1.3.6.1.4.1.2021.13.15.1.1.1.18|2|18
1.3.6.1.4.1.2021.13.15.1.1.1.19|2|19
1.3.6.1.4.1.2021.13.15.1.1.1.20|2|20
1.3.6.1.4.1.2021.13.15.1.1.1.21|2|21
1.3.6.1.4.1.2021.13.15.1.1.1.22|2|22
1.3.6.1.4.1.2021.13.15.1.1.1.23|2|23
1.3.6.1.4.1.2021.13.15.1.1.1.24|2|24
1.3.6.1.4.1.2021.13.15.1.1.1.25|2|25
1.3.6.1.4.1.2021.13.15.1.1.1.26|2|26
1.3.6.1.4.1.2021.13.15.1.1.1.27|2|27
1.3.6.1.4.1.2021.13.15.1.1.1.28|2|28
1.3.6.1.4.1.2021.13.15.1.1.2.1|4|ram0
1.3.6.1.4.1.2021.13.15.1.1.2.2|4|ram1
1.3.6.1.4.1.2021.13.15.1.1.2.3|4|ram2
1.3.6.1.4.1.2021.13.15.1.1.2.4|4|ram3
1.3.6.1.4.1.2021.13.15.1.1.2.5|4|ram4
1.3.6.1.4.1.2021.13.15.1.1.2.6|4|ram5
1.3.6.1.4.1.2021.13.15.1.1.2.7|4|ram6
1.3.6.1.4.1.2021.13.15.1.1.2.8|4|ram7
1.3.6.1.4.1.2021.13.15.1.1.2.9|4|ram8
1.3.6.1.4.1.2021.13.15.1.1.2.10|4|ram9
1.3.6.1.4.1.2021.13.15.1.1.2.11|4|ram10
1.3.6.1.4.1.2021.13.15.1.1.2.12|4|ram11
1.3.6.1.4.1.2021.13.15.1.1.2.13|4|ram12
1.3.6.1.4.1.2021.13.15.1.1.2.14|4|ram13
1.3.6.1.4.1.2021.13.15.1.1.2.15|4|ram14
1.3.6.1.4.1.2021.13.15.1.1.2.16|4|ram15
1.3.6.1.4.1.2021.13.15.1.1.2.17|4|loop0
1.3.6.1.4.1.2021.13.15.1.1.2.18|4|loop1
1.3.6.1.4.1.2021.13.15.1.1.2.19|4|loop2
1.3.6.1.4.1.2021.13.15.1.1.2.20|4|loop3
1.3.6.1.4.1.2021.13.15.1.1.2.21|4|loop4
1.3.6.1.4.1.2021.13.15.1.1.2.22|4|loop5
1.3.6.1.4.1.2021.13.15.1.1.2.23|4|loop6
1.3.6.1.4.1.2021.13.15.1.1.2.24|4|loop7
1.3.6.1.4.1.2021.13.15.1.1.2.25|4|sda
1.3.6.1.4.1.2021.13.15.1.1.2.26|4|sda1
1.3.6.1.4.1.2021.13.15.1.1.2.27|4|sdb
1.3.6.1.4.1.2021.13.15.1.1.2.28|4|sdb1
1.3.6.1.4.1.2021.13.15.1.1.3.1|65|0
1.3.6.1.4.1.2021.13.15.1.1.3.2|65|0
1.3.6.1.4.1.2021.13.15.1.1.3.3|65|0
1.3.6.1.4.1.2021.13.15.1.1.3.4|65|0
1.3.6.1.4.1.2021.13.15.1.1.3.5|65|0
1.3.6.1.4.1.2021.13.15.1.1.3.6|65|0
1.3.6.1.4.1.2021.13.15.1.1.3.7|65|0
1.3.6.1.4.1.2021.13.15.1.1.3.8|65|0
1.3.6.1.4.1.2021.13.15.1.1.3.9|65|0
1.3.6.1.4.1.2021.13.15.1.1.3.10|65|0
1.3.6.1.4.1.2021.13.15.1.1.3.11|65|0
1.3.6.1.4.1.2021.13.15.1.1.3.12|65|0
1.3.6.1.4.1.2021.13.15.1.1.3.13|65|0
1.3.6.1.4.1.2021.13.15.1.1.3.14|65|0
1.3.6.1.4.1.2021.13.15.1.1.3.15|65|0
1.3.6.1.4.1.2021.13.15.1.1.3.16|65|0
1.3.6.1.4.1.2021.13.15.1.1.3.17|65|0
1.3.6.1.4.1.2021.13.15.1.1.3.18|65|0
1.3.6.1.4.1.2021.13.15.1.1.3.19|65|0
1.3.6.1.4.1.2021.13.15.1.1.3.20|65|0
1.3.6.1.4.1.2021.13.15.1.1.3.21|65|0
1.3.6.1.4.1.2021.13.15.1.1.3.22|65|0
1.3.6.1.4.1.2021.13.15.1.1.3.23|65|0
1.3.6.1.4.1.2021.13.15.1.1.3.24|65|0
1.3.6.1.4.1.2021.13.15.1.1.3.25|65|437437440
1.3.6.1.4.1.2021.13.15.1.1.3.26|65|436818944
1.3.6.1.4.1.2021.13.15.1.1.3.27|65|121253888
1.3.6.1.4.1.2021.13.15.1.1.3.28|65|120631296
1.3.6.1.4.1.2021.13.15.1.1.4.1|65|0
1.3.6.1.4.1.2021.13.15.1.1.4.2|65|0
1.3.6.1.4.1.2021.13.15.1.1.4.3|65|0
1.3.6.1.4.1.2021.13.15.1.1.4.4|65|0
1.3.6.1.4.1.2021.13.15.1.1.4.5|65|0
1.3.6.1.4.1.2021.13.15.1.1.4.6|65|0
1.3.6.1.4.1.2021.13.15.1.1.4.7|65|0
1.3.6.1.4.1.2021.13.15.1.1.4.8|65|0
1.3.6.1.4.1.2021.13.15.1.1.4.9|65|0
1.3.6.1.4.1.2021.13.15.1.1.4.10|65|0
1.3.6.1.4.1.2021.13.15.1.1.4.11|65|0
1.3.6.1.4.1.2021.13.15.1.1.4.12|65|0
1.3.6.1.4.1.2021.13.15.1.1.4.13|65|0
1.3.6.1.4.1.2021.13.15.1.1.4.14|65|0
1.3.6.1.4.1.2021.13.15.1.1.4.15|65|0
1.3.6.1.4.1.2021.13.15.1.1.4.16|65|0
1.3.6.1.4.1.2021.13.15.1.1.4.17|65|0
1.3.6.1.4.1.2021.13.15.1.1.4.18|65|0
1.3.6.1.4.1.2021.13.15.1.1.4.19|65|0
1.3.6.1.4.1.2021.13.15.1.1.4.20|65|0
1.3.6.1.4.1.2021.13.15.1.1.4.21|65|0
1.3.6.1.4.1.2021.13.15.1.1.4.22|65|0
1.3.6.1.4.1.2021.13.15.1.1.4.23|65|0
1.3.6.1.4.1.2021.13.15.1.1.4.24|65|0
1.3.6.1.4.1.2021.13.15.1.1.4.25|65|1982947328
1.3.6.1.4.1.2021.13.15.1.1.4.26|65|1982947328
1.3.6.1.4.1.2021.13.15.1.1.4.27|65|223305728
1.3.6.1.4.1.2021.13.15.1.1.4.28|65|223305728
1.3.6.1.4.1.2021.13.15.1.1.5.1|65|0
1.3.6.1.4.1.2021.13.15.1.1.5.2|65|0
1.3.6.1.4.1.2021.13.15.1.1.5.3|65|0
1.3.6.1.4.1.2021.13.15.1.1.5.4|65|0
1.3.6.1.4.1.2021.13.15.1.1.5.5|65|0
1.3.6.1.4.1.2021.13.15.1.1.5.6|65|0
1.3.6.1.4.1.2021.13.15.1.1.5.7|65|0
1.3.6.1.4.1.2021.13.15.1.1.5.8|65|0
1.3.6.1.4.1.2021.13.15.1.1.5.9|65|0
1.3.6.1.4.1.2021.13.15.1.1.5.10|65|0
1.3.6.1.4.1.2021.13.15.1.1.5.11|65|0
1.3.6.1.4.1.2021.13.15.1.1.5.12|65|0
1.3.6.1.4.1.2021.13.15.1.1.5.13|65|0
1.3.6.1.4.1.2021.13.15.1.1.5.14|65|0
1.3.6.1.4.1.2021.13.15.1.1.5.15|65|0
1.3.6.1.4.1.2021.13.15.1.1.5.16|65|0
1.3.6.1.4.1.2021.13.15.1.1.5.17|65|0
1.3.6.1.4.1.2021.13.15.1.1.5.18|65|0
1.3.6.1.4.1.2021.13.15.1.1.5.19|65|0
1.3.6.1.4.1.2021.13.15.1.1.5.20|65|0
1.3.6.1.4.1.2021.13.15.1.1.5.21|65|0
1.3.6.1.4.1.2021.13.15.1.1.5.22|65|0
1.3.6.1.4.1.2021.13.15.1.1.5.23|65|0
1.3.6.1.4.1.2021.13.15.1.1.5.24|65|0
1.3.6.1.4.1.2021.13.15.1.1.5.25|65|147216
1.3.6.1.4.1.2021.13.15.1.1.5.26|65|147065
1.3.6.1.4.1.2021.13.15.1.1.5.27|65|4525
1.3.6.1.4.1.2021.13.15.1.1.5.28|65|4373
1.3.6.1.4.1.2021.13.15.1.1.6.1|65|0
1.3.6.1.4.1.2021.13.15.1.1.6.2|65|0
1.3.6.1.4.1.2021.13.15.1.1.6.3|65|0
1.3.6.1.4.1.2021.13.15.1.1.6.4|65|0
1.3.6.1.4.1.2021.13.15.1.1.6.5|65|0
1.3.6.1.4.1.2021.13.15.1.1.6.6|65|0
1.3.6.1.4.1.2021.13.15.1.1.6.7|65|0
1.3.6.1.4.1.2021.13.15.1.1.6.8|65|0
1.3.6.1.4.1.2021.13.15.1.1.6.9|65|0
1.3.6.1.4.1.2021.13.15.1.1.6.10|65|0
1.3.6.1.4.1.2021.13.15.1.1.6.11|65|0
1.3.6.1.4.1.2021.13.15.1.1.6.12|65|0
1.3.6.1.4.1.2021.13.15.1.1.6.13|65|0
1.3.6.1.4.1.2021.13.15.1.1.6.14|65|0
1.3.6.1.4.1.2021.13.15.1.1.6.15|65|0
1.3.6.1.4.1.2021.13.15.1.1.6.16|65|0
1.3.6.1.4.1.2021.13.15.1.1.6.17|65|0
1.3.6.1.4.1.2021.13.15.1.1.6.18|65|0
1.3.6.1.4.1.2021.13.15.1.1.6.19|65|0
1.3.6.1.4.1.2021.13.15.1.1.6.20|65|0
1.3.6.1.4.1.2021.13.15.1.1.6.21|65|0
1.3.6.1.4.1.2021.13.15.1.1.6.22|65|0
1.3.6.1.4.1.2021.13.15.1.1.6.23|65|0
1.3.6.1.4.1.2021.13.15.1.1.6.24|65|0
1.3.6.1.4.1.2021.13.15.1.1.6.25|65|2228402
1.3.6.1.4.1.2021.13.15.1.1.6.26|65|2111325
1.3.6.1.4.1.2021.13.15.1.1.6.27|65|943
1.3.6.1.4.1.2021.13.15.1.1.6.28|65|943
1.3.6.1.4.1.2021.13.15.1.1.9.1|2|0
1.3.6.1.4.1.2021.13.15.1.1.9.2|2|0
1.3.6.1.4.1.2021.13.15.1.1.9.3|2|0
1.3.6.1.4.1.2021.13.15.1.1.9.4|2|0
1.3.6.1.4.1.2021.13.15.1.1.9.5|2|0
1.3.6.1.4.1.2021.13.15.1.1.9.6|2|0
1.3.6.1.4.1.2021.13.15.1.1.9.7|2|0
1.3.6.1.4.1.2021.13.15.1.1.9.8|2|0
1.3.6.1.4.1.2021.13.15.1.1.9.9|2|0
1.3.6.1.4.1.2021.13.15.1.1.9.10|2|0
1.3.6.1.4.1.2021.13.15.1.1.9.11|2|0
1.3.6.1.4.1.2021.13.15.1.1.9.12|2|0
1.3.6.1.4.1.2021.13.15.1.1.9.13|2|0
1.3.6.1.4.1.2021.13.15.1.1.9.14|2|0
1.3.6.1.4.1.2021.13.15.1.1.9.15|2|0
1.3.6.1.4.1.2021.13.15.1.1.9.16|2|0
1.3.6.1.4.1.2021.13.15.1.1.9.17|2|0
1.3.6.1.4.1.2021.13.15.1.1.9.18|2|0
1.3.6.1.4.1.2021.13.15.1.1.9.19|2|0
1.3.6.1.4.1.2021.13.15.1.1.9.20|2|0
1.3.6.1.4.1.2021.13.15.1.1.9.21|2|0
1.3.6.1.4.1.2021.13.15.1.1.9.22|2|0
1.3.6.1.4.1.2021.13.15.1.1.9.23|2|0
1.3.6.1.4.1.2021.13.15.1.1.9.24|2|0
1.3.6.1.4.1.2021.13.15.1.1.9.25|2|0
1.3.6.1.4.1.2021.13.15.1.1.9.26|2|0
1.3.6.1.4.1.2021.13.15.1.1.9.27|2|0
1.3.6.1.4.1.2021.13.15.1.1.9.28|2|0
1.3.6.1.4.1.2021.13.15.1.1.10.1|2|0
1.3.6.1.4.1.2021.13.15.1.1.10.2|2|0
1.3.6.1.4.1.2021.13.15.1.1.10.3|2|0
1.3.6.1.4.1.2021.13.15.1.1.10.4|2|0
1.3.6.1.4.1.2021.13.15.1.1.10.5|2|0
1.3.6.1.4.1.2021.13.15.1.1.10.6|2|0
1.3.6.1.4.1.2021.13.15.1.1.10.7|2|0
1.3.6.1.4.1.2021.13.15.1.1.10.8|2|0
1.3.6.1.4.1.2021.13.15.1.1.10.9|2|0
1.3.6.1.4.1.2021.13.15.1.1.10.10|2|0
1.3.6.1.4.1.2021.13.15.1.1.10.11|2|0
1.3.6.1.4.1.2021.13.15.1.1.10.12|2|0
1.3.6.1.4.1.2021.13.15.1.1.10.13|2|0
1.3.6.1.4.1.2021.13.15.1.1.10.14|2|0
1.3.6.1.4.1.2021.13.15.1.1.10.15|2|0
1.3.6.1.4.1.2021.13.15.1.1.10.16|2|0
1.3.6.1.4.1.2021.13.15.1.1.10.17|2|0
1.3.6.1.4.1.2021.13.15.1.1.10.18|2|0
1.3.6.1.4.1.2021.13.15.1.1.10.19|2|0
1.3.6.1.4.1.2021.13.15.1.1.10.20|2|0
1.3.6.1.4.1.2021.13.15.1.1.10.21|2|0
1.3.6.1.4.1.2021.13.15.1.1.10.22|2|0
1.3.6.1.4.1.2021.13.15.1.1.10.23|2|0
1.3.6.1.4.1.2021.13.15.1.1.10.24|2|0
1.3.6.1.4.1.2021.13.15.1.1.10.25|2|0
1.3.6.1.4.1.2021.13.15.1.1.10.26|2|0
1.3.6.1.4.1.2021.13.15.1.1.10.27|2|0
1.3.6.1.4.1.2021.13.15.1.1.10.28|2|0
1.3.6.1.4.1.2021.13.15.1.1.11.1|2|0
1.3.6.1.4.1.2021.13.15.1.1.11.2|2|0
1.3.6.1.4.1.2021.13.15.1.1.11.3|2|0
1.3.6.1.4.1.2021.13.15.1.1.11.4|2|0
1.3.6.1.4.1.2021.13.15.1.1.11.5|2|0
1.3.6.1.4.1.2021.13.15.1.1.11.6|2|0
1.3.6.1.4.1.2021.13.15.1.1.11.7|2|0
1.3.6.1.4.1.2021.13.15.1.1.11.8|2|0
1.3.6.1.4.1.2021.13.15.1.1.11.9|2|0
1.3.6.1.4.1.2021.13.15.1.1.11.10|2|0
1.3.6.1.4.1.2021.13.15.1.1.11.11|2|0
1.3.6.1.4.1.2021.13.15.1.1.11.12|2|0
1.3.6.1.4.1.2021.13.15.1.1.11.13|2|0
1.3.6.1.4.1.2021.13.15.1.1.11.14|2|0
1.3.6.1.4.1.2021.13.15.1.1.11.15|2|0
1.3.6.1.4.1.2021.13.15.1.1.11.16|2|0
1.3.6.1.4.1.2021.13.15.1.1.11.17|2|0
1.3.6.1.4.1.2021.13.15.1.1.11.18|2|0
1.3.6.1.4.1.2021.13.15.1.1.11.19|2|0
1.3.6.1.4.1.2021.13.15.1.1.11.20|2|0
1.3.6.1.4.1.2021.13.15.1.1.11.21|2|0
1.3.6.1.4.1.2021.13.15.1.1.11.22|2|0
1.3.6.1.4.1.2021.13.15.1.1.11.23|2|0
1.3.6.1.4.1.2021.13.15.1.1.11.24|2|0
1.3.6.1.4.1.2021.13.15.1.1.11.25|2|0
1.3.6.1.4.1.2021.13.15.1.1.11.26|2|0
1.3.6.1.4.1.2021.13.15.1.1.11.27|2|0
1.3.6.1.4.1.2021.13.15.1.1.11.28|2|0
1.3.6.1.4.1.2021.13.15.1.1.12.1|70|0
1.3.6.1.4.1.2021.13.15.1.1.12.2|70|0
1.3.6.1.4.1.2021.13.15.1.1.12.3|70|0
1.3.6.1.4.1.2021.13.15.1.1.12.4|70|0
1.3.6.1.4.1.2021.13.15.1.1.12.5|70|0
1.3.6.1.4.1.2021.13.15.1.1.12.6|70|0
1.3.6.1.4.1.2021.13.15.1.1.12.7|70|0
1.3.6.1.4.1.2021.13.15.1.1.12.8|70|0
1.3.6.1.4.1.2021.13.15.1.1.12.9|70|0
1.3.6.1.4.1.2021.13.15.1.1.12.10|70|0
1.3.6.1.4.1.2021.13.15.1.1.12.11|70|0
1.3.6.1.4.1.2021.13.15.1.1.12.12|70|0
1.3.6.1.4.1.2021.13.15.1.1.12.13|70|0
1.3.6.1.4.1.2021.13.15.1.1.12.14|70|0
1.3.6.1.4.1.2021.13.15.1.1.12.15|70|0
1.3.6.1.4.1.2021.13.15.1.1.12.16|70|0
1.3.6.1.4.1.2021.13.15.1.1.12.17|70|0
1.3.6.1.4.1.2021.13.15.1.1.12.18|70|0
1.3.6.1.4.1.2021.13.15.1.1.12.19|70|0
1.3.6.1.4.1.2021.13.15.1.1.12.20|70|0
1.3.6.1.4.1.2021.13.15.1.1.12.21|70|0
1.3.6.1.4.1.2021.13.15.1.1.12.22|70|0
1.3.6.1.4.1.2021.13.15.1.1.12.23|70|0
1.3.6.1.4.1.2021.13.15.1.1.12.24|70|0

1.3.6.1.4.1.2021.13.15.1.1.12.25|70|4732404736
1.3.6.1.4.1.2021.13.15.1.1.12.26|70|4731786240
1.3.6.1.4.1.2021.13.15.1.1.12.27|70|121253888
1.3.6.1.4.1.2021.13.15.1.1.12.28|70|120631296
1.3.6.1.4.1.2021.13.15.1.1.13.1|70|0
1.3.6.1.4.1.2021.13.15.1.1.13.2|70|0
1.3.6.1.4.1.2021.13.15.1.1.13.3|70|0
1.3.6.1.4.1.2021.13.15.1.1.13.4|70|0
1.3.6.1.4.1.2021.13.15.1.1.13.5|70|0
1.3.6.1.4.1.2021.13.15.1.1.13.6|70|0
1.3.6.1.4.1.2021.13.15.1.1.13.7|70|0
1.3.6.1.4.1.2021.13.15.1.1.13.8|70|0
1.3.6.1.4.1.2021.13.15.1.1.13.9|70|0
1.3.6.1.4.1.2021.13.15.1.1.13.10|70|0
1.3.6.1.4.1.2021.13.15.1.1.13.11|70|0
1.3.6.1.4.1.2021.13.15.1.1.13.12|70|0
1.3.6.1.4.1.2021.13.15.1.1.13.13|70|0
1.3.6.1.4.1.2021.13.15.1.1.13.14|70|0
1.3.6.1.4.1.2021.13.15.1.1.13.15|70|0
1.3.6.1.4.1.2021.13.15.1.1.13.16|70|0
1.3.6.1.4.1.2021.13.15.1.1.13.17|70|0
1.3.6.1.4.1.2021.13.15.1.1.13.18|70|0
1.3.6.1.4.1.2021.13.15.1.1.13.19|70|0
1.3.6.1.4.1.2021.13.15.1.1.13.20|70|0
1.3.6.1.4.1.2021.13.15.1.1.13.21|70|0
1.3.6.1.4.1.2021.13.15.1.1.13.22|70|0
1.3.6.1.4.1.2021.13.15.1.1.13.23|70|0
1.3.6.1.4.1.2021.13.15.1.1.13.24|70|0
1.3.6.1.4.1.2021.13.15.1.1.13.25|70|27752751104
1.3.6.1.4.1.2021.13.15.1.1.13.26|70|27752751104
1.3.6.1.4.1.2021.13.15.1.1.13.27|70|223305728
1.3.6.1.4.1.2021.13.15.1.1.13.28|70|223305728
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
	public function test_list_storage_index_and_description() {
		$this->assertCommand("-H @endpoint@ -C mycommunity", array(
		), array(
			'### Fetched storage data over NET-SNMP ###',
			'Index:	Description:',
			'1	Physical memory',
			'3	Virtual memory',
			'6	Memory buffers',
			'7	Cached memory',
			'10	Swap space',
			'31	/',
			'35	/dev/shm'
		), 0);
	}
	public function test_list_storage_index_and_description_with_T_parameter() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -T storage_list", array(
		), array(
			'### Fetched storage data over NET-SNMP ###',
			'Index:	Description:',
			'1	Physical memory',
			'3	Virtual memory',
			'6	Memory buffers',
			'7	Cached memory',
			'10	Swap space',
			'31	/',
			'35	/dev/shm'
		), 0);
	}
	public function test_valid_index_option_without_extra_parameters() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -f -i /", array(
		), array(
			'OK: 32% of storage used'
		), 0);
	}
	public function test_valid_index_option_with_default_T_parameter() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -f -i / -T storage_percent_used", array(
		), array(
			'OK: 32% of storage used'
		), 0);
	}
	public function test_valid_index_option_with_perfdata() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -i /", array(
		), array(
			"OK: 32% of storage used |'/'=32%;;"
		), 0);
	}
	public function test_invalid_I_option() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -i invalid", array(
		), array(
			"Invalid input string for -i (Use -T storage_list for a list of valid strings)."
		), 3);
	}
	public function test_invalid_T_option() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -i /dev/shm -T this_doesnt_exist", array(
		), array(
			"Wrong parameter for -T."
		), 3);
	}
	
/** 
 * Storage percent used
 */
	public function test_percent_storage_used_OK() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -i / -w 50 -c 75", array(
		), array(
			"OK: 32% of storage used |'/'=32%;50;75"
		), 0);
	}
	public function test_percent_storage_used_WARNING() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -i / -w 25 -c 75", array(
		), array(
			"WARNING: 32% of storage used |'/'=32%;25;75"
		), 1);
	}
	public function test_percent_storage_used_CRITICAL() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -i / -w 25 -c 30", array(
		), array(
			"CRITICAL: 32% of storage used |'/'=32%;25;30"
		), 2);
	}
/** 
 * Storage percent left
 */
	public function test_percent_storage_left_OK() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -i / -w 75 -c 95 -T storage_percent_left", array(
		), array(
			"OK: 67% of storage left |'/'=67%;75;95"
		), 0);
	}
	public function test_percent_storage_left_WARNING() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -i / -w 25 -c 95 -T storage_percent_left", array(
		), array(
			"WARNING: 67% of storage left |'/'=67%;25;95"
		), 1);
	}
	public function test_percent_storage_left_CRITICAL() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -i / -w 25 -c 30 -T storage_percent_left", array(
		), array(
			"CRITICAL: 67% of storage left |'/'=67%;25;30"
		), 2);
	}
/** 
 * Storage MB used
 */
	public function test_mb_storage_used_OK() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -i / -w 3000 -c 4000 -T storage_mb_used", array(
		), array(
			"OK: 2627MB of storage used |'/'=2627MB;3000;4000"
		), 0);
	}
	public function test_mb_storage_used_WARNING() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -f -i / -w 2500 -c 4000 -T storage_mb_used", array(
		), array(
			"WARNING: 2627MB of storage used"
		), 1);
	}
	public function test_mb_storage_used_CRITICAL() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -f -i / -w 2500 -c 2600 -T storage_mb_used", array(
		), array(
			"CRITICAL: 2627MB of storage used"
		), 2);
	}
/** 
 * Storage MB left
 */
	public function test_mb_storage_left_OK() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -i / -w 5500 -c 6000 -T storage_mb_left", array(
		), array(
			"OK: 5434MB of storage left |'/'=5434MB;5500;6000"
		), 0);
	}
	public function test_mb_storage_left_WARNING() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -f -i / -w 4000 -c 6000 -T storage_mb_left", array(
		), array(
			"WARNING: 5434MB of storage left"
		), 1);
	}
	public function test_mb_storage_left_CRITICAL() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -f -i / -w 4000 -c 4500 -T storage_mb_left", array(
		), array(
			"CRITICAL: 5434MB of storage left"
		), 2);
	}
/** 
 * Storage GB used/left
 */
	public function test_gb_storage_used_OK() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -i / -w 3 -c 4 -T storage_gb_used", array(
		), array(
			"OK: 3GB of storage used |'/'=3GB;3;4"
		), 0);
	}
	public function test_gb_storage_left_OK() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -i / -w 6 -c 7 -T storage_gb_left", array(
		), array(
			"OK: 5GB of storage left |'/'=5GB;6;7"
		), 0);
	}
/** 
 * Monitoring-plugins standard warning and critical interval
 */
	public function test_monitoring_plugins_standard_warning_critical_OK() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -i / -w 30:50 -c \~:75", array(
		), array(
			"OK: 32% of storage used |'/'=32%;30:50;~:75"
		), 0);
	}
	public function test_monitoring_plugins_standard_warning_critical_WARNING() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -i / -w 40:45 -c 30:75", array(
		), array(
			"WARNING: 32% of storage used |'/'=32%;40:45;30:75"
		), 1);
	}
	public function test_monitoring_plugins_standard_warning_critical_CRITICAL() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -i / -w 40:45 -c @30:40", array(
		), array(
			"CRITICAL: 32% of storage used |'/'=32%;40:45;@30:40"
		), 2);
	}
/** 
 * IO Testing
 */
	public function test_list_io_index_and_description() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -T io_1", array(
		), array(
			'### Fetched IO data over NET-SNMP ###',
			'Index:	Description:',
			'1	ram0',
			'2	ram1',
			'3	ram2',
			'4	ram3',
			'5	ram4',
			'6	ram5',
			'7	ram6',
			'8	ram7',
			'9	ram8',
			'10	ram9',
			'11	ram10',
			'12	ram11',
			'13	ram12',
			'14	ram13',
			'15	ram14',
			'16	ram15',
			'17	loop0',
			'18	loop1',
			'19	loop2',
			'20	loop3',
			'21	loop4',
			'22	loop5',
			'23	loop6',
			'24	loop7',
			'25	sda',
			'26	sda1',
			'27	sdb',
			'28	sdb1'
		), 0);
	}
	public function test_list_io_index_and_description_with_T_parameter() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -T io_list", array(
		), array(
			'### Fetched IO data over NET-SNMP ###',
			'Index:	Description:',
			'1	ram0',
			'2	ram1',
			'3	ram2',
			'4	ram3',
			'5	ram4',
			'6	ram5',
			'7	ram6',
			'8	ram7',
			'9	ram8',
			'10	ram9',
			'11	ram10',
			'12	ram11',
			'13	ram12',
			'14	ram13',
			'15	ram14',
			'16	ram15',
			'17	loop0',
			'18	loop1',
			'19	loop2',
			'20	loop3',
			'21	loop4',
			'22	loop5',
			'23	loop6',
			'24	loop7',
			'25	sda',
			'26	sda1',
			'27	sdb',
			'28	sdb1'
		), 0);
	}
	public function test_io_invalid_I_option() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -i invalid -T io_1", array(
		), array(
			"Invalid input string for -i (Use -T io_list for a list of valid strings)."
		), 3);
	}
	
	public function test_io_load_1_option() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -i sda -T io_1 -w 60 -c 70", array(
			"1.3.6.1.4.1.2021.13.15.1.1.9.25" => array(2,50)
		), array(
			"OK: 50% IO Load-1 |'sda'=50%;60;70"
		), 0);
	}
	public function test_io_load_5_option() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -f -i sda -T io_5", array(
			"1.3.6.1.4.1.2021.13.15.1.1.10.25" => array(2,100)
		), array(
			'OK: 100% IO Load-5'
		), 0);
	}
	public function test_io_load_15_option() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -f -i sda -T io_15", array(
			"1.3.6.1.4.1.2021.13.15.1.1.11.25" => array(2,1)
		), array(
			'OK: 1% IO Load-15'
		), 0);
	}
	public function test_io_load_5_OK() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -i sda -T io_5 -w 60 -c 80", array(
			"1.3.6.1.4.1.2021.13.15.1.1.10.25" => array(2,50)
		), array(
			"OK: 50% IO Load-5 |'sda'=50%;60;80"
		), 0);
	}
	public function test_io_load_5_WARNING() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -i sda -T io_5 -w 60 -c 80", array(
			"1.3.6.1.4.1.2021.13.15.1.1.10.25" => array(2,75)
		), array(
			"WARNING: 75% IO Load-5 |'sda'=75%;60;80"
		), 1);
	}
	public function test_io_load_5_CRITICAL() {
		$this->assertCommand("-H @endpoint@ -C mycommunity -i sda -T io_5 -w 60 -c 80", array(
			"1.3.6.1.4.1.2021.13.15.1.1.10.25" => array(2,100)
		), array(
			"CRITICAL: 100% IO Load-5 |'sda'=100%;60;80"
		), 2);
	}
/**
 * No arguments, usage and help
 */
	public function test_no_arguments() {
		$this->assertCommand("", array(
		), array(
			'check_snmp_disk: Could not parse arguments',
			'Usage:',
			'check_snmp_disk -H <ip_address> -C <snmp_community> -i <name of disk>',
			'[-w <warn_range>] [-c <crit_range>] [-t <timeout>] [-T <type>]',
			'([-P snmp version] [-N context] [-L seclevel] [-U secname]',
			'[-a authproto] [-A authpasswd] [-x privproto] [-X privpasswd])'
		), 3);
	}
	public function test_usage() {
		$this->assertCommand("-u", array(
		), array(
			'Usage:',
			'check_snmp_disk -H <ip_address> -C <snmp_community> -i <name of disk>',
			'[-w <warn_range>] [-c <crit_range>] [-t <timeout>] [-T <type>]',
			'([-P snmp version] [-N context] [-L seclevel] [-U secname]',
			'[-a authproto] [-A authpasswd] [-x privproto] [-X privpasswd])'
		), 0);
	}
	public function disable_test_help() {
		$this->assertCommand("-h", array(
		), array(
			''
		), 0);
	}
}
