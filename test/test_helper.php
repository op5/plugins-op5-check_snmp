<?php
# abstract phpunit doesn't instantiate this
abstract class test_helper extends PHPUnit_Framework_TestCase
{
	private $snmpsimroot = "/tmp";
	private $snmpsimroot_current = false;
	public $snmp_community = 'mycommunity';
	# snmp usage arguments are the same for all plugins
	public $snmp_usage = <<<EOF
  -H <hostname> [-t <timeout>] [-p <port>]
  [-P 1|2c|3] [-C <community>]
  [-L authPriv|authNoPriv|noAuthNoPriv] [-U <secname>]
  [-a SHA|MD5] [-A <authpass>] [-x AES|DES] [-X <privpass>]
SNMP defaults: -p 161 -P 3 -L authPriv -a SHA -x AES
EOF;

	public function __construct()
	{
		$plugin = __DIR__ . "/../src/" . $this->plugin;
		if (!file_exists($plugin)) {
			$plugin =  __DIR__ . "/../../../opt/plugins/" . $this->plugin;
		}
		$this->snmpsimd = $this->find_in_path(array('snmpsimd', 'snmpsimd.py'));
		$this->plugin = $plugin;
		$this->snmpsimroot = $this->snmpsimroot . "/" . basename($this->plugin) . "_test/";
		if (!$this->snmpdata) {
			echo "\$this->snmpdata not set in test. exiting\n";
			exit(1);
		}
		parent::__construct();
	}

	private function find_in_path($names = array())
	{
		$path = getenv('PATH');
		$path_entries = split(':', $path);
		foreach ($path_entries as $p) {
			foreach ($names as $n) {
				if (file_exists("$p/$n")) {
					return "$p/$n";
				}
			}
		}
		return False;
	}

	private function snmpsim_recfile()
	{
		return $this->snmpsimroot_current . "/data/" . $this->snmp_community;
	}

	private function start_snmpsim($snmpdata)
	{
		if ($this->snmpsimroot_current !== false) {
			$this->stop_snmpsim();
		}
		$this->snmpsimroot_current = $this->snmpsimroot.md5(uniqid())."/";
		$recfile = $this->snmpsimroot_current . "/data/" . $this->snmp_community . ".snmprec";
		@mkdir($this->snmpsimroot_current, 0777, true);
		@mkdir($this->snmpsimroot_current."data", 0777, true);
		file_put_contents($recfile, $snmpdata);

		$command = $this->snmpsimd .
			" --daemonize".
			" --pid-file=".$this->snmpsimroot_current . "pidfile".
			" --agent-udpv4-endpoint=127.0.0.1:21161".
			" --device-dir=".$this->snmpsimroot_current . "data";
		system($command, $returnval);
	}

	public function stop_snmpsim()
	{
		if ($this->snmpsimroot_current === false) {
			return;
		}
		posix_kill(intval(file_get_contents($this->snmpsimroot_current . "pidfile")), SIGINT);
		exec("rm -rf " . $this->snmpsimroot_current);
		$this->snmpsimroot_current = false;
	}

	public function tearDown()
	{
		$this->stop_snmpsim();
	}

	public function run_command($args, &$output, &$return)
	{
		$cmd = $this->plugin . " " . $args;
		return exec($cmd, $output, $return);
	}

	private function generate_incorrect_snmpdata()
	{
		$incorrect = <<<EOF
1.
EOF;
	}

	private function generate_snmpdata($snmpdata_diff)
	{
		$snmpdata = $this->snmpdata;
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

	public function assertCommandIncorrectSnmp($args, $expectedoutput, $expectedreturn)
	{
		$this->start_snmpsim($this->generate_incorrect_snmpdata());
		$args = str_replace("@endpoint@","127.0.0.1:21161",$args);
		$args = str_replace("@community@",$this->snmp_community, $args);
		$this->run_command($args, $output, $return);

		if(is_array($expectedoutput))
			$expectedoutput = implode("\n", $expectedoutput)."\n";
		$output = implode("\n", $output)."\n";

		$this->assertEquals($expectedoutput, $output);
		$this->assertEquals($expectedreturn, $return);
	}

	public function assertCommand($args, $snmpdata_diff, $expectedoutput, $expectedreturn)
	{
		$this->start_snmpsim($this->generate_snmpdata($snmpdata_diff));
		$args = str_replace("@endpoint@", "127.0.0.1:21161", $args);
		$args = str_replace("@community@", $this->snmp_community, $args);
		$this->run_command($args, $output, $return);

		if(is_array($expectedoutput))
			$expectedoutput = implode("\n", $expectedoutput)."\n";
		$output = implode("\n", $output)."\n";

		$this->assertEquals($expectedoutput, $output);
		$this->assertEquals($expectedreturn, $return);
	}

	#####
	#
	# Tests common for all plugins
	#
	public function test_version_has_op5()
	{
		$this->run_command("-V", $output, $return);
		$this->run_command("--version", $output2, $return2);
		$this->assertEquals($output, $output2);
		$this->assertEquals($return, $return2);
		$this->assertEquals($return, 0);
		$in_str = strstr(implode("\n", $output), "op5") !== False;
		$this->assertEquals($in_str, True);
	}

	public function test_help_works()
	{
		$this->run_command("--help", $output, $return);
		$this->run_command("-h", $output2, $return2);
		$this->assertEquals($output, $output2);
		$this->assertEquals($return, $return2);
		$this->assertEquals($return, 0);
	}
}
