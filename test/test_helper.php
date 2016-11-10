<?php
# abstract phpunit doesn't instantiate this
abstract class test_helper extends PHPUnit_Framework_TestCase
{
	private $snmpsimroot = "/tmp";
	private $snmpsimroot_current = false;
	private $snmpv3 = false;
	public $snmp_community = 'mycommunity';
	# snmp usage arguments are the same for all plugins
	public $snmp_usage = <<<EOF
  -H <hostname> [-t <timeout>] [-p <port>]
  [-P 1|2c|3] [-C <community>]
  [-L authPriv|authNoPriv|noAuthNoPriv] [-U <secname>]
  [-a SHA|MD5] [-A <authpass>] [-x AES|DES] [-X <privpass>]
SNMP defaults: -p 161 -P 3 -L authPriv -a SHA -x AES
EOF;

	/*
	 * Since we use a dataProvider for our tests the __construct needs to take
	 * $name, $data, $dataName and send it to the parent constructur. If this
	 * isn't done the dataProvider will break and you will get the error
	 * message: Missing argument 1
	 */
	public function __construct(
		$name = NULL, array $data = array(), $dataName = ''
	)
	{
		putenv("MP_STATE_PATH=/tmp/test_dir_for_check_by_snmp");
		$plugin = __DIR__ . "/../src/" . $this->plugin;
		if (!file_exists($plugin)) {
			$plugin =  __DIR__ . "/../../../opt/plugins/" . $this->plugin;
		}
		$this->snmpsimd = $this->find_in_path(array('snmpsimd', 'snmpsimd.py'));
		$this->plugin = $plugin;
		$this->snmpsimroot =
			$this->snmpsimroot . "/" . basename($this->plugin) . "_test/";
		if (!$this->get_snmp_data()) {
			echo "\$this->get_snmp_data() not set in test. exiting\n";
			exit(1);
		}
		parent::__construct($name, $data, $dataName);
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

	/*
	 * Each time we start snmpsim we also create a folder with a uniqe name
	 * which contains a .snmprec file containing the SNMP data. For SNMPv3 we
	 * use a small workaround since the check_by_snmp_* plugins can't send the
	 * context name. The name of the file and folder will be the same and is
	 * hardcoded until we can change it to use the context instead.
	 */
	private function start_snmpsim($snmpdata)
	{
		if ($this->snmpsimroot_current !== false) {
			$this->stop_snmpsim();
		}
		$this->snmpsimroot_current = $this->snmpsimroot.md5(uniqid())."/";
		@mkdir($this->snmpsimroot_current, 0777, true);
		@mkdir($this->snmpsimroot_current."data", 0777, true);
		if ($this->snmpv3 === true) {
			$recfile = $this->snmpsimroot_current .
				"data/1.3.6.1.6.1.1.0/127.0.0.1.snmprec"; // workaround
			@mkdir($this->snmpsimroot_current.
				"data/1.3.6.1.6.1.1.0", 0777, true);
		}
		else {
			$recfile = $this->snmpsimroot_current .
				"data/" . $this->snmp_community . ".snmprec";
		}
		file_put_contents($recfile, $snmpdata);

		$command = $this->snmpsimd .
			" --daemonize".
			" --pid-file=".$this->snmpsimroot_current . "pidfile".
			" --agent-udpv4-endpoint=127.0.0.1:21161".
			" --v3-user=auth_none".
			" --v3-user=auth_md5 --v3-auth-key=md5_pass".
			" --v3-auth-proto=MD5".
			" --v3-user=auth_md5_des".
			" --v3-auth-key=md5_pass --v3-priv-key=des_crypt".
			" --v3-auth-proto=MD5 --v3-priv-proto=DES".
			" --v3-user=auth_md5_aes".
			" --v3-auth-key=md5_pass --v3-priv-key=aes_crypt".
			" --v3-auth-proto=MD5 --v3-priv-proto=AES".
			" --v3-user=auth_sha --v3-auth-key=sha_pass".
			" --v3-auth-proto=SHA".
			" --v3-user=auth_sha_des".
			" --v3-auth-key=sha_pass --v3-priv-key=des_crypt".
			" --v3-auth-proto=SHA --v3-priv-proto=DES".
			" --v3-user=auth_sha_aes".
			" --v3-auth-key=sha_pass --v3-priv-key=aes_crypt".
			" --v3-auth-proto=SHA --v3-priv-proto=AES".
			" --data-dir=".$this->snmpsimroot_current . "data/";
		system($command, $returnval);
	}

	public function stop_snmpsim()
	{
		if ($this->snmpsimroot_current === false) {
			return;
		}
		posix_kill(intval(file_get_contents(
			$this->snmpsimroot_current . "pidfile")
		), SIGINT);
		$this->snmpsimroot_current = false;
	}

	public function setUp()
	{
		$this->snmp_community = md5(uniqid());
	}

	public function tearDown()
	{
		$this->stop_snmpsim();
		exec("rm -rf " . $this->snmpsimroot_current);
		exec("rm -rf " . getenv('MP_STATE_PATH'));
	}

	public function run_command($args, &$output, &$error, &$return)
	{
		$cmd = $this->plugin . " " . $args;
		$descriptorspec = array(
			0 => array("pipe", "r"), // stdin
			1 => array("pipe", "w"), // stdout
			2 => array("pipe", "w")  // stderr
		);
		$process = proc_open($cmd, $descriptorspec, $pipes);
		if(!is_resource($process)) {
			return -1;
		}

		fclose($pipes[0]); // Nothing for stdin

		$output = stream_get_contents($pipes[1]);
		fclose($pipes[1]);

		$error = stream_get_contents($pipes[2]);
		fclose($pipes[2]);

		$return = proc_close($process);
	}

	private function generate_incorrect_snmpdata()
	{
		$incorrect = "1.3.6.1.4.1.2021.13.15.1.1.1.1|2|1";
		return $incorrect;
	}

	private function generate_without_unused_snmpdata()
	{
		$incorrect = "1.3.6.1.4.1.2021.13.15.1.1.1.1|2|1
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
			1.3.6.1.4.1.2021.13.15.1.1.1.29|2|29
			1.3.6.1.4.1.2021.13.15.1.1.1.30|2|30
			1.3.6.1.4.1.2021.13.15.1.1.1.31|2|31
			1.3.6.1.4.1.2021.13.15.1.1.1.32|2|32
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
			1.3.6.1.4.1.2021.13.15.1.1.2.25|4|sr0
			1.3.6.1.4.1.2021.13.15.1.1.2.26|4|fd0
			1.3.6.1.4.1.2021.13.15.1.1.2.27|4|sda
			1.3.6.1.4.1.2021.13.15.1.1.2.28|4|sda1
			1.3.6.1.4.1.2021.13.15.1.1.2.29|4|sda2
			1.3.6.1.4.1.2021.13.15.1.1.2.30|4|sda3
			1.3.6.1.4.1.2021.13.15.1.1.2.31|4|sdb
			1.3.6.1.4.1.2021.13.15.1.1.2.32|4|sdb1
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
			1.3.6.1.4.1.2021.13.15.1.1.3.25|65|0
			1.3.6.1.4.1.2021.13.15.1.1.3.26|65|0
			1.3.6.1.4.1.2021.13.15.1.1.3.27|65|573330432
			1.3.6.1.4.1.2021.13.15.1.1.3.28|65|204156928
			1.3.6.1.4.1.2021.13.15.1.1.3.29|65|711446528
			1.3.6.1.4.1.2021.13.15.1.1.3.30|65|3949880320
			1.3.6.1.4.1.2021.13.15.1.1.3.31|65|3230336000
			1.3.6.1.4.1.2021.13.15.1.1.3.32|65|3226612736
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
			1.3.6.1.4.1.2021.13.15.1.1.4.25|65|0
			1.3.6.1.4.1.2021.13.15.1.1.4.26|65|0
			1.3.6.1.4.1.2021.13.15.1.1.4.27|65|2066960384
			1.3.6.1.4.1.2021.13.15.1.1.4.28|65|745472
			1.3.6.1.4.1.2021.13.15.1.1.4.29|65|546734080
			1.3.6.1.4.1.2021.13.15.1.1.4.30|65|1519480832
			1.3.6.1.4.1.2021.13.15.1.1.4.31|65|1077686272
			1.3.6.1.4.1.2021.13.15.1.1.4.32|65|1077686272
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
			1.3.6.1.4.1.2021.13.15.1.1.5.25|65|0
			1.3.6.1.4.1.2021.13.15.1.1.5.26|65|0
			1.3.6.1.4.1.2021.13.15.1.1.5.27|65|1381423
			1.3.6.1.4.1.2021.13.15.1.1.5.28|65|3710
			1.3.6.1.4.1.2021.13.15.1.1.5.29|65|62914
			1.3.6.1.4.1.2021.13.15.1.1.5.30|65|1314504
			1.3.6.1.4.1.2021.13.15.1.1.5.31|65|73676638
			1.3.6.1.4.1.2021.13.15.1.1.5.32|65|73676343
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
			1.3.6.1.4.1.2021.13.15.1.1.6.25|65|0
			1.3.6.1.4.1.2021.13.15.1.1.6.26|65|0
			1.3.6.1.4.1.2021.13.15.1.1.6.27|65|11644961
			1.3.6.1.4.1.2021.13.15.1.1.6.28|65|607
			1.3.6.1.4.1.2021.13.15.1.1.6.29|65|69113
			1.3.6.1.4.1.2021.13.15.1.1.6.30|65|11575241
			1.3.6.1.4.1.2021.13.15.1.1.6.31|65|145945759
			1.3.6.1.4.1.2021.13.15.1.1.6.32|65|145945759";
		$incorrect = preg_replace("#^\s+#", "", $incorrect);
		return $incorrect;
	}

	/*
	 * Run most tests with SNMPv2c and SNMPv3, we use this function to provide
	 * the dataProvider with data.
	 */
	public function snmpArgsProvider()
	{
		return array(
			'SNMPv2c'        => array("-H @endpoint@ @community@"),
			'SNMPv3_none'    => array("-H @endpoint@ @context@ -L noAuthNoPriv".
				" -U auth_none"),
			'SNMPv3_md5'     => array("-H @endpoint@ @context@ -L authNoPriv".
				" -U auth_md5     -a MD5 -A md5_pass"),
			'SNMPv3_md5_des' => array("-H @endpoint@ @context@ -L authPriv".
				" -U auth_md5_des -a MD5 -A md5_pass -x DES -X des_crypt"),
			'SNMPv3_md5_aes' => array("-H @endpoint@ @context@ -L authPriv".
				" -U auth_md5_aes -a MD5 -A md5_pass -x AES -X aes_crypt"),
			'SNMPv3_sha'     => array("-H @endpoint@ @context@ -L authNoPriv".
				" -U auth_sha     -a SHA -A sha_pass"),
			'SNMPv3_sha_des' => array("-H @endpoint@ @context@ -L authPriv".
				" -U auth_sha_des -a SHA -A sha_pass -x DES -X des_crypt"),
			'SNMPv3_sha_aes' => array("-H @endpoint@ @context@ -L authPriv".
				" -U auth_sha_aes -a SHA -A sha_pass -x AES -X aes_crypt")
		);
	}

	private function generate_snmpdata($snmpdata_diff)
	{
		$snmpdata = $this->get_snmp_data();
		$snmpdata_arr = array();
		foreach( explode("\n", $snmpdata) as $line) {
			$line = preg_replace("#^\s+#", "", $line);
			if($line == "")
				continue;
			list($oid, $type, $value) = explode("|", $line, 3);
			$snmpdata_arr[$oid] = array($type, $value);
		}

		$this->assertNotEmpty($snmpdata_arr);

		foreach($snmpdata_diff as $oid => $newval) {
			if($oid[0] == "/"){
					foreach($snmpdata_arr as $old_oid => $old_val) {
						if(!preg_match($oid, $old_oid))
							continue;
						if($newval === false)
							unset($snmpdata_arr[$old_oid]);
						else
							$snmpdata_arr[$old_oid] = $newval;
					}
			}
			elseif($newval === false)
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

	public function assertCommandIncorrectSnmp(
		$conn_args, $args, $expectedoutput, $expectedreturn
	) {
		$args = $conn_args . " " . $args;
		if (strpos($args, "@context@")) {
			$this->snmpv3 = true;
		}
		else {
			$this->snmpv3 = false;
		}
		$args = str_replace("@context@", "", $args);
		$args = str_replace("@endpoint@", "127.0.0.1:21161", $args);
		$args = str_replace("@community@", "-C ".$this->snmp_community, $args);
		$this->start_snmpsim($this->generate_incorrect_snmpdata());
		$this->run_command($args, $output, $error, $return);

		if(is_array($expectedoutput))
			$expectedoutput = implode("\n", $expectedoutput);
		$output = trim($output);

		$this->assertEquals("", $error);
		$this->assertEquals($expectedoutput, $output);
		$this->assertEquals($expectedreturn, $return);
	}

	public function assertCommandMissingUnusedData(
		$conn_args, $args, $expectedoutput, $expectedreturn
	) {
		$args = $conn_args . " " . $args;
		if (strpos($args, "@context@")) {
			$this->snmpv3 = true;
		}
		else {
			$this->snmpv3 = false;
		}
		$args = str_replace("@context@", "", $args);
		$args = str_replace("@endpoint@", "127.0.0.1:21161", $args);
		$args = str_replace("@community@", "-C ".$this->snmp_community, $args);
		$this->start_snmpsim($this->generate_without_unused_snmpdata());
		$this->run_command($args, $output, $error, $return);

		if(is_array($expectedoutput))
			$expectedoutput = implode("\n", $expectedoutput);
		$output = trim($output);

		$this->assertEquals("", $error);
		$this->assertEquals($expectedoutput, $output);
		$this->assertEquals($expectedreturn, $return);
	}

	public function assertCommand(
		$conn_args, $args, $snmpdata_diff, $expectedoutput, $expectedreturn
	) {
		$args = $conn_args . " " . $args;
		if (strpos($args, "@context@")) {
			$this->snmpv3 = true;
		}
		else {
			$this->snmpv3 = false;
		}
		$args = str_replace("@context@", "", $args);
		$args = str_replace("@endpoint@", "127.0.0.1:21161", $args);
		$args = str_replace("@community@", "-C ".$this->snmp_community, $args);
		$this->start_snmpsim($this->generate_snmpdata($snmpdata_diff));
		$this->run_command($args, $output, $error, $return);

		if(is_array($expectedoutput))
			$expectedoutput = implode("\n", $expectedoutput);
		$output = trim($output);

		$this->assertEquals("", $error);
		$this->assertEquals($expectedoutput, $output);
		$this->assertEquals($expectedreturn, $return);
	}

	#####
	#
	# Tests common for all plugins
	#
	public function test_version_has_op5()
	{
		$this->run_command("-V", $output, $error, $return);
		$this->run_command("--version", $output2, $error2, $return2);
		$this->assertEquals($output, $output2);
		$this->assertEquals($return, $return2);
		$this->assertEquals($return, 0);
		$in_str = strstr($output, "op5") !== False;
		$this->assertEquals($in_str, True);
	}

	public function test_help_works()
	{
		$this->run_command("--help", $output, $error, $return);
		$this->run_command("-h", $output2, $error2, $return2);
		$this->assertEquals($output, $output2);
		$this->assertEquals($return, $return2);
		$this->assertEquals($return, 0);
	}

	public function test_invalid_option()
	{
		$this->run_command("-f", $output, $error, $return);
		$this->assertStringEndsWith("invalid option -- 'f'", trim($error));
		$this->assertEquals($return, 3);
	}
}
