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
		$path_entries = explode(':', $path);
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
			// detect regex in a dumb but fast way
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
