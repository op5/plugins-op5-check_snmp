<?php
require_once('test_helper.php');
class Check_Snmp_Disk_Test extends test_helper
{
	public $plugin = 'check_by_snmp_disk';
	public function get_snmp_data() {
		$snmpdata = "1.3.6.1.2.1.25.2.3.1.1.1|2|1
1.3.6.1.2.1.25.2.3.1.1.2|2|2
1.3.6.1.2.1.25.2.3.1.1.3|2|3
1.3.6.1.2.1.25.2.3.1.1.4|2|4
1.3.6.1.2.1.25.2.3.1.1.5|2|5
1.3.6.1.2.1.25.2.3.1.1.6|2|6
1.3.6.1.2.1.25.2.3.1.1.7|2|7
1.3.6.1.2.1.25.2.3.1.2.1|6|.1.3.6.1.2.1.25.2.1.5
1.3.6.1.2.1.25.2.3.1.2.2|6|.1.3.6.1.2.1.25.2.1.4
1.3.6.1.2.1.25.2.3.1.2.3|6|.1.3.6.1.2.1.25.2.1.7
1.3.6.1.2.1.25.2.3.1.2.4|6|.1.3.6.1.2.1.25.2.1.4
1.3.6.1.2.1.25.2.3.1.2.5|6|.1.3.6.1.2.1.25.2.1.4
1.3.6.1.2.1.25.2.3.1.2.6|6|.1.3.6.1.2.1.25.2.1.3
1.3.6.1.2.1.25.2.3.1.2.7|6|.1.3.6.1.2.1.25.2.1.2
1.3.6.1.2.1.25.2.3.1.3.1|4|A:\\
1.3.6.1.2.1.25.2.3.1.3.2|4|C:\\ Label:  Serial Number 3ec33a66
1.3.6.1.2.1.25.2.3.1.3.3|4|D:\\
1.3.6.1.2.1.25.2.3.1.3.4|4|E:\\ Label:verep002  Serial Number d4c1ea4e
1.3.6.1.2.1.25.2.3.1.3.5|4|F:\\ Label:verepmon002  Serial Number 2c0bbb0d
1.3.6.1.2.1.25.2.3.1.3.6|4|Virtual Memory
1.3.6.1.2.1.25.2.3.1.3.7|4|Physical Memory
1.3.6.1.2.1.25.2.3.1.4.1|2|0
1.3.6.1.2.1.25.2.3.1.4.2|2|4096
1.3.6.1.2.1.25.2.3.1.4.3|2|0
1.3.6.1.2.1.25.2.3.1.4.4|2|65536
1.3.6.1.2.1.25.2.3.1.4.5|2|65536
1.3.6.1.2.1.25.2.3.1.4.6|2|65536
1.3.6.1.2.1.25.2.3.1.4.7|2|65536
1.3.6.1.2.1.25.2.3.1.5.1|2|0
1.3.6.1.2.1.25.2.3.1.5.2|2|20765695
1.3.6.1.2.1.25.2.3.1.5.3|2|0
1.3.6.1.2.1.25.2.3.1.5.4|2|457700831
1.3.6.1.2.1.25.2.3.1.5.5|2|457700831
1.3.6.1.2.1.25.2.3.1.5.6|2|749559
1.3.6.1.2.1.25.2.3.1.5.7|2|655351
1.3.6.1.2.1.25.2.3.1.6.1|2|0
1.3.6.1.2.1.25.2.3.1.6.2|2|8656207
1.3.6.1.2.1.25.2.3.1.6.3|2|0
1.3.6.1.2.1.25.2.3.1.6.4|2|422935855
1.3.6.1.2.1.25.2.3.1.6.5|2|365923834
1.3.6.1.2.1.25.2.3.1.6.6|2|52659
1.3.6.1.2.1.25.2.3.1.6.7|2|54242
1.3.6.1.2.1.25.2.3.1.7.1|65|0
1.3.6.1.2.1.25.2.3.1.7.2|65|0
1.3.6.1.2.1.25.2.3.1.7.3|65|0
1.3.6.1.2.1.25.2.3.1.7.4|65|0
1.3.6.1.2.1.25.2.3.1.7.5|65|0
1.3.6.1.2.1.25.2.3.1.7.6|65|0
1.3.6.1.2.1.25.2.3.1.7.7|65|0";
		return $snmpdata;
	}

	/**
	 * @dataProvider snmpArgsProvider
	 */
	public function test_list_storage_units($conn_args) {
		$this->assertCommand($conn_args, "-D --list", array(
		), array(
			'A:\             : RemovableDisk  0K-blocks     -nan% used of 0.00bytes. 0.00bytes free',
			'C:\ Label:  Serial Number 3ec33a66: FixedDisk      4K-blocks    41.69% used of 79.21GiB. 46.19GiB free',
			'D:\             : CompactDisc    0K-blocks     -nan% used of 0.00bytes. 0.00bytes free',
			'E:\ Label:verep002  Serial Number d4c1ea4e: FixedDisk      64K-blocks    92.40% used of 27.28TiB. 2.07TiB free',
			'F:\ Label:verepmon002  Serial Number 2c0bbb0d: FixedDisk      64K-blocks    79.95% used of 27.28TiB. 5.47TiB free',
			'Virtual Memory  : VirtualMemory  64K-blocks     7.03% used of 45.75GiB. 42.54GiB free',
			'Physical Memory : Ram            64K-blocks     8.28% used of 40.00GiB. 36.69GiB free',
		), 0);
	}

	/**
	 * @dataProvider snmpArgsProvider
	 */
	public function test_list_storage_strip_descr($conn_args) {
		$this->assertCommand($conn_args, "-D --list --strip-descr :", array(
		), array(
			'A               : RemovableDisk  0K-blocks     -nan% used of 0.00bytes. 0.00bytes free',
			'C               : FixedDisk      4K-blocks    41.69% used of 79.21GiB. 46.19GiB free',
			'D               : CompactDisc    0K-blocks     -nan% used of 0.00bytes. 0.00bytes free',
			'E               : FixedDisk      64K-blocks    92.40% used of 27.28TiB. 2.07TiB free',
			'F               : FixedDisk      64K-blocks    79.95% used of 27.28TiB. 5.47TiB free',
			'Virtual Memory  : VirtualMemory  64K-blocks     7.03% used of 45.75GiB. 42.54GiB free',
			'Physical Memory : Ram            64K-blocks     8.28% used of 40.00GiB. 36.69GiB free',
		), 0);
	}
}
