#include <tap.h>
#define MP_TEST_PROGRAM 1
#include "../check_snmp_disk.c"

/*
 * there is a bit of magic constants in this file, but it's all
 * well-defined in the HOST-RESOURCES-TYPES mib
 */
oid hrStorageOther[] =         { 1, 3, 6, 1, 2, 1, 25, 2, 1, 1 };
oid hrStorageRam[] =           { 1, 3, 6, 1, 2, 1, 25, 2, 1, 2 };
oid hrStorageVirtualMemory[] = { 1, 3, 6, 1, 2, 1, 25, 2, 1, 3 };
oid hrStorageFixedDisk[] =     { 1, 3, 6, 1, 2, 1, 25, 2, 1, 4 };
oid hrStorageRemovableDisk[] = { 1, 3, 6, 1, 2, 1, 25, 2, 1, 5 };
oid hrStorageFloppyDisk[] =    { 1, 3, 6, 1, 2, 1, 25, 2, 1, 6 };
oid hrStorageCompactDisc[] =   { 1, 3, 6, 1, 2, 1, 25, 2, 1, 7 };
oid hrStorageRamDisk[] =       { 1, 3, 6, 1, 2, 1, 25, 2, 1, 8 };
oid hrStorageFlashMemory[] =   { 1, 3, 6, 1, 2, 1, 25, 2, 1, 9 };
oid hrStorageNetworkDisk[] =   { 1, 3, 6, 1, 2, 1, 25, 2, 1, 10 };

#define TRY_OID2TYPE(v, oid) ok(v == oid2storage_type(oid, ARRAY_SIZE(oid)), #oid " must convert to " #v)
#define TRY_TYPE2STR(v, str) ok(0 == strcmp(storage_type_name(v), #str), #str " must come from converting " #v)
#define TRY_PARSEBYTES(v, str, e) \
	do { \
		ok(v == parse_bytes(str, &err), "parse_bytes(" #str ") == " #v""); \
		ok(err == e, "parse_bytes(" #str ") has errorcode " #e""); \
	} while (0)
#define TRY_PARSE_DISK_TYPES(v, str) ok((v) == parse_disk_types(str), #str " should yield mask " #v)
int main(int argc, char *argv[])
{
	int err;

	plan_tests(45);
	TRY_OID2TYPE(1, hrStorageOther);
	TRY_OID2TYPE(2, hrStorageRam);
	TRY_OID2TYPE(3, hrStorageVirtualMemory);
	TRY_OID2TYPE(4, hrStorageFixedDisk);
	TRY_OID2TYPE(5, hrStorageRemovableDisk);
	TRY_OID2TYPE(6, hrStorageFloppyDisk);
	TRY_OID2TYPE(7, hrStorageCompactDisc);
	TRY_OID2TYPE(8, hrStorageRamDisk);
	TRY_OID2TYPE(9, hrStorageFlashMemory);
	TRY_OID2TYPE(10, hrStorageNetworkDisk);

	TRY_TYPE2STR(1, Other);
	TRY_TYPE2STR(2, Ram);
	TRY_TYPE2STR(3, VirtualMemory);
	TRY_TYPE2STR(4, FixedDisk);
	TRY_TYPE2STR(5, RemovableDisk);
	TRY_TYPE2STR(6, FloppyDisk);
	TRY_TYPE2STR(7, CompactDisc);
	TRY_TYPE2STR(8, RamDisk);
	TRY_TYPE2STR(9, FlashMemory);
	TRY_TYPE2STR(10, NetworkDisk);

	TRY_PARSEBYTES(1024, "1k", 0);
	TRY_PARSEBYTES(1024 * 1024, "1m", 0);
	TRY_PARSEBYTES(1739461754.88, "1.62g", 0);
	TRY_PARSEBYTES(1739461754.88, "1.62GiB", 0);

	/*
	 * first test each type individually and then chain some together
	 * We don't bother with all !n combinations, since that would
	 * be 3.6 million tests.
	 */
	TRY_PARSE_DISK_TYPES(1 << STORAGE_TYPE_Other, "Other");
	TRY_PARSE_DISK_TYPES(1 << STORAGE_TYPE_Ram, "RAM");
	TRY_PARSE_DISK_TYPES(1 << STORAGE_TYPE_VirtualMemory, "virtual");
	TRY_PARSE_DISK_TYPES(1 << STORAGE_TYPE_FixedDisk, "fixed");
	TRY_PARSE_DISK_TYPES(1 << STORAGE_TYPE_RemovableDisk, "removable");
	TRY_PARSE_DISK_TYPES(1 << STORAGE_TYPE_FloppyDisk, "floppy");
	TRY_PARSE_DISK_TYPES(1 << STORAGE_TYPE_CompactDisc, "cd");
	TRY_PARSE_DISK_TYPES(1 << STORAGE_TYPE_RamDisk, "ramdisk");
	TRY_PARSE_DISK_TYPES(1 << STORAGE_TYPE_FlashMemory, "flash");
	TRY_PARSE_DISK_TYPES(1 << STORAGE_TYPE_NetworkDisk, "net");
	TRY_PARSE_DISK_TYPES(STORAGE_MASK_DISK, "disk");
	TRY_PARSE_DISK_TYPES(STORAGE_MASK_MEM, "mem");
	TRY_PARSE_DISK_TYPES(STORAGE_MASK_DISK | (1 << STORAGE_TYPE_Other), "other,disk");
	TRY_PARSE_DISK_TYPES((1 << STORAGE_TYPE_FlashMemory) | (1 << STORAGE_TYPE_CompactDisc), "flash,cd,dvd");
	TRY_PARSE_DISK_TYPES((1 << STORAGE_TYPE_RemovableDisk), "removable");
	TRY_PARSE_DISK_TYPES((1 << STORAGE_TYPE_NetworkDisk) | (1 << STORAGE_TYPE_Ram) | (1 << STORAGE_TYPE_VirtualMemory), "net,ram,vmem");
	TRY_PARSE_DISK_TYPES((1 << STORAGE_TYPE_NetworkDisk) | (1 << STORAGE_TYPE_FixedDisk) | (1 << STORAGE_TYPE_RemovableDisk), "net,fixed,removable");

	return exit_status();
}
