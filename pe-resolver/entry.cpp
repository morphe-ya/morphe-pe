#include "includes/includes.hpp"

#include "offsets/offsets.hpp"
#include "utils/process/process.hpp"
#include "pe/pe.hpp"

NTSTATUS driver_entry( ) {
	if ( !offsets::initialize( ) ) {
		DbgPrintEx( 0, 0, "[*] failed to initialize offsets\n" );
		return STATUS_UNSUCCESSFUL;
	}

	const auto& pid = process::get_process_id( L"cmd.exe" );

	if ( !pid ) {
		DbgPrintEx( 0, 0, "[*] failed to get pid\n" );
		return STATUS_UNSUCCESSFUL;
	}

	const auto& address = process::get_base_address( pid );

	if ( !address ) {
		DbgPrintEx( 0, 0, "[*] failed to get address\n" );
		return STATUS_UNSUCCESSFUL;
	}

	DbgPrintEx( 0, 0, "[+] pid: %p\n", ( uint64_t )pid );
	DbgPrintEx( 0, 0, "[+] address: %p\n", address );

	pe::get( pid, address );

	return STATUS_SUCCESS;
}