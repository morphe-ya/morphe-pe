#include "pe.hpp"

#include "../offsets/offsets.hpp"
#include "../utils/process/process.hpp"

namespace pe {
	bool copy_pe_header( HANDLE pid, uint64_t base, PIMAGE_NT_HEADERS* out_nt_headers, PUCHAR* out_buffer ) {
		NTSTATUS status{ };
		PEPROCESS process{ };
		size_t bytes{ };

		if ( !NT_SUCCESS( PsLookupProcessByProcessId( pid, &process ) ) ) {
			DbgPrintEx( 0, 0, "[1]\n" );
			return false;
		}

		IMAGE_DOS_HEADER dos_header{ };
		MmCopyVirtualMemory( process, ( void* )base, PsGetCurrentProcess( ), &dos_header, sizeof( IMAGE_DOS_HEADER ), KernelMode, &bytes );

		if ( dos_header.e_magic != IMAGE_DOS_SIGNATURE ) {
			DbgPrintEx( 0, 0, "[2]\n" );
			return false;
		}

		ULONG header_size{ 0x1000 };
		MmCopyVirtualMemory( process, ( void* )( base + dos_header.e_lfanew + FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader.SizeOfHeaders ) ), PsGetCurrentProcess( ), &header_size, sizeof( header_size ), KernelMode, &bytes );

		if ( header_size < 0x200 )
			header_size = 0x1000;

		const auto& buffer = ( UCHAR* )ExAllocatePoolWithTag( NonPagedPoolNx, header_size, 'zaya' );

		if ( !buffer ) {
			ObDereferenceObject( process );
			DbgPrintEx( 0, 0, "[3]\n" );
			return false;
		}

		ObDereferenceObject( process );

		if ( !NT_SUCCESS( MmCopyVirtualMemory( process, ( void* )base, PsGetCurrentProcess( ), buffer, header_size, KernelMode, &bytes ) ) ) {
			ExFreePoolWithTag( buffer, 'zaya' );
			DbgPrintEx( 0, 0, "[4]\n" );
			return false;
		}

		const auto& nt_headers = RtlImageNtHeader( buffer );

		if ( !nt_headers ) {
			ExFreePoolWithTag( buffer, 'zaya' );
			DbgPrintEx( 0, 0, "[5]\n" );
			return false;
		}

		*out_nt_headers = nt_headers;
		*out_buffer = buffer;

		return true;
	}

	void get_nt_headers( IMAGE_NT_HEADERS* nt_headers ) {
		const auto& file_header = nt_headers->FileHeader;

		DbgPrintEx( 0, 0, "[*] *** FILE_HEADER ***\n" );

		DbgPrintEx( 0, 0, "    [+] Machine: 0x%04x | NumberOfSections: %u\n", file_header.Machine, file_header.NumberOfSections );
		DbgPrintEx( 0, 0, "    [+] TimeDateStamp: 0x%08x | Characteristics: 0x%04x\n", file_header.TimeDateStamp, file_header.Characteristics );
		DbgPrintEx( 0, 0, "    [+] NumberOfSymbols: %u | SizeOfOptionalHeader: %u\n", file_header.NumberOfSymbols, file_header.SizeOfOptionalHeader );
	}

	void get_sections( const IMAGE_NT_HEADERS* nt_headers ) {
		DbgPrintEx( 0, 0, "[*] *** SECTIONS ***\n" );

		const auto& section = IMAGE_FIRST_SECTION( nt_headers );

		for ( int idx{ }; idx < nt_headers->FileHeader.NumberOfSections; ++idx ) {
			char name[ 9 ]{ };
			RtlCopyMemory( name, section[ idx ].Name, 8 );

			DbgPrintEx( 0, 0, "[+]    %s [%i] VA: 0x%p Size: 0x%p\n", name, idx, section[ idx ].VirtualAddress, section[ idx ].Misc.VirtualSize );
		}
	}

	void get_import_directory( HANDLE pid, uint64_t base, const IMAGE_NT_HEADERS* nt_headers ) {
		const auto& data_directory = nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];

		if ( !data_directory.VirtualAddress 
			 || !data_directory.Size )
			return;

		IMAGE_IMPORT_DESCRIPTOR descriptors[ 256 ]{ };

		if ( !process::read( pid, base, nt_headers, data_directory.VirtualAddress, descriptors, data_directory.Size ) )
			return;

		DbgPrintEx( 0, 0, "[*] *** IMPORT_DIRECTORY ***\n" );

		for ( uint32_t idx{ }; idx < 256; ++idx ) {
			const auto& descriptor = descriptors[ idx ];

			if ( !descriptor.OriginalFirstThunk
				 && !descriptor.FirstThunk
				 && !descriptor.Name )
				continue;

			char dll_name[ 256 ]{ };

			if ( descriptor.Name )
				process::read( pid, base, nt_headers, descriptor.Name, dll_name, sizeof( dll_name ) - 1 );

			DbgPrintEx( 0, 0, "[+]    DLL: %s IAT: 0x%p\n", dll_name[ 0 ] ? dll_name : "Empty",
					  descriptor.OriginalFirstThunk, descriptor.FirstThunk );

			if ( descriptor.OriginalFirstThunk ) {
				uint64_t thunks[ 256 ]{ };

				if ( !process::read( pid, base, nt_headers, descriptor.OriginalFirstThunk, thunks, sizeof( thunks ) ) )
					continue;

				for ( uint32_t idx{ }; idx < _countof( thunks ) && thunks[ idx ]; ++idx ) {
					const auto& thunk = thunks[ idx ];

					if ( !thunk )
						continue;

					if ( thunk & IMAGE_ORDINAL_FLAG64 )
						DbgPrintEx( 0, 0, "[+]    Ordinal: %p\n", thunk & 0xffff );
					else {
						IMAGE_IMPORT_BY_NAME import{ };

						if ( !process::read( pid, base, nt_headers, ( ULONG )thunks[ idx ], & import, sizeof( IMAGE_IMPORT_BY_NAME ) ) )
							continue;

						char procedure[ 128 ]{ };

						if ( !process::read( pid, base, nt_headers, ( ULONG )thunks[ idx ] + FIELD_OFFSET( IMAGE_IMPORT_BY_NAME, Name ), procedure, sizeof( procedure ) - 1 ) )
							continue;

						DbgPrintEx( 0, 0, "[+]    %s [HINT: %x]\n", procedure, import.Hint );
					}
				}
			}
		}
	}

	void get_tls_directory( HANDLE pid, uint64_t base, const IMAGE_NT_HEADERS* nt_headers ) {
		const auto& data_directory = nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_TLS ];
		
		if ( !data_directory.VirtualAddress
			 || !data_directory.Size )
			return;

		IMAGE_TLS_DIRECTORY64 tls_directory{ };

		if ( !process::read( pid, base, nt_headers, data_directory.VirtualAddress, &tls_directory, data_directory.Size ) )
			return;

		DbgPrintEx( 0, 0, "[*] *** TLS DIRECTORY ***\n" );

		DbgPrintEx( 0, 0, "    [+] StartAddressOfRawData: 0x%p EndAddressOfRawData: 0x%p\n", tls_directory.StartAddressOfRawData, tls_directory.EndAddressOfRawData );
		DbgPrintEx( 0, 0, "    [+] AddressOfIndex: 0x%p AddressOfCallBacks: 0x%p\n", tls_directory.AddressOfIndex, tls_directory.AddressOfCallBacks );
	}

	void get( HANDLE pid, uint64_t base ) {
		PIMAGE_NT_HEADERS nt_headers{ };
		PUCHAR buffer{ };

		if ( !copy_pe_header( pid, base, &nt_headers, &buffer ) ) {
			DbgPrintEx( 0, 0, "[*] failed copy pe header\n" );
			return;
		}

		const auto& dos_header = reinterpret_cast< PIMAGE_DOS_HEADER >( buffer );

		if ( dos_header->e_magic != IMAGE_DOS_SIGNATURE ) {
			DbgPrintEx( 0, 0, "[*] invalid dos header\n" );
			return;
		}

		get_nt_headers( nt_headers );
		get_sections( nt_headers );
		get_import_directory( pid, base, nt_headers );
		get_tls_directory( pid, base, nt_headers );
	}
}