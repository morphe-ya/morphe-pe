#include "process.hpp"

#include "../../offsets/offsets.hpp"

inline void* g_process_buffer{ };
inline uint64_t g_buffer_size{ };

namespace process {
	HANDLE get_process_id( PCWSTR name ) {
		NTSTATUS status{ };
		ULONG size{ };

		status = ZwQuerySystemInformation( 5, 0, 0, &size );

		if ( status != STATUS_INFO_LENGTH_MISMATCH )
			return 0;

		if ( size > g_buffer_size ) {
			if ( g_process_buffer ) {
				ExFreePoolWithTag( g_process_buffer, 'zaya' );
				g_process_buffer = 0;
			}

			g_process_buffer = ExAllocatePoolWithTag( PagedPool, size, 'zaya' );
			g_buffer_size = size;
		}

		if ( !g_process_buffer )
			return 0;

		if ( !NT_SUCCESS( ZwQuerySystemInformation( 5, g_process_buffer, g_buffer_size, &size ) ) )
			return 0;

		auto entry = ( PSYSTEM_PROCESSES )g_process_buffer;

		UNICODE_STRING target{ };
		RtlInitUnicodeString( &target, name );

		do {
			if ( entry->ProcessName.Length ) {
				if ( RtlEqualUnicodeString( &entry->ProcessName, &target, true ) )
					return ( HANDLE )entry->ProcessId;
			}

			if ( !entry->NextEntryDelta )
				break;

			entry = ( PSYSTEM_PROCESSES )( ( BYTE* )entry + entry->NextEntryDelta );
		} while ( true );

		return 0;
	}

	uint64_t get_base_address( HANDLE pid ) {
		PEPROCESS process{ };

		if ( !NT_SUCCESS( PsLookupProcessByProcessId( pid, &process ) ) )
			return 0;

		const auto& base_address = PsGetProcessSectionBaseAddress( process );

		if ( !base_address )
			return 0;

		ObDereferenceObject( process );

		return reinterpret_cast< uint64_t >( base_address );
	}

	bool read( HANDLE pid, uint64_t base, const IMAGE_NT_HEADERS* nt_headers, ULONG rva, void* out, size_t size ) {
		PEPROCESS process{ };

		if ( !NT_SUCCESS( PsLookupProcessByProcessId( pid, &process ) ) )
			return false;

		size_t copied{ };

		if ( !NT_SUCCESS( MmCopyVirtualMemory( process, reinterpret_cast< void* >( base + rva ), PsGetCurrentProcess( ), out, size, KernelMode, &copied ) ) )
			return false;

		ObDereferenceObject( process );

		return true;
	}
}