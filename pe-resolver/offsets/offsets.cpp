#include "offsets.hpp"

namespace offsets {
	bool initialize( ) {
		const auto& process = ( uint64_t )PsInitialSystemProcess;

		if ( !process )
			return false;

		for ( uint32_t idx{ }; idx < 0xFFF; ++idx ) {
			if ( !unique_process_id && !active_process_links ) {
				if ( *reinterpret_cast< uint64_t* >( process + idx ) == 4 &&
					 *reinterpret_cast< uint64_t* >( process + idx + 8 ) > 0xFFFF000000000000 ) {
					unique_process_id = idx;
					active_process_links = idx + 8;
				}
			}

			if ( !image_file_name && !active_threads ) {
				if ( *reinterpret_cast< uint64_t* >( process + idx ) > 0x0000400000000000 &&
					 *reinterpret_cast< uint64_t* >( process + idx ) < 0x0000800000000000 &&
					 *reinterpret_cast< uint64_t* >( process + idx + 0x48 ) > 0 &&
					 *reinterpret_cast< uint64_t* >( process + idx + 0x48 ) < 0xFFF ) {
					image_file_name = idx;
					active_threads = idx + 0x48;
				}
			}
		}

		if ( unique_process_id && active_process_links && image_file_name && active_threads )
			return true;

		return false;
	}
}