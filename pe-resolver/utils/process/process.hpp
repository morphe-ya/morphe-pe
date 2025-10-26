#pragma once

#include "../../includes/includes.hpp"

namespace process {
	uint64_t get_base_address( HANDLE );
	HANDLE get_process_id( PCWSTR );

	bool read( HANDLE, uint64_t, const IMAGE_NT_HEADERS*, ULONG, void*, size_t );
}