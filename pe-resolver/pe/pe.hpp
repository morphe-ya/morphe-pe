#pragma once

#include "../includes/includes.hpp"

namespace pe {
	bool copy_pe_header( HANDLE, uint64_t, PIMAGE_NT_HEADERS*, PUCHAR* );

	void get_nt_headers( IMAGE_NT_HEADERS* );
	void get_sections( const IMAGE_NT_HEADERS* );
	void get_import_directory( HANDLE, uint64_t, const IMAGE_NT_HEADERS* );
	void get_tls_directory( HANDLE, uint64_t, const IMAGE_NT_HEADERS* );
	void get( HANDLE, uint64_t );
}