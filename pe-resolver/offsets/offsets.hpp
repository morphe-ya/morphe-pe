#pragma once

#include "../includes/includes.hpp"

namespace offsets {
	inline uint32_t image_file_name{ };
	inline uint32_t active_threads{ };
	inline uint32_t unique_process_id{ };
	inline uint32_t active_process_links{ };

	bool initialize( );
}