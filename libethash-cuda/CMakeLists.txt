# A custom command and target to turn the CUDA kernel into a byte array header
# The normal build depends on it properly and if the kernel file is changed, then
# a rebuild of libethash-cuda should be triggered

add_custom_command(
	OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/CUDAMiner_kernel.h
	COMMAND ${CMAKE_COMMAND} ARGS
	-DTXT2STR_SOURCE_FILE="${CMAKE_CURRENT_SOURCE_DIR}/CUDAMiner_kernel.cu"
	-DTXT2STR_VARIABLE_NAME=CUDAMiner_kernel
	-DTXT2STR_HEADER_FILE="${CMAKE_CURRENT_BINARY_DIR}/CUDAMiner_kernel.h"
	-P "${CMAKE_CURRENT_SOURCE_DIR}/../cmake/txt2str.cmake"
	COMMENT "Generating CUDA Kernel"
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/CUDAMiner_kernel.cu
)
add_custom_target(cuda_kernel DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/CUDAMiner_kernel.h ${CMAKE_CURRENT_SOURCE_DIR}/CUDAMiner_kernel.cu)

find_package(CUDA REQUIRED)

set(CUDA_NVCC_FLAGS ${CUDA_NVCC_FLAGS};--ptxas-options=-v;-lineinfo;-use_fast_math)
list(APPEND CUDA_NVCC_FLAGS -allow-unsupported-compiler)
list(APPEND CUDA_NVCC_FLAGS -Xcompiler "/D_ALLOW_COMPILER_AND_STL_VERSION_MISMATCH")

if (NOT MSVC)
	list(APPEND CUDA_NVCC_FLAGS "--disable-warnings")
endif()

list(APPEND CUDA_NVCC_FLAGS_RELEASE -O3)
list(APPEND CUDA_NVCC_FLAGS_DEBUG -G)

if(COMPUTE AND (COMPUTE GREATER 0))
	set(_ethash_cuda_arches ${COMPUTE})
else()
	# Default: cover Pascal refresh (sm_61) through current Blackwell (sm_120)
	set(_ethash_cuda_arches 61 62 70 72 75 80 86 87 89 90)
	if(NOT CUDA_VERSION VERSION_LESS 12.0)
		list(APPEND _ethash_cuda_arches 100 101)
	endif()
	if(NOT CUDA_VERSION VERSION_LESS 12.8)
		list(APPEND _ethash_cuda_arches 120)
	endif()
endif()

list(REMOVE_DUPLICATES _ethash_cuda_arches)

set(_ethash_cuda_highest_arch 0)
foreach(_arch IN LISTS _ethash_cuda_arches)
	list(APPEND CUDA_NVCC_FLAGS "-gencode arch=compute_${_arch},code=sm_${_arch}")
	if(_arch GREATER _ethash_cuda_highest_arch)
		set(_ethash_cuda_highest_arch ${_arch})
	endif()
endforeach()
if(_ethash_cuda_highest_arch GREATER 0)
	list(APPEND CUDA_NVCC_FLAGS "-gencode arch=compute_${_ethash_cuda_highest_arch},code=compute_${_ethash_cuda_highest_arch}")
endif()

file(GLOB sources CUDAMiner.cpp CUDAMiner_cuda.cu)
file(GLOB headers CUDAMiner.h CUDAMiner_cuda.h ${CMAKE_CURRENT_BINARY_DIR}/CUDAMiner_kernel.h)

cuda_add_library(ethash-cuda STATIC ${sources} ${headers})
add_dependencies(ethash-cuda cuda_kernel)
# Cmake doesn't handle nvrtc automatically
find_library(CUDA_nvrtc_LIBRARY NAMES nvrtc PATHS ${CUDA_TOOLKIT_ROOT_DIR} PATH_SUFFIXES lib64 lib/x64 lib64/stubs lib/x64/stubs lib NO_DEFAULT_PATH)
find_library(CUDA_cuda_LIBRARY NAMES cuda PATHS ${CUDA_TOOLKIT_ROOT_DIR} PATH_SUFFIXES lib64 lib/x64 lib64/stubs lib/x64/stubs lib NO_DEFAULT_PATH)
target_link_libraries(ethash-cuda ethcore ethash progpow Boost::thread)
target_link_libraries(ethash-cuda ${CUDA_nvrtc_LIBRARY} ${CUDA_cuda_LIBRARY})
target_include_directories(ethash-cuda PUBLIC ${CUDA_INCLUDE_DIRS})
target_include_directories(ethash-cuda PRIVATE .. ${CMAKE_CURRENT_BINARY_DIR})
