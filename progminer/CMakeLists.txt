cmake_policy(SET CMP0015 NEW)

aux_source_directory(. SRC_LIST)

include_directories(BEFORE ..)

set(EXECUTABLE progminer)

file(GLOB HEADERS "*.h")

add_executable(${EXECUTABLE} ${SRC_LIST} ${HEADERS})
if(MSVC)
	target_sources(${EXECUTABLE} PRIVATE progminer.rc)
endif()

hunter_add_package(CLI11)
find_package(CLI11 CONFIG REQUIRED)

target_link_libraries(progminer PRIVATE ethcore poolprotocols devcore progminer-buildinfo CLI11::CLI11 Boost::filesystem Boost::system Boost::thread)


if(ETH_ETHASHCUDA)
    if(NOT CUDA_TOOLKIT_ROOT_DIR)
        set(CUDA_TOOLKIT_ROOT_DIR "$ENV{CUDA_TOOLKIT_ROOT_DIR}")
    endif()
    find_library(NVML_LIBRARY
        NAMES nvml
        HINTS
            "${CUDA_TOOLKIT_ROOT_DIR}/lib/x64"
            "${CUDA_TOOLKIT_ROOT_DIR}/lib64"
            "${CUDA_TOOLKIT_ROOT_DIR}/lib"
            "C:/Program Files/NVIDIA Corporation/NVSMI"
        PATHS ENV CUDA_PATH ENV CUDA_LIB_PATH
        PATH_SUFFIXES lib/x64 lib64 lib
    )
    if(NVML_LIBRARY)
        target_link_libraries(progminer PRIVATE ${NVML_LIBRARY})
        target_include_directories(progminer PRIVATE "${CUDA_TOOLKIT_ROOT_DIR}/include")
        target_compile_definitions(progminer PRIVATE USE_NVML_FAN_CONTROL)
    else()
        message(WARNING "NVML library not found. NVML fan control disabled.")
    endif()
endif()

if(ETHDBUS)
	find_package(PkgConfig)
	set( ENV{PKG_CONFIG_PATH} "$ENV{PKG_CONFIG_PATH}:/usr/lib/x86_64-linux-gnu/pkgconfig" )
	pkg_check_modules(DBUS dbus-1)
	include_directories(${DBUS_INCLUDE_DIRS})
	link_directories(${DBUS_LIBRARY_DIRS})
	target_link_libraries(progminer PRIVATE ${DBUS_LIBRARIES})
endif()

if(APICORE)
	target_link_libraries(progminer PRIVATE apicore)
endif()

include(GNUInstallDirs)
install(TARGETS progminer DESTINATION ${CMAKE_INSTALL_BINDIR})
if(MSVC)
    install(FILES $<TARGET_PDB_FILE:progminer> DESTINATION ${CMAKE_INSTALL_BINDIR} OPTIONAL)
endif()
