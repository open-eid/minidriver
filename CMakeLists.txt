cmake_minimum_required(VERSION 2.6)
project(esteidcm)

# Custom cmake modules
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules")
set(CNG_INCLUDE_DIR "C:/Program Files/Microsoft CNG Development Kit/Include")
include(InstallSettings)
find_package(SmartCardpp REQUIRED)

add_definitions(
    -D_UNICODE
    -DUNICODE
    -D_CRT_SECURE_NO_DEPRECATE
)

# disable incremental linking to work around a missing MSVCR90D.dll with
# debug builds
SET(CMAKE_MODULE_LINKER_FLAGS_DEBUG "/debug /INCREMENTAL:NO")
SET(CMAKE_SHARED_LINKER_FLAGS_DEBUG "/debug /INCREMENTAL:NO")
SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "/debug /INCREMENTAL:NO")

if(USE_STATIC_RUNTIME)
    message(STATUS "Building with static MSVC runtime")
    foreach(flag_var
            CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE
            CMAKE_CXX_FLAGS_MINSIZEREL CMAKE_CXX_FLAGS_RELWITHDEBINFO)
        if(${flag_var} MATCHES "/MD")
            string(REGEX REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
        endif(${flag_var} MATCHES "/MD")
    endforeach(flag_var)
endif(USE_STATIC_RUNTIME)

include_directories(${SMARTCARDPP_INCLUDE_DIR} ${CNG_INCLUDE_DIR})

set(esteidcm_SRCS
    esteidcm.cpp
    esteidcm.def
    esteidcm.rc
    notimplemented.cpp
    precompiled.cpp
)

add_library(esteidcm SHARED ${esteidcm_SRCS}) 
target_link_libraries(esteidcm ${SMARTCARDPP_LIBRARIES} ws2_32)
install(TARGETS esteidcm DESTINATION ${INSTALL_TARGETS_DEFAULT_ARGS})
install(FILES install/esteidcm_x86.inf install/esteidcm_x64.inf DESTINATION ${BIN_INSTALL_DIR})
