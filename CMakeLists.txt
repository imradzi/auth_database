cmake_minimum_required(VERSION 3.21)
project(PPOSAuthentication VERSION 0.9.0)

message("CMAKE_PREFIX_PATH = ${CMAKE_PREFIX_PATH}")

include(../cmake/common.cmake)
cmake_policy(SET CMP0091 NEW)

set(CMAKE_CXX_STANDARD 23)

SET(CMAKE_EXPORT_COMPILE_COMMANDS 1)
message("cmake_generator_platform=${CMAKE_GENERATOR_PLATFORM}")
message("cmake_cl_64=${CMAKE_CL_64}")

find_package(gRPC CONFIG REQUIRED)
find_package(Boost 1.82 COMPONENTS system filesystem program_options serialization date_time coroutine regex REQUIRED)
find_package(fmt CONFIG REQUIRED)

# Proto file PPOS
get_filename_component(ppos_proto "../protos/ppos.proto" ABSOLUTE)
get_filename_component(ppos_proto_path "${ppos_proto}" PATH)
# Generated sources

set(ppos_proto_srcs "${CMAKE_CURRENT_BINARY_DIR}/ppos.pb.cc")
set(ppos_proto_hdrs "${CMAKE_CURRENT_BINARY_DIR}/ppos.pb.h")
set(ppos_grpc_srcs "${CMAKE_CURRENT_BINARY_DIR}/ppos.grpc.pb.cc")
set(ppos_grpc_hdrs "${CMAKE_CURRENT_BINARY_DIR}/ppos.grpc.pb.h")
add_custom_command(
      OUTPUT "${ppos_proto_srcs}" "${ppos_proto_hdrs}" "${ppos_grpc_srcs}" "${ppos_grpc_hdrs}"
      COMMAND ${_PROTOBUF_PROTOC}
      ARGS --grpc_out "${CMAKE_CURRENT_BINARY_DIR}"
        --cpp_out "${CMAKE_CURRENT_BINARY_DIR}"
        -I "${ppos_proto_path}"
        --plugin=protoc-gen-grpc="${_GRPC_CPP_PLUGIN_EXECUTABLE}"
        "${ppos_proto}"
      DEPENDS "${ppos_proto}"
)

#auth_database proto
get_filename_component(auth_database_proto "../protos/auth_database.proto" ABSOLUTE)
get_filename_component(auth_database_proto_path "${auth_database_proto}" PATH)

set(auth_database_proto_srcs "${CMAKE_CURRENT_BINARY_DIR}/auth_database.pb.cc")
set(auth_database_proto_hdrs "${CMAKE_CURRENT_BINARY_DIR}/auth_database.pb.h")
set(auth_database_grpc_srcs "${CMAKE_CURRENT_BINARY_DIR}/auth_database.grpc.pb.cc")
set(auth_database_grpc_hdrs "${CMAKE_CURRENT_BINARY_DIR}/auth_database.grpc.pb.h")
add_custom_command(
      OUTPUT "${auth_database_proto_srcs}" "${auth_database_proto_hdrs}" "${auth_database_grpc_srcs}" "${auth_database_grpc_hdrs}"
      COMMAND ${_PROTOBUF_PROTOC}
      ARGS --grpc_out "${CMAKE_CURRENT_BINARY_DIR}"
        --cpp_out "${CMAKE_CURRENT_BINARY_DIR}"
        -I "${auth_database_proto_path}"
        --plugin=protoc-gen-grpc="${_GRPC_CPP_PLUGIN_EXECUTABLE}"
        "${auth_database_proto}"
      DEPENDS "${auth_database_proto}"
      COMMENT "Building auth_database protos..."
)

#auth_chat proto
get_filename_component(auth_chat_proto "../protos/auth_chat.proto" ABSOLUTE)
get_filename_component(auth_chat_proto_path "${auth_chat_proto}" PATH)

set(auth_chat_proto_srcs "${CMAKE_CURRENT_BINARY_DIR}/auth_chat.pb.cc")
set(auth_chat_proto_hdrs "${CMAKE_CURRENT_BINARY_DIR}/auth_chat.pb.h")
set(auth_chat_grpc_srcs "${CMAKE_CURRENT_BINARY_DIR}/auth_chat.grpc.pb.cc")
set(auth_chat_grpc_hdrs "${CMAKE_CURRENT_BINARY_DIR}/auth_chat.grpc.pb.h")
add_custom_command(
      OUTPUT "${auth_chat_proto_srcs}" "${auth_chat_proto_hdrs}" "${auth_chat_grpc_srcs}" "${auth_chat_grpc_hdrs}"
      COMMAND ${_PROTOBUF_PROTOC}
      ARGS --grpc_out "${CMAKE_CURRENT_BINARY_DIR}"
        --cpp_out "${CMAKE_CURRENT_BINARY_DIR}"
        -I "${auth_chat_proto_path}"
        --plugin=protoc-gen-grpc="${_GRPC_CPP_PLUGIN_EXECUTABLE}"
        "${auth_chat_proto}"
      DEPENDS "${auth_chat_proto}"
      COMMENT "Building AuthChat protos..."
)



include_directories("${CMAKE_CURRENT_BINARY_DIR}")


if (MSVC)
    set(WIN32FL WIN32)
    set(PCRE2_LIBRARIES "${VCPKG_ROOT}/installed/${VCPKG_TARGET_TRIPLET}/lib/pcre2-16.lib")
    SET(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} /MP /bigobj /D_UNICODE /DWIN32 /DNOMINMAX /DPARTIO_USE_ZLIB")
    add_compile_options(-DNO_PNG)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    #set_property(GLOBAL PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
else()
	SET(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -fno-common -pedantic -pedantic-errors -Wall -Wextra -Werror -DPARTIO_USE_ZLIB\
  -Wno-deprecated-enum-enum-conversion -Wno-missing-field-initializers -Wmissing-include-dirs -Woverloaded-virtual -Wredundant-decls \
	-Wshadow -Wswitch-default -Wundef -Wno-switch-default -Wno-unused-parameter -Wno-shadow -Wno-unused-but-set-parameter")
endif()


set_source_files_properties(${auth_database_grpc_srcs} ${auth_database_grpc_hdrs} ${auth_database_proto_srcs} ${auth_database_proto_hdrs} PROPERTIES GENERATED TRUE)
add_library(auth_database_grpc_proto ${auth_database_grpc_srcs} ${auth_database_grpc_hdrs} ${auth_database_proto_srcs} ${auth_database_proto_hdrs} ${auth_database_proto})
target_link_libraries(auth_database_grpc_proto ${_GRPC_GRPCPP} ${_PROTOBUF_LIBPROTOBUF})

#auth_chat proto
set_source_files_properties(${auth_chat_grpc_srcs} ${auth_chat_grpc_hdrs} ${auth_chat_proto_srcs} ${auth_chat_proto_hdrs} PROPERTIES GENERATED TRUE)
add_library(auth_chat_grpc_proto ${auth_chat_grpc_srcs} ${auth_chat_grpc_hdrs} ${auth_chat_proto_srcs} ${auth_chat_proto_hdrs} ${auth_chat_proto})
target_link_libraries(auth_chat_grpc_proto ${_GRPC_GRPCPP} ${_PROTOBUF_LIBPROTOBUF})

#ppos proto
set_source_files_properties(${ppos_grpc_srcs} ${ppos_grpc_hdrs} ${ppos_proto_srcs} ${ppos_proto_hdrs} PROPERTIES GENERATED TRUE)
add_library(ppos_grpc_proto ${ppos_grpc_srcs} ${ppos_grpc_hdrs} ${ppos_proto_srcs} ${ppos_proto_hdrs} ${ppos_proto})
target_link_libraries(ppos_grpc_proto ${_GRPC_GRPCPP} ${_PROTOBUF_LIBPROTOBUF})


message("plugin = ${_GRPC_CPP_PLUGIN_EXECUTABLE}")
message("reflection= ${_REFLECTION}, grpc_grpcpp = ${_GRPC_GRPCPP}, protobuf_libprotobuf = ${_PROTOBUF_LIBPROTOBUF}")
include_directories("${CMAKE_CURRENT_BINARY_DIR}")

message("cmake lib path = ${CMAKE_LIBRARY_PATH}")

if (MSVC)
    set(WIN32FL WIN32)
    set(PCRE2_LIBRARIES "${VCPKG_ROOT}/installed/${VCPKG_TARGET_TRIPLET}/lib/pcre2-16.lib")
    SET(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} /MP /bigobj /D_UNICODE /DWIN32 /DNOMINMAX")
    add_compile_options(-DNO_PNG)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    #set_property(GLOBAL PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
else()
	SET(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -fno-common -pedantic -pedantic-errors -Wall -Wextra -Werror \
  -Wno-deprecated-enum-enum-conversion -Wno-missing-field-initializers -Wmissing-include-dirs -Woverloaded-virtual -Wredundant-decls \
	-Wshadow -Wswitch-default -Wundef -Wno-switch-default -Wno-unused-parameter -Wno-shadow -Wno-unused-but-set-parameter")
endif()

function(SetIncludeDirMin LibName)
    target_include_directories(${LibName} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
endfunction()

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

file(GLOB all_SRC
    "../sqlite3/sqlite3.c" "../sqlite3/*.h" 
    "../wpSQL/wpSQLDatabase.cpp" "../wpSQL/wpSQLDatabase.h" 
    "../wpSQL/rDb.cpp" "../wpSQL/rDb.h" 
    "../wpSQL/rDb-SQLite3.cpp"
    "../wpSQL/dbbackup.cpp"
    "../wpSQL/checkSchema.cpp"
    "../wpSQL/lockTimeout.cpp"
    "../util/timefunctions.h"
    "../net/net.cpp" "../net/net.h"
    "../net/md5.cpp" "../net/md5.h"
    "../net/sha01.cpp" "../net/sha01.h"
    "../net/sha256.cpp" "../net/sha256.h"
    "../net/guid.cpp" "../net/guid.h"
    "../zip/ZIP.cpp" "../zip/ZIP.h"
    "../beast/http_server_synchronous.cpp"
    "../beast/http_client_awaitable.cpp"
    ${auth_database_grpc_srcs}
    ${auth_database_proto_srcs}
    ${ppos_proto_hdrs} 
    ${ppos_grpc_hdrs} 
    ${auth_chat_grpc_hdrs} 
    ${auth_chat_proto_hdrs} 
    "main.cpp"
    "static_definition.cpp"
    "DB/*.cpp" "DB/*.h"
    "Services/*.h"
    "Services/*.cpp"
    "PPOS_Client/*.h"
    "PPOS_Client/*.cpp"
    "process_web_command.cpp"
)

add_executable(auth_database ${WIN32FL} ${all_SRC})

if(MSVC) 
    target_link_libraries(auth_database 
        fmt::fmt-header-only ${Boost_LIBRARIES}
        ${PCRE2_LIBRARIES}
        auth_database_grpc_proto 
        ppos_grpc_proto 
        auth_chat_grpc_proto 
        ${_GRPC_GRPCPP} ${_PROTOBUF_LIBPROTOBUF}
    )

    set_target_properties(auth_database PROPERTIES LINK_FLAGS /SUBSYSTEM:CONSOLE)

else()
    target_link_libraries(auth_database
        auth_database_grpc_proto 
        ppos_grpc_proto 
        auth_chat_grpc_proto 
        ${_GRPC_GRPCPP} ${_PROTOBUF_LIBPROTOBUF}
        fmt::fmt-header-only ${Boost_LIBRARIES}
        -luuid
        -ldl
        -lssl
        -lcrypto
    )

endif()
target_include_directories(auth_database PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_include_directories(auth_database PRIVATE "${CMAKE_SOURCE_DIR}/../wpSQL")
target_include_directories(auth_database PRIVATE "${CMAKE_SOURCE_DIR}/../sqlite3")
target_include_directories(auth_database PRIVATE "${CMAKE_SOURCE_DIR}/../beast")
target_include_directories(auth_database PRIVATE "${CMAKE_SOURCE_DIR}/../util")
target_include_directories(auth_database PRIVATE "${CMAKE_SOURCE_DIR}/../net")
target_include_directories(auth_database PRIVATE "${CMAKE_SOURCE_DIR}/../zip")
target_include_directories(auth_database PRIVATE "${CMAKE_SOURCE_DIR}/DB")
target_include_directories(auth_database PRIVATE "${CMAKE_SOURCE_DIR}/Services")

target_compile_definitions(auth_database PUBLIC -D_UNICODE -DNO_REPORT -DNO_XLS -DSQLITE_ENABLE_FTS5 -DSQLITE_ENABLE_FTS4 -DPARTIO_USE_ZLIB)
