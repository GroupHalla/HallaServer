cmake_minimum_required(VERSION 3.21)

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" HALLA_VERSION LIMIT_COUNT 1)
string(STRIP "${HALLA_VERSION}" HALLA_VERSION)
if (NOT HALLA_VERSION MATCHES "^[0-9]+\\.[0-9]+\\.[0-9]+$")
    message(FATAL_ERROR "VERSION inválida: '${HALLA_VERSION}'")
endif()
project(HallaServer VERSION ${HALLA_VERSION} LANGUAGES CXX)
configure_file(src/Version.h.in "${CMAKE_CURRENT_BINARY_DIR}/generated/Version.h" @ONLY)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 6.2 QUIET COMPONENTS Core Network Sql)
find_package(OpenSSL REQUIRED)
if (Qt6_FOUND)
    set(QT_LIBS Qt6::Core Qt6::Network Qt6::Sql)
else()
    find_package(Qt5 5.15 REQUIRED COMPONENTS Core Network Sql)
    set(QT_LIBS Qt5::Core Qt5::Network Qt5::Sql)
endif()

add_executable(halla-server
    src/main.cpp
    src/ServerCore.cpp
    src/ServerCoreStorage.cpp
    src/ServerV3.cpp
    src/ServerQuery.cpp
    src/ClientSession.cpp
    src/VoiceRelay.cpp
    src/PasswordHash.cpp
    src/TlsCertificate.cpp
)
target_include_directories(halla-server PRIVATE src shared "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_link_libraries(halla-server PRIVATE ${QT_LIBS} OpenSSL::Crypto)

# --- ferramenta de teste de protocolo (CLI) ---
add_executable(halla-nettest tools/nettest.cpp)
target_include_directories(halla-nettest PRIVATE shared)
target_link_libraries(halla-nettest PRIVATE ${QT_LIBS})

set_target_properties(halla-server halla-nettest PROPERTIES WIN32_EXECUTABLE FALSE)
set_target_properties(halla-server PROPERTIES OUTPUT_NAME_DEBUG halla-server-d)
set_target_properties(halla-nettest PROPERTIES OUTPUT_NAME_DEBUG halla-nettest-d)

enable_testing()
add_executable(halla-selftest tests/selftest.cpp src/PasswordHash.cpp src/TlsCertificate.cpp)
target_include_directories(halla-selftest PRIVATE shared src)
target_link_libraries(halla-selftest PRIVATE ${QT_LIBS} OpenSSL::Crypto)
add_test(NAME halla-selftest COMMAND halla-selftest)

# O teste end-to-end abre sockets TLS e valida autorização/isolamento real de
# plugin_data. Mantemos em plataformas Unix, onde o encerramento por SIGTERM e
# o CLI OpenSSL usados pelo fixture são portáveis no CI oficial.
if (UNIX)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    add_test(
        NAME plugin-data-integration
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/plugin_data_integration.py
                --server $<TARGET_FILE:halla-server>
    )
    set_tests_properties(plugin-data-integration PROPERTIES TIMEOUT 90)
    add_test(
        NAME nick-persistence-integration
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/nick_persistence_integration.py
                --server $<TARGET_FILE:halla-server>
    )
    set_tests_properties(nick-persistence-integration PROPERTIES TIMEOUT 90)
    add_test(
        NAME move-bypass-integration
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/move_bypass_integration.py
                --server $<TARGET_FILE:halla-server>
    )
    set_tests_properties(move-bypass-integration PROPERTIES TIMEOUT 90)
    add_test(
        NAME whisper-cross-channel-integration
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/whisper_cross_channel_integration.py
                --server $<TARGET_FILE:halla-server>
    )
    set_tests_properties(whisper-cross-channel-integration PROPERTIES TIMEOUT 90)
    add_test(
        NAME voice-key-lifecycle-integration
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/voice_key_lifecycle_integration.py
                --server $<TARGET_FILE:halla-server>
    )
    set_tests_properties(voice-key-lifecycle-integration PROPERTIES TIMEOUT 90)
    add_test(
        NAME talking-indicator-integration
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/talking_indicator_integration.py
                --server $<TARGET_FILE:halla-server>
    )
    set_tests_properties(talking-indicator-integration PROPERTIES TIMEOUT 90)
    add_test(
        NAME nick-in-use-integration
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/nick_in_use_integration.py
                --server $<TARGET_FILE:halla-server>
    )
    set_tests_properties(nick-in-use-integration PROPERTIES TIMEOUT 90)
    add_test(
        NAME voice-relay-integration
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/voice_relay_integration.py
                --server $<TARGET_FILE:halla-server>
    )
    set_tests_properties(voice-relay-integration PROPERTIES TIMEOUT 90)
    add_test(
        NAME multi-role-icons-integration
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/multi_role_icons_integration.py
                --server $<TARGET_FILE:halla-server>
    )
    set_tests_properties(multi-role-icons-integration PROPERTIES TIMEOUT 90)
endif()

install(TARGETS halla-server RUNTIME DESTINATION bin)
