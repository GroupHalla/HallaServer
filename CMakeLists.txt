cmake_minimum_required(VERSION 3.21)

project(HallaServer VERSION 1.1.27 LANGUAGES CXX)

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
)
target_include_directories(halla-server PRIVATE src shared)
target_link_libraries(halla-server PRIVATE ${QT_LIBS} OpenSSL::Crypto)

# --- ferramenta de teste de protocolo (CLI) ---
add_executable(halla-nettest tools/nettest.cpp)
target_include_directories(halla-nettest PRIVATE shared)
target_link_libraries(halla-nettest PRIVATE ${QT_LIBS})

set_target_properties(halla-server halla-nettest PROPERTIES
    WIN32_EXECUTABLE FALSE
    OUTPUT_NAME_DEBUG halla-server-d
)

install(TARGETS halla-server RUNTIME DESTINATION bin)
