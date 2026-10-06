# A downstream project as a GUI or another tool would write it: nothing from the libstein
# tree, only the installed package. CI installs libstein to a prefix, configures this with
# -DCMAKE_PREFIX_PATH=<prefix>, builds it and runs it on a fixture image.
cmake_minimum_required(VERSION 3.25)
project(stein_consumer LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(stein 0.1 CONFIG REQUIRED)

add_executable(stein_consumer main.cpp)
target_link_libraries(stein_consumer PRIVATE stein::probe stein::block stein::core)

option(STEIN_CONSUMER_SANITIZE "Link with ASan/UBSan (needed when libstein was built with them)" OFF)
if(STEIN_CONSUMER_SANITIZE)
  target_compile_options(stein_consumer PRIVATE -fsanitize=address,undefined)
  target_link_options(stein_consumer PRIVATE -fsanitize=address,undefined)
endif()

enable_testing()
add_test(NAME consumer_probe COMMAND stein_consumer ${STEIN_CONSUMER_IMAGE})
if(WIN32)
  set_tests_properties(consumer_probe PROPERTIES ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${CMAKE_PREFIX_PATH}/bin")
endif()
