add_executable(stein main.cpp)
target_link_libraries(stein PRIVATE stein::pt stein::fs stein::block stein::layout stein::core stein::compiler_flags)
set_target_properties(stein PROPERTIES FOLDER "stein/tools")
