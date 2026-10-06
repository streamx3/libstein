include(SteinLayout)

stein_add_module(layout
  SOURCES
    src/spec.cpp
    src/node.cpp
    src/describe.cpp
  PUBLIC_DEPS stein::core)

stein_add_layouts(stein_layout
  ${PROJECT_SOURCE_DIR}/formats/gpt.layout.toml
  ${PROJECT_SOURCE_DIR}/formats/mbr.layout.toml)

stein_add_test(test_layout
  SOURCES ../core/tests/test_main.cpp tests/test_layout.cpp
  DEPS stein::layout)
