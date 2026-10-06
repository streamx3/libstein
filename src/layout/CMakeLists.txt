include(SteinLayout)

stein_add_module(layout
  SOURCES
    src/spec.cpp
    src/node.cpp
    src/describe.cpp
  PUBLIC_DEPS stein::core)

file(GLOB STEIN_MANIFESTS CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/formats/*.layout.toml)
stein_add_layouts(stein_layout ${STEIN_MANIFESTS})

stein_add_test(test_layout
  SOURCES ../core/tests/test_main.cpp tests/test_layout.cpp
  DEPS stein::layout)
