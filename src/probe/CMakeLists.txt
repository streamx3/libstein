stein_add_module(probe
  SOURCES src/topology.cpp
  PUBLIC_DEPS stein::core stein::block stein::pt stein::fs stein::container)

stein_add_test(test_probe
  SOURCES ../core/tests/test_main.cpp tests/test_probe.cpp
  DEPS stein::probe)
