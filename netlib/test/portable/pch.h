// pch.h: minimal precompiled-header stand-in for the portable native test runner.
//
// The Windows netlib-tests project resolves "pch.h" to netlib-tests/pch.h. Platform-independent
// test sources (those that include only Windows-free netlib headers) are also built by
// run-portable-tests.sh with this directory first on the include path, so they can run on any
// host with a C++20 compiler and GoogleTest.

#pragma once

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

#include <gtest/gtest.h>
