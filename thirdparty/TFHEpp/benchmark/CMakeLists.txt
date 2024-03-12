option(BENCHMARK_ENABLE_GTEST_TESTS "" OFF)
option(CMAKE_BUILD_TYPE "" Release)

add_subdirectory(google-benchmark)
add_executable(bench bench.cpp)
add_executable(tfhe_tfhepp tfhe_tfhepp.cpp)

include_directories(
  /root/HE3DB/thirdparty/TFHEpp/thirdparties/cereal/include/)
target_link_libraries(bench benchmark::benchmark tfhe++)
target_link_libraries(tfhe_tfhepp tfhe++)
