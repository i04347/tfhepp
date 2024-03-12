set(CMAKE_CXX_FLAGS "-std=c++17 -march=armv8-a+crypto -O3 -g -funroll-loops -Wall -Wextra -pedantic -Wno-sign-compare -fpermissive -fPIC -no-pie"
)
set(SPQLIOX_AARCH64_SRCS fft_processor_spqliox_aarch64.cpp)
set(SPQLIOX_AARCH64_HEADERS fft_processor_spqliox_aarch64.h
                            spqliox_aarch64_impl.h)

add_library(spqliox_aarch64 STATIC ${SPQLIOX_AARCH64_SRCS}
                                   ${SPQLIOX_AARCH64_HEADERS})

target_include_directories(spqliox_aarch64 PUBLIC /root/HE3DB/thirdparty/TFHEpp/include)
install(TARGETS spqliox_aarch64
	EXPORT spqliox_aarch64Targets
	LIBRARY DESTINATION lib
)
