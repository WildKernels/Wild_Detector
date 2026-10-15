cmake_minimum_required(VERSION 3.22.1)
project("wild")

add_library(wild SHARED wild_jni.c)

# library mode of the engine: includes <jni.h>, drops main()
target_compile_definitions(wild PRIVATE LKMDET_LIBRARY)
target_link_libraries(wild log)
