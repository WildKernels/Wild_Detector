cmake_minimum_required(VERSION 3.22.1)
project("wild")

add_library(wild SHARED wild_jni.c)

target_link_libraries(wild log)
