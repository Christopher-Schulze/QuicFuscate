cmake_minimum_required(VERSION 3.10)

# CLI-Anwendung
add_executable(cli-app main.cpp)
target_link_libraries(cli-app quicsand-core)
