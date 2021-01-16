# tunproxy

TUN proxy implementation using C on Ubuntu 20.04.01 LTS

# building
1. sudo apt install gcc
2. sudo apt install make
3. make

# running
1. `./tunproxy 127.0.0.1 1080` or `./tunproxy 127.0.0.1:1080` starts proxy tunnel on provided ip and port  
2. `./tunproxy` prints cli usage  

# static analysis
run cppcheck script to analyse code for errors / warnings / style mistakes  
1. `touch static_analysis_result.txt`
2. `./cppcheck/cppcheck_run.sh`
