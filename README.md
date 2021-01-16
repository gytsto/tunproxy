# tunproxy

TUN proxy implementation using C on Ubuntu 20.04.01 LTS

# building
1. `sudo apt install gcc`
2. `sudo apt install make`
3. `make`

# running
1. `./tunproxy 127.0.0.1 1080` or `./tunproxy 127.0.0.1:1080` starts proxy tunnel on provided ip and port  
2. `./tunproxy` prints cli usage  

# static analysis
run cppcheck script to analyse code for errors / warnings / style mistakes  
1. `sudo apt install cppcheck`
2. `touch static_analysis_result.txt`
3. `./cppcheck/cppcheck_run.sh`

# features
1. tuntap interface - **working separately**
2. proxy socks5 socket - **working separately**
3. tuntap & socks5 combination - **doesn't work**

# todo
1. socks5 client interface
2. fix combination of socks5 and proxy
