# Tunnel Proxy

## Specification

Using low level programming language of your choice (C / C++ / Rust / Go) 
write a CLI program for OS of your choice, which will redirect all of your UDP traffic trough a [SOCKS5](http://tools.ietf.org/html/rfc1928) proxy.

Program should be started by specifying proxy ip and port: for egz.:
```
$ tunproxy 10.10.10.10 1080
or
$ tunproxy 10.10.10.10:1080
```

## Requirements
- Use some kind of `tun/tap` interface to capture network traffic.
- Provide README, explaining how to compile, setup and use the program. Specify operating system it is designed for.
- Program should automatically setup and cleanup `tun/tap` interface.

## Bonus 

- Use non-blocking IO.
- Specify add a way to test your program (Vagrant, etc..).
- Implement some kind of logging to see proxied traffic
- Capture and also proxy TCP traffic.
- Any extra features.

## Notes

- You can use any 3rd party libraries/frameworks (although you may need to explain why it's needed, it may also limit ability to judge your skills)
- If program only proxies UDP packets, all other network traffic should be unaffected.
