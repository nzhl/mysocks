# mysocks
Simple Shadowsocks implementation in Golang.

## Usage
```
# update your ss config
mv .env.example .env

# start client
make run

# config your Chrome extesion e.g. SwitchyOmega 
# socsks5://127.0.0.1:7788


# Or simply use it in the terminal.
export http_proxy=socks5://127.0.0.1:7788; 
export https_proxy=socks5://127.0.0.1:7788; 
curl https://www.google.com/ -v

```


## Notice
This project is for self-education purposes. Currently it only accepts SOCKS5 connections (IPV4 only) and forward requests using AES128GCM encryption. But it should be easy to expand upon.

## Demo
[![asciicast](https://asciinema.org/a/ynx88z0BL4r20aet36rABBhGY.svg)](https://asciinema.org/a/ynx88z0BL4r20aet36rABBhGY)