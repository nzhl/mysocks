package main

import "github.com/nzhl/mysocks/client"




func main() {
  //  1. local connection => client (accept socks5)  
  //  2. connection based on private protocol
  //  3. server forward request and response to client

  client.Listen("7788")
}
