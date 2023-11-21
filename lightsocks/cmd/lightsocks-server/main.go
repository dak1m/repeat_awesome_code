package main

import (
	"fmt"
	"github.com/phayes/freeport"
	"lightsocks"
	"lightsocks/cmd"
	"lightsocks/server"
	"log"
	"net"
	"os"
	"strconv"
)

var version = "master"

func main() {
	log.SetFlags(log.Lshortfile)

	// 优先从环境变量中获取监听端口
	port, err := strconv.Atoi(os.Getenv("LIGHTSOCKS_SERVER_PORT"))
	if err != nil {
		port, err = freeport.GetFreePort()
	}
	if err != nil {
		// 随机端口失败就采用 7448
		port = 7448
	}
	config := &cmd.Config{
		ListenAddr: fmt.Sprintf(":%d", port),
		Password:   lightsocks.RandPassword(),
	}
	config.ReadConfig()
	config.SaveConfig()
	lsServer, err := server.NewLsServer(config.Password, config.ListenAddr)
	if err != nil {
		log.Fatalln(err)
	}
	log.Fatalln(lsServer.Listen(func(listenAddr *net.TCPAddr) {
		log.Println(fmt.Sprintf(`
lightsocks-server:%s 启动成功，配置如下：
服务监听地址：
%s
密码：
%s`, version, listenAddr, config.Password))
	}))
}
