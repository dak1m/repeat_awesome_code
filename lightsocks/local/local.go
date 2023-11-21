package local

import (
	"lightsocks"
	"log"
	"net"
)

/*
本地端的职责是:
1. 监听来自本机浏览器的代理请求；
2. 转发前加密数据；
3. 转发socket数据到墙外代理服务端；
4. 把服务端返回的数据转发给用户的浏览器。
*/

type LsLocal struct {
	Cipher                 *lightsocks.Cipher
	ListenAddr, RemoteAddr *net.TCPAddr
}

func NewLsLocal(password, listenAddr, remoteAddr string) (*LsLocal, error) {
	bsPassword, err := lightsocks.ParsePassword(password)
	if err != nil {
		return nil, err
	}
	structListenAddr, err := net.ResolveTCPAddr("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	structRemoteAddr, err := net.ResolveTCPAddr("tcp", remoteAddr)
	if err != nil {
		return nil, err
	}
	return &LsLocal{
		Cipher:     lightsocks.NewCipher(bsPassword),
		ListenAddr: structListenAddr,
		RemoteAddr: structRemoteAddr,
	}, nil
}

// Listen 本地端启动监听，接收来自本机浏览器的连接
func (l *LsLocal) Listen(didListen func(listenAddr *net.TCPAddr)) error {
	return lightsocks.ListenEncryTCP(l.ListenAddr, l.Cipher, l.handleConn, didListen)
}

func (l *LsLocal) handleConn(userConn *lightsocks.SecureTCPConn) {
	defer userConn.Close()
	proxyServer, err := lightsocks.DialEncryptedTCP(l.RemoteAddr, l.Cipher)
	if err != nil {
		log.Println(err)
		return
	}
	defer proxyServer.Close()

	// 进行转发
	// 从 proxyServer 读取数据发送到 localUser
	go func() {
		err := proxyServer.DecodeCopy(userConn)
		if err != nil {
			// 可能出现的网络波动，等任何错误发生时，直接关闭用户的连接
			_ = proxyServer.Close()
			_ = userConn.Close()
		}
	}()
	// 从 localUser 发送数据发送到 proxyServer，这里因为处在翻墙阶段出现网络错误的概率更大
	_ = userConn.EncodeCopy(proxyServer)
}
