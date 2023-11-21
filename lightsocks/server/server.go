package server

import (
	"encoding/binary"
	"lightsocks"
	"net"
)

/*
服务端的职责是:
1. 监听来自本地代理客户端的请求
2. 解密本地代理客户端请求的数据，解析 SOCKS5 协议，连接用户浏览器真正想要连接的远程服务器
3. 转发用户浏览器真正想要连接的远程服务器返回的数据的加密后的内容到本地代理客户端
*/

type LsServer struct {
	Cipher     *lightsocks.Cipher
	ListenAddr *net.TCPAddr
}

func NewLsServer(password, listenAddr string) (*LsServer, error) {
	bsPassword, err := lightsocks.ParsePassword(password)
	if err != nil {
		return nil, err
	}
	structListenAddr, err := net.ResolveTCPAddr("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	return &LsServer{
		Cipher:     lightsocks.NewCipher(bsPassword),
		ListenAddr: structListenAddr,
	}, nil
}

func (l *LsServer) Listen(didListen func(listenAddr *net.TCPAddr)) error {
	return lightsocks.ListenEncryTCP(l.ListenAddr, l.Cipher, l.handleConn, didListen)
}

// 解 SOCKS5 协议
// https://www.ietf.org/rfc/rfc1928.txt

func (l *LsServer) handleConn(userConn *lightsocks.SecureTCPConn) {
	defer userConn.Close()
	buf := make([]byte, 256)
	/**
	   The localConn connects to the dstServer, and sends a ver
	   identifier/method selection message:
		          +----+----------+----------+
		          |VER | NMETHODS | METHODS  |
		          +----+----------+----------+
		          | 1  |    1     | 1 to 255 |
		          +----+----------+----------+
	   The VER field is set to X'05' for this ver of the protocol.  The
	   NMETHODS field contains the number of method identifier octets that
	   appear in the METHODS field.
	*/
	// 第一个字段VER代表Socks的版本，Socks5默认为0x05，其固定长度为1个字节
	_, err := userConn.DecodeRead(buf)
	if err != nil || buf[0] != 0x05 {
		return
	}

	/**
	   The dstServer selects from one of the methods given in METHODS, and
	   sends a METHOD selection message:

		          +----+--------+
		          |VER | METHOD |
		          +----+--------+
		          | 1  |   1    |
		          +----+--------+
	*/
	// 不需要验证，直接验证通过
	userConn.EncodeWrite([]byte{0x05, 0x00})

	/**
	  +----+-----+-------+------+----------+----------+
	  |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	  +----+-----+-------+------+----------+----------+
	  | 1  |  1  | X'00' |  1   | Variable |    2     |
	  +----+-----+-------+------+----------+----------+
	*/

	/*
		VER：代表 SOCKS 协议的版本，SOCKS 默认为0x05，其值长度为1个字节；
		REP代表响应状态码，值长度也是1个字节，有以下几种类型
		0x00 succeeded
		0x01 general SOCKS server failure
		0x02 connection not allowed by ruleset
		0x03 Network unreachable
		0x04 Host unreachable
		0x05 Connection refused
		0x06 TTL expired
		0x07 Command not supported
		0x08 Address type not supported
		0x09 to 0xFF unassigned
		RSV：保留字，值长度为1个字节
		ATYP：代表请求的远程服务器地址类型，值长度1个字节，有三种类型
		IP V4 address： 0x01
		DOMAINNAME： 0x03
		IP V6 address： 0x04
		BND.ADDR：表示绑定地址，值长度不定。
		BND.PORT： 表示绑定端口，值长度2个字节
	*/
	// 获取真正的远程服务的地址
	n, err := userConn.DecodeRead(buf)
	// n 最短的长度为7 情况为 ATYP=3 DST.ADDR占用1字节 值为0x0
	if err != nil || n < 7 {
		return
	}
	// CMD代表客户端请求的类型，值长度也是1个字节，有三种类型
	// CONNECT X'01'
	if buf[1] != 0x01 {
		// 目前只支持 CONNECT
		return
	}

	var dIP []byte
	switch buf[3] {
	case 0x01:
		//	IP V4 address: X'01'
		dIP = buf[4 : 4+net.IPv4len]
	case 0x03:
		//	DOMAINNAME: X'03'
		ipAddr, err := net.ResolveIPAddr("ip", string(buf[5:n-2]))
		if err != nil {
			return
		}
		dIP = ipAddr.IP
	case 0x04:
		//	IP V6 address: X'04'
		dIP = buf[4 : 4+net.IPv6len]
	default:
		return
	}

	dPort := buf[n-2:]
	dstAddr := &net.TCPAddr{
		IP:   dIP,
		Port: int(binary.BigEndian.Uint16(dPort)),
	}
	// 连接真正的服务器
	dstServer, err := net.DialTCP("tcp", nil, dstAddr)
	if err != nil {
		return
	} else {
		defer dstServer.Close()
		// Conn被关闭时直接清除所有数据 不管没有发送的数据
		dstServer.SetLinger(0)
		// 响应客户端连接成功
		/**
		  +----+-----+-------+------+----------+----------+
		  |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
		  +----+-----+-------+------+----------+----------+
		  | 1  |  1  | X'00' |  1   | Variable |    2     |
		  +----+-----+-------+------+----------+----------+
		*/
		// 响应客户端连接成功
		userConn.EncodeWrite([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	}
	// 转发
	// 从 localUser 读取数据发送到 dstServer
	go func() {
		err = userConn.DecodeCopy(dstServer)
		if err != nil {
			// 在 copy 的过程中可能会存在网络超时等 error 被 return，只要有一个发生了错误就退出本次工作
			dstServer.Close()
			userConn.Close()
		}
	}()
	// 从 dstServer 读取数据发送到 localUser，这里因为处在翻墙阶段出现网络错误的概率更大
	dstConn := &lightsocks.SecureTCPConn{
		ReadWriteCloser: dstServer,
		Cipher:          l.Cipher,
	}
	_ = dstConn.EncodeCopy(userConn)
}
