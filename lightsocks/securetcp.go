package lightsocks

import (
	"io"
	"log"
	"net"
	"sync"
)

const bufSize = 1024

var bPool sync.Pool

type SecureTCPConn struct {
	io.ReadWriteCloser
	Cipher *Cipher
}

func init() {
	bPool.New = func() interface{} {
		return make([]byte, bufSize)
	}
}

func bufferPoolGet() []byte {
	return bPool.Get().([]byte)
}

func bufferPoolPut(b []byte) {
	bPool.Put(b)
}

// DecodeRead 读取输入流解密
func (s *SecureTCPConn) DecodeRead(b []byte) (n int, err error) {
	n, err = s.Read(b)
	if err != nil {
		return
	}
	s.Cipher.decode(b[:n])
	return
}

// EncodeWrite 加密后写入输出流
func (s *SecureTCPConn) EncodeWrite(b []byte) (n int, err error) {
	s.Cipher.encode(b)
	return s.Write(b)
}

// EncodeCopy 从src中源源不断的读取原数据加密后写入到dst，直到src中没有数据可以再读取
func (s *SecureTCPConn) EncodeCopy(dst io.ReadWriteCloser) error {
	buf := bufferPoolGet()
	defer bufferPoolPut(buf)
	for {
		readCount, err := s.Read(buf)
		if err != nil {
			if err != io.EOF {
				return err
			} else {
				return nil
			}
		}
		if readCount > 0 {
			dstConn := &SecureTCPConn{
				ReadWriteCloser: dst,
				Cipher:          s.Cipher,
			}
			writeCount, err := dstConn.EncodeWrite(buf[:readCount])
			if err != nil {
				return err
			}
			if readCount != writeCount {
				return io.ErrShortWrite
			}
		}
	}
}

// DecodeCopy 从src中源源不断的读取加密后的数据解密后写入到dst，直到src中没有数据可以再读取
func (s *SecureTCPConn) DecodeCopy(dst io.Writer) error {
	buf := bufferPoolGet()
	defer bufferPoolPut(buf)
	for {
		readCount, err := s.DecodeRead(buf)
		if err != nil {
			if err != io.EOF {
				return err
			} else {
				return nil
			}
		}
		if readCount > 0 {
			writeCount, err := dst.Write(buf[:readCount])
			if err != nil {
				return err
			}
			if readCount != writeCount {
				return io.ErrShortWrite
			}
		}
	}
}

// DialEncryptedTCP 加密连接
func DialEncryptedTCP(addr *net.TCPAddr, cipher *Cipher) (*SecureTCPConn, error) {
	remoteConn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		return nil, err
	}
	// Conn被关闭时直接清除所有数据 不管没有发送的数据
	remoteConn.SetLinger(0)
	return &SecureTCPConn{
		ReadWriteCloser: remoteConn,
		Cipher:          cipher,
	}, nil
}

func ListenEncryTCP(laddr *net.TCPAddr, cipher *Cipher, handleConn func(localConn *SecureTCPConn), didListen func(listenAddr *net.TCPAddr)) error {
	listener, err := net.ListenTCP("tcp", laddr)
	if err != nil {
		return err
	}
	defer listener.Close()
	if didListen != nil {
		// didListen 可能有阻塞操作
		go didListen(listener.Addr().(*net.TCPAddr))
	}
	for {
		localConn, err := listener.AcceptTCP()
		if err != nil {
			log.Println(err)
			continue
		}
		// localConn被关闭时直接清除所有数据 不管没有发送的数据
		localConn.SetLinger(0)
		go handleConn(&SecureTCPConn{
			ReadWriteCloser: localConn,
			Cipher:          cipher,
		})
	}
}
