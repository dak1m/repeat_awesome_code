package lightsocks

type Cipher struct {
	// 编码用的密码
	encodePassword *Password
	// 解码用的密码
	decodePassword *Password
}

func (c *Cipher) encode(b []byte) {
	for i, v := range b {
		b[i] = c.encodePassword[v]
	}
}

func (c *Cipher) decode(b []byte) {
	for i, v := range b {
		b[i] = c.decodePassword[v]
	}
}

// NewCipher 新建一个编码解码器
func NewCipher(encodePassword *Password) *Cipher {
	decodePassword := &Password{}
	for i, v := range encodePassword {
		encodePassword[i] = v
		decodePassword[v] = byte(i)
	}
	return &Cipher{
		encodePassword: encodePassword,
		decodePassword: decodePassword,
	}
}
