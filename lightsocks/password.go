package lightsocks

import (
	"encoding/base64"
	"errors"
	"math/rand"
	"time"
)

// PasswordLength 数据是以 byte 为最小单位流式传输的。一个 byte 的取值只可能是 0～255。
const PasswordLength = 256

type Password [PasswordLength]byte

func init() {
	// 种子必须设置，否则每次生成的密码都一样
	rand.NewSource(time.Now().Unix())
}

// RandPassword 产生 256个byte随机组合的 密码
func RandPassword() string {
	intArr := rand.Perm(PasswordLength)
	p := &Password{}
	for i, v := range intArr {
		p[i] = byte(v)
		if i == v {
			// 索引与值不能是同一个数，否则会导致加密后的数据没有变化
			return RandPassword()
		}
	}
	return p.String()
}

// ParsePassword 解析采用base64编码的字符串获取密码
func ParsePassword(passStr string) (*Password, error) {
	bs, err := base64.StdEncoding.DecodeString(passStr)
	if err != nil || len(bs) != PasswordLength {
		return nil, errors.New("invalid password")
	}
	p := Password{}
	copy(p[:], bs)
	bs = nil
	return &p, nil
}

// 采用base64编码把密码转换为字符串
func (p *Password) String() string {
	return base64.StdEncoding.EncodeToString(p[:])
}
