package google_authenticator_provider

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

var regexpCode = regexp.MustCompile(`^\d+$`)
var base32AlphabetChars = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
var base32AlphabetCharsLen = len(base32AlphabetChars)

func decodedComputeCode(key []byte, base int64) int {
	hash := hmac.New(sha1.New, key)
	err := binary.Write(hash, binary.BigEndian, base)
	if err != nil {
		return -1
	}
	h := hash.Sum(nil)
	
	offset := h[19] & 0x0f
	
	truncated := binary.BigEndian.Uint32(h[offset : offset+4])
	
	truncated &= 0x7fffffff
	code := truncated % 1000000
	
	return int(code)
}

func GenerateSecret() string {
	var b = make([]byte, 8)
	for i := range b {
		b[i] = base32AlphabetChars[rand.Intn(base32AlphabetCharsLen)]
	}
	return string(b)
}
func ComputePassword(secret string) string {
	var key, err = base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return ""
	}
	var base = time.Now().Unix() / 30
	var code = decodedComputeCode(key, base)
	if code < 0 {
		return ""
	}
	var res = strconv.FormatInt(int64(code), 10)
	return strings.Repeat("0", 6 - len(res)) + res
}
func Authenticate(secret string, password string) bool {
	var ok bool
	if password, ok = PasswordFormat(password); !ok {
		return false
	}
	var err error
	var value int
	if value, err = strconv.Atoi(password); err != nil && value < 0 {
		return false
	}
	var key []byte
	if key, err = base32.StdEncoding.DecodeString(secret); err != nil {
		return false
	}
	var base = time.Now().Unix() / 30
	return decodedComputeCode(key, base) == value || decodedComputeCode(key, base - 1) == value || decodedComputeCode(key, base + 1) == value
}
func PasswordFormat(password string) (string, bool) {
	password = strings.TrimSpace(password)
	if len(password) > 0 && regexpCode.MatchString(password) {
		password = strings.TrimLeft(password, "0")
		var l = len(password)
		if l == 6 {
			return password, true
		} else if l < 6 {
			return strings.Repeat("0", 6 - l) + password, true
		}
	}
	return "000000", false
}
