package aes

import (
	"encoding/base64"
	"testing"
)

// go test -run TestAesCBCEncrypt -v
func TestAesCBCEncrypt(t *testing.T) {
	key := []byte("D7810B832347228614268C0DADDFE6C5")
	plaintext := []byte("size=20&page=1&cityid=1")
	iv := []byte("14268C0DADDFE6C5")

	t.Logf("plaintext: %s, key: %s, iv: %s \n", string(plaintext), string(key), string(iv))

	ciphertext, err := AesCBCEncrypt(plaintext, key, iv)
	if err != nil {
		t.Error(err)
		return
	}

	base64Data := base64.StdEncoding.EncodeToString(ciphertext)
	t.Logf("base64 encode encrypt: %s", base64Data)
}

// go test -run TestAesCBCDecrypt -v
func TestAesCBCDecrypt(t *testing.T) {
	key := []byte("260D8A16C18DC4F417B50526059DF968")
	txt := `qb8WcRbS3YknCB1tepOMfUJrpEoNweYKGPhNgX+h8uabhAg8xuu4yHgNwyBulaZAdATnWeD+ZHBpI8WM4Yx4HtHLcUMZ98m2cU7bvQQ6Gw8WGkkb5GXl0ZawgiYFNfJWgU1idfmQ3VJvKbdjeNQMv4Qt6Zjb7P1HvB26wyLgACh9E4RoXqdMKPZTSnMSLG+MYwO1AhfgQ7Y6yGt8R+zKFVaYeO13A1t5pYrsO7Qjuxrfb30eqiPe3rD4jsZvWerI7Jvu+Rb5lF++cX8uXuc6f5fgDLeONNDzmT6j7JZ6AwETxh8ypnpQRYuWE3dpB9ikPPQA0R/9vjsaOOS93nEX1ezfKxlogHGCWFmg0HWEZwVvI929IlXJzxZZoE225/4tJJIjrwRakMF1GiSJudaf8M4yAtITMVNBeTtFRZaoM7tMMdCzEq2N9S+1bG7bZxMxLeTN26By/LfeoaxEj+Dtey3ZuBRQmEdx008QxjJRIUFUZ66W/35Ax1K1QFzmYo+0CG+ValgbU7l46NIEWrZoX7LgC4TiO19yfeM4l+Pk+yXTe21KqrUFv/Do5vxEx/OgQqQC1ZswGNHuN/NZqq3fHHgehUNzb6z50vF6oNzbiow=`
	ciphertext := []byte(txt)
	iv := []byte("17B50526059DF968")

	t.Logf("ciphertext: %s, key: %s, iv: %s \n", string(ciphertext), string(key), string(iv))

	base64DecodeData, _ := base64.StdEncoding.DecodeString(string(ciphertext))
	plaintext, err := AesCBCDecrypt(base64DecodeData, key, iv)
	if err != nil {
		t.Error(err)
		return
	}

	t.Logf("plaintext: %s \n", string(plaintext))
}
