package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	"time"
)

type fajson struct {
	Accounts []struct {
		Name   string
		Secret string
	}
}

func main() {

	pfile := flag.String("json", "./my2fa.json", "The 2FA json file")
	pmatch := flag.String("match", "", "only match entries that contain the provided substring")
	pwait := flag.Bool("wait", false, "Wait until OTP expires and show count-down")
	flag.Parse()

	file, err := ioutil.ReadFile(*pfile)
	if err != nil {
		log.Fatal(err)
	}

	var fa fajson
	json.Unmarshal(file, &fa)

	expiresAt := (time.Now().Unix() + 30) / 30 * 30
	for _, account := range fa.Accounts {
		if len(*pmatch) == 0 || strings.Contains(strings.ToLower(account.Name), strings.ToLower(*pmatch)) {
			fmt.Printf("% 12s -- %06d\n", account.Name, totp(account.Secret))
		}
	}

	fmt.Println()

	remainingSeconds := expiresAt - time.Now().Unix()

	if *pwait {
		for remaining := remainingSeconds; remaining > -1; remaining-- {
			fmt.Printf("\r   remaining -- %-02d", remaining)
			time.Sleep(1000 * time.Millisecond)
		}

		fmt.Println()
	} else {
		fmt.Println("Expires at", time.Unix(expiresAt, 0).Format("15:04:05"), " -- in", remainingSeconds, "seconds.")
	}
}

func totp(secret string) uint32 {

	if len(secret)%8 > 0 {
		secret += strings.Repeat("=", 8-len(secret)%8)
	}

	key, err2 := base32.StdEncoding.DecodeString(strings.ToUpper(secret))
	if err2 != nil {
		log.Fatal(err2)
	}

	intervals := uint64(time.Now().Unix() / 30)

	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, intervals)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg)
	h := mac.Sum(nil)
	o := h[19] & 15
	d := (binary.BigEndian.Uint32(h[o:o+4]) & 0x7fffffff) % 1000000
	return d
}
