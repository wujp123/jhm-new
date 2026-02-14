// keygen/main.go
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// 【核心】在 keygen 工具内部，独立定义所需的数据结构。
// 它不再需要、也不应该依赖 backend 项目。
type LicenseData struct {
	MachineID string `json:"machine_id"`
	ExpiryUTC int64  `json:"expiry_utc"`
}

type License struct {
	Data      string `json:"data"`
	Signature string `json:"signature"`
}

// 【核心】路径是相对于项目根目录
const (
	privateKeyPath = "keygen-keys/private.pem" // 将私钥保存在一个独立的、安全的地方
	publicKeyPath  = "backend/public.pem"      // 公钥将生成到 backend 目录中
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}
	switch os.Args[1] {
	case "generate":
		handleGenerateKeys()
	case "issue":
		handleIssueLicense()
	default:
		fmt.Printf("错误: 未知的命令 '%s'\n\n", os.Args[1])
		printUsage()
	}
}

func printUsage() {
	fmt.Println("用法: go run keygen/main.go [命令]")
	fmt.Println("  generate   生成 RSA 密钥对")
	fmt.Println("  issue      签发一个新的激活码")
}

func handleGenerateKeys() {
	fmt.Println("正在生成新的 RSA 密钥对...")

	// 创建私钥目录
	if err := os.MkdirAll(filepath.Dir(privateKeyPath), 0755); err != nil {
		fmt.Printf("错误: 无法创建目录 '%s': %v\n", filepath.Dir(privateKeyPath), err)
		return
	}

	if _, err := os.Stat(privateKeyPath); err == nil {
		if !askForConfirmation("警告: 私钥文件已存在，确定要覆盖吗? (y/n): ") {
			fmt.Println("操作已取消。")
			return
		}
	}

	// 生成密钥对
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("错误: 生成密钥失败: %v\n", err)
		return
	}

	// 保存私钥
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateKeyBytes}
	privateFile, err := os.OpenFile(privateKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Printf("错误: 无法创建私钥文件: %v\n", err)
		return
	}
	defer privateFile.Close()

	if err := pem.Encode(privateFile, privateKeyBlock); err != nil {
		fmt.Printf("错误: 写入私钥失败: %v\n", err)
		return
	}

	// 保存公钥
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		fmt.Printf("错误: 序列化公钥失败: %v\n", err)
		return
	}
	publicKeyBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyBytes}

	if err := os.MkdirAll(filepath.Dir(publicKeyPath), 0755); err != nil {
		fmt.Printf("错误: 无法创建公钥目录: %v\n", err)
		return
	}

	publicFile, err := os.Create(publicKeyPath)
	if err != nil {
		fmt.Printf("错误: 无法创建公钥文件: %v\n", err)
		return
	}
	defer publicFile.Close()

	if err := pem.Encode(publicFile, publicKeyBlock); err != nil {
		fmt.Printf("错误: 写入公钥失败: %v\n", err)
		return
	}

	fmt.Printf("\n✅ 成功! 新的密钥对已生成:\n   私钥: '%s'\n   公钥: '%s'\n", privateKeyPath, publicKeyPath)
}

func handleIssueLicense() {
	fmt.Println("正在签发新的许可证...")

	// 检查私钥文件是否存在
	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		fmt.Printf("错误: '%s' 文件未找到。\n请先运行 'go run keygen/main.go generate'\n", privateKeyPath)
		return
	}

	reader := bufio.NewReader(os.Stdin)

	// 读取机器码
	fmt.Print("请输入客户的机器码: ")
	machineID, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("错误: 读取机器码失败: %v\n", err)
		return
	}
	machineID = strings.TrimSpace(machineID)

	if machineID == "" {
		fmt.Println("错误: 机器码不能为空。")
		return
	}

	// 验证机器码格式（基本验证）
	if len(machineID) < 10 {
		fmt.Println("错误: 机器码格式无效，长度太短。")
		return
	}

	// 读取到期日期
	fmt.Print("请输入许可证到期日期 (格式 YYYY-MM-DD): ")
	expiryDateStr, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("错误: 读取日期失败: %v\n", err)
		return
	}
	expiryDateStr = strings.TrimSpace(expiryDateStr)

	// 解析日期（北京时间）
	beijingLocation, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		fmt.Printf("错误: 加载时区失败: %v\n", err)
		return
	}

	t, err := time.ParseInLocation("2006-01-02", expiryDateStr, beijingLocation)
	if err != nil {
		fmt.Printf("错误: 无效的日期格式，请使用 YYYY-MM-DD 格式 (例: 2025-12-31): %v\n", err)
		return
	}

	// 计算到期时间（当天的23:59:59）
	endOfDay := t.Add(24*time.Hour - 1*time.Second)

	// 检查到期时间是否在未来（允许今天的日期，因为到期时间是23:59:59）
	if endOfDay.Before(time.Now()) {
		fmt.Println("错误: 到期日期不能是过去的日期。")
		return
	}
	expiryUTC := endOfDay.UTC().Unix()

	// 构建许可证数据
	licenseData := LicenseData{MachineID: machineID, ExpiryUTC: expiryUTC}
	dataJSON, err := json.Marshal(licenseData)
	if err != nil {
		fmt.Printf("错误: 序列化许可证数据失败: %v\n", err)
		return
	}

	// 读取私钥
	privateKeyBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		fmt.Printf("错误: 读取私钥文件失败: %v\n", err)
		return
	}

	block, _ := pem.Decode(privateKeyBytes)
	if block == nil {
		fmt.Println("错误: 私钥文件格式无效。")
		return
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Printf("错误: 解析私钥失败: %v\n", err)
		return
	}

	// 签名
	hasher := sha256.New()
	hasher.Write(dataJSON)
	hashed := hasher.Sum(nil)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
	if err != nil {
		fmt.Printf("错误: 签名失败: %v\n", err)
		return
	}

	// 构建许可证
	license := License{
		Data:      base64.StdEncoding.EncodeToString(dataJSON),
		Signature: base64.StdEncoding.EncodeToString(signature),
	}
	licenseJSON, err := json.Marshal(license)
	if err != nil {
		fmt.Printf("错误: 序列化许可证失败: %v\n", err)
		return
	}

	// 压缩
	var compressedData bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressedData)
	if _, err := gzipWriter.Write(licenseJSON); err != nil {
		fmt.Printf("错误: 压缩失败: %v\n", err)
		return
	}
	if err := gzipWriter.Close(); err != nil {
		fmt.Printf("错误: 关闭压缩流失败: %v\n", err)
		return
	}

	finalCode := base64.StdEncoding.EncodeToString(compressedData.Bytes())

	// 显示结果
	fmt.Println("\n************** 激活码 **************")
	fmt.Println(finalCode)
	fmt.Println("******************************************")
	fmt.Printf("\n许可证信息:\n")
	fmt.Printf("  机器码: %s\n", machineID)
	fmt.Printf("  到期日期: %s 23:59:59 (北京时间)\n", expiryDateStr)
	fmt.Printf("  此激活码与机器码绑定，仅能在指定机器使用。(换电脑请重新购买激活码！)\n")
	fmt.Println("\n✅ 成功! 激活码已生成。")
}

func askForConfirmation(prompt string) bool {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print(prompt)
		input, _ := reader.ReadString('\n')
		input = strings.ToLower(strings.TrimSpace(input))
		if input == "y" || input == "yes" {
			return true
		}
		if input == "n" || input == "no" {
			return false
		}
	}
}
