package main

import (
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
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ================= 全局配置 =================

var (
	SecurityToken = getEnv("SECURITY_TOKEN", "123456")
	TgBotToken    = os.Getenv("TELEGRAM_BOT_TOKEN")
	TgChatID      = os.Getenv("TELEGRAM_CHAT_ID")
)

const PageSize = 20

// ================= 数据结构 =================

type LicenseData struct {
	MachineID string `json:"machine_id"`
	ExpiryUTC int64  `json:"expiry_utc"`
}

type License struct {
	Data      string `json:"data"`
	Signature string `json:"signature"`
}

type GenerateRequest struct {
	Token     string `json:"token"`
	MachineID string `json:"machine_id"`
	Expiry    string `json:"expiry"`
}

type DeleteRequest struct {
	Token     string `json:"token"`
	No        int    `json:"no,omitempty"`
	MachineID string `json:"machine_id,omitempty"`
}

type HistoryRecord struct {
	GenerateTime string `json:"generate_time"`
	MachineID    string `json:"machine_id"`
	ExpiryDate   string `json:"expiry_date"`
	LicenseCode  string `json:"license_code"`
}

type MachineRecord struct {
	MachineID string `json:"machine_id"`
	LastSeen  string `json:"last_seen"`
}

// ================= 全局存储 =================

var (
	historyList []HistoryRecord
	machineList []MachineRecord
	historyFile = "history.json"
	machineFile = "machines.json"
	mutex       sync.Mutex
)

// ================= 主程序入口 =================

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println(">>> 正在启动应用...")

	safeLoadData()

	if TgBotToken != "" && TgChatID != "" {
		log.Printf("✅ Telegram 通知已启用 (目标: %s)", TgChatID)
	} else {
		log.Println("⚠️ Telegram 配置未找到，将不会推送通知")
	}

	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/history", handleHistory)
	http.HandleFunc("/machines", handleMachines)
	http.HandleFunc("/setup", handleSetup)
	http.HandleFunc("/api/generate", handleAPI)
	http.HandleFunc("/api/delete", handleDeleteHistory)
	http.HandleFunc("/api/machines/delete", handleDeleteMachine)

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	})

	port := getEnv("PORT", "8080")
	log.Printf(">>> 🚀 服务准备监听: 0.0.0.0:%s", port)
	if err := http.ListenAndServe("0.0.0.0:"+port, nil); err != nil {
		log.Fatalf(">>> ❌ 致命错误: %v", err)
	}
}

// ================= Telegram 推送逻辑 =================

func sendTelegramNotification(machineID, expiry, tokenUsed string) {
	if TgBotToken == "" || TgChatID == "" {
		return
	}

	go func() {
		apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", TgBotToken)

		msg := fmt.Sprintf("🔔 <b>新激活码已生成!</b>\n\n"+
			"💻 <b>机器码:</b> <code>%s</code>\n"+
			"📅 <b>到期日:</b> %s\n"+
			"🔑 <b>使用Token:</b> %s\n"+
			"🕒 <b>时间:</b> %s",
			machineID, expiry, tokenUsed, time.Now().Format("2006-01-02 15:04:05"))

		// 支持逗号分隔多个ID
		ids := strings.Split(TgChatID, ",")

		for _, id := range ids {
			cleanID := strings.TrimSpace(id)
			if cleanID == "" { continue }

			_, err := http.PostForm(apiURL, url.Values{
				"chat_id":    {cleanID},
				"text":       {msg},
				"parse_mode": {"HTML"},
			})

			if err != nil {
				log.Printf("❌ Telegram 推送失败 (ID: %s): %v", cleanID, err)
			}
		}
	}()
}

// ================= 核心逻辑 =================

func generateLicenseCore(machineID, expiryStr string) (string, error) {
	if machineID == "" || expiryStr == "" { return "", fmt.Errorf("机器码或日期为空") }

	var rawKey []byte
	var source string

	if f, err := os.ReadFile("private.pem"); err == nil {
		rawKey = f; source = "file"
	} else {
		envKey := os.Getenv("PRIVATE_KEY")
		if envKey != "" { rawKey = []byte(envKey); source = "env" }
	}

	if len(rawKey) == 0 { return "", fmt.Errorf("❌ 未找到私钥") }

	var block *pem.Block
	block, _ = pem.Decode(rawKey)

	if block == nil {
		if source == "file" { return "", fmt.Errorf("本地文件格式错误") }
		cleanKey := string(rawKey)
		cleanKey = strings.Map(func(r rune) rune {
			if r == '-' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '+' || r == '/' || r == '=' { return r }
			return -1
		}, cleanKey)
		cleanKey = strings.ReplaceAll(cleanKey, "BEGINRSAPRIVATEKEY", "")
		cleanKey = strings.ReplaceAll(cleanKey, "ENDRSAPRIVATEKEY", "")
		cleanKey = strings.ReplaceAll(cleanKey, "BEGINPRIVATEKEY", "")
		cleanKey = strings.ReplaceAll(cleanKey, "ENDPRIVATEKEY", "")
		var builder strings.Builder
		builder.WriteString("-----BEGIN RSA PRIVATE KEY-----\n")
		for i := 0; i < len(cleanKey); i += 64 {
			end := i + 64; if end > len(cleanKey) { end = len(cleanKey) }
			builder.WriteString(cleanKey[i:end]); builder.WriteString("\n")
		}
		builder.WriteString("-----END RSA PRIVATE KEY-----")
		block, _ = pem.Decode([]byte(builder.String()))
	}

	if block == nil { return "", fmt.Errorf("私钥解析失败") }

	var privKey *rsa.PrivateKey
	var err error
	privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		if pkcs8, err2 := x509.ParsePKCS8PrivateKey(block.Bytes); err2 == nil {
			if k, ok := pkcs8.(*rsa.PrivateKey); ok { privKey = k } else { return "", fmt.Errorf("不是 RSA 私钥") }
		} else { return "", fmt.Errorf("私钥格式错误: %v", err) }
	}

	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil { loc = time.FixedZone("CST", 8*3600) }

	t, err := time.ParseInLocation("2006-01-02", expiryStr, loc)
	if err != nil { return "", fmt.Errorf("日期格式错误: %v", err) }

	now := time.Now().In(loc)
	maxAllowed := now.AddDate(0, 1, 0)
	if t.After(maxAllowed.Add(24 * time.Hour)) {
		return "", fmt.Errorf("❌ 有效期限制：不能超过1个月")
	}

	expiryUTC := t.Add(24*time.Hour - time.Second).UTC().Unix()
	licenseData := LicenseData{MachineID: machineID, ExpiryUTC: expiryUTC}
	dataJSON, _ := json.Marshal(licenseData)
	hasher := sha256.New(); hasher.Write(dataJSON); hashed := hasher.Sum(nil)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashed)
	if err != nil { return "", fmt.Errorf("签名失败: %v", err) }

	license := License{Data: base64.StdEncoding.EncodeToString(dataJSON), Signature: base64.StdEncoding.EncodeToString(signature)}
	licenseJSON, _ := json.Marshal(license)
	var compressedData bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressedData); gzipWriter.Write(licenseJSON); gzipWriter.Close()
	return base64.StdEncoding.EncodeToString(compressedData.Bytes()), nil
}

// ================= HTTP Handlers =================

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" { http.NotFound(w, r); return }
	html := `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>License Keygen</title>
	<style>
		body{font-family:-apple-system,sans-serif;max-width:600px;margin:20px auto;padding:20px;background:#f5f5f7}
		.card{background:white;padding:30px;border-radius:12px;box-shadow:0 4px 12px rgba(0,0,0,0.1)}
		input{width:100%;padding:10px;margin:5px 0 15px;box-sizing:border-box;border:1px solid #ccc;border-radius:6px}
		button{width:100%;padding:12px;background:#0071e3;color:white;border:none;border-radius:6px;cursor:pointer}
		button:hover{background:#005bb5}
		#res{margin-top:20px;word-break:break-all;padding:10px;background:#eee;border-radius:6px;display:none;font-family:monospace}
		.link-box{margin-bottom:15px;text-align:right;font-size:12px}
		a{color:#666;text-decoration:none;margin-left:10px} a:hover{color:#0071e3}
		.tags { display: flex; gap: 8px; margin-bottom: 5px; }
		.tag { padding: 4px 10px; border-radius: 15px; background: #eef6ff; color: #0071e3; font-size: 12px; cursor: pointer; border: 1px solid #dcebfa; user-select: none; transition: all 0.2s; }
		.tag:hover { background: #0071e3; color: white; }
	</style>
	</head><body><div class="card"><h2>🔐 激活码生成器</h2>
	<div class="link-box">
		<a href="#" onclick="goPage('/machines');return false">💻 机器管理</a>
		<a href="#" onclick="goPage('/history');return false">📜 生成记录</a>
	</div>
	<label>鉴权Token</label><input type="password" id="token" placeholder="默认为 123456">
	<label>机器码</label><input type="text" id="mid" placeholder="客户机器码">
	<label>到期日期</label>
	<div class="tags">
		<div class="tag" onclick="addDate(1)">+1天</div>
		<div class="tag" onclick="addDate(3)">+3天</div>
		<div class="tag" onclick="addDate(7)">+1周</div>
		<div class="tag" onclick="addMonth(1)">+1月</div>
	</div>
	<input type="date" id="date">
	<button onclick="gen()" id="btn">生成激活码</button><div id="res" onclick="copy(this)"></div></div>
	<script>
	document.getElementById('date').valueAsDate = new Date();
	function addDate(days) { const d = new Date(); d.setDate(d.getDate() + days); document.getElementById('date').valueAsDate = d; }
	function addMonth(months) { const d = new Date(); d.setMonth(d.getMonth() + months); document.getElementById('date').valueAsDate = d; }
	if(localStorage.getItem('lt')) document.getElementById('token').value = localStorage.getItem('lt');
	function goPage(path){var t=document.getElementById('token').value;if(!t)return alert('请输入Token');location.href=path+'?token='+t}
	async function gen(){
		var t=document.getElementById('token').value, m=document.getElementById('mid').value, d=document.getElementById('date').value;
		if(!t||!m||!d)return alert('请填写完整');
		localStorage.setItem('lt',t);
		var btn=document.getElementById('btn'), res=document.getElementById('res');
		btn.disabled=true; btn.innerText="生成中...";
		try{
			var r = await fetch('/api/generate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:t,machine_id:m,expiry:d})});
			var txt = await r.text();
			res.style.display='block';
			if(r.ok){res.style.color='green';res.innerText=txt;}else{res.style.color='red';res.innerText="错误: "+txt;}
		}catch(e){alert(e)}
		btn.disabled=false; btn.innerText="生成激活码";
	}
	function copy(e){navigator.clipboard.writeText(e.innerText).then(()=>alert('已复制'))}
	</script></body></html>`
	w.Write([]byte(html))
}

func handleSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		priv, _ := rsa.GenerateKey(rand.Reader, 2048)
		privBytes := x509.MarshalPKCS1PrivateKey(priv)
		pubBytes, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		privPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})
		pubPem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
		os.WriteFile("private.pem", privPem, 0600)
		os.WriteFile("public.pem", pubPem, 0644)
		json.NewEncoder(w).Encode(map[string]string{"private_key": string(privPem), "public_key": string(pubPem)})
		return
	}
	html := `<!DOCTYPE html><html><body style="font-family:sans-serif;padding:20px;max-width:800px;margin:0 auto"><h2>🛠️ 密钥工具</h2><button onclick="gen()" style="padding:10px 20px;background:red;color:white;border:none;border-radius:5px;cursor:pointer">生成新密钥</button><div id="box" style="display:none;margin-top:20px"><h3>私钥</h3><textarea id="priv" style="width:100%;height:150px" onclick="this.select()"></textarea><h3>公钥</h3><textarea id="pub" style="width:100%;height:150px" onclick="this.select()"></textarea></div><script>async function gen(){if(!confirm('确定生成吗？'))return;var res=await fetch('/setup',{method:'POST'});var d=await res.json();document.getElementById('box').style.display='block';document.getElementById('priv').value=d.private_key;document.getElementById('pub').value=d.public_key;}</script></body></html>`
	w.Write([]byte(html))
}

func handleMachines(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token != SecurityToken { http.Error(w, "Forbidden", 403); return }

	mutex.Lock()
	rowsHtml := ""
	count := 0
	for i := len(machineList) - 1; i >= 0; i-- {
		count++
		rec := machineList[i]
		rowsHtml += fmt.Sprintf(`<tr><td style="text-align:center;color:#888">%d</td><td style="font-family:monospace;color:#0071e3">%s</td><td>%s</td><td style="text-align:center"><button onclick="copyText('%s')" class="copy-btn">复制</button><button onclick="delMachine('%s')" class="del-btn">删除</button></td></tr>`, count, rec.MachineID, rec.LastSeen, rec.MachineID, rec.MachineID)
	}
	mutex.Unlock()

	html := fmt.Sprintf(`<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>机器码管理</title>
	<style>body{font-family:-apple-system,sans-serif;max-width:900px;margin:20px auto;padding:10px;background:#f5f5f7}.card{background:white;padding:20px;border-radius:12px;box-shadow:0 2px 10px rgba(0,0,0,0.1)}table{width:100%%;border-collapse:collapse;margin-top:10px;font-size:14px}th{text-align:left;background:#fafafa;padding:10px;border-bottom:2px solid #eee}td{padding:12px 10px;border-bottom:1px solid #f5f5f5;color:#333}tr:hover{background:#f9f9f9}.del-btn{background:#fff;border:1px solid #ff3b30;color:#ff3b30;padding:4px 8px;border-radius:4px;cursor:pointer;font-size:12px} .del-btn:hover{background:#ff3b30;color:white}.copy-btn{background:#fff;border:1px solid #0071e3;color:#0071e3;padding:4px 8px;border-radius:4px;cursor:pointer;font-size:12px;margin-right:6px} .copy-btn:hover{background:#0071e3;color:white}</style></head><body>
	<div class="card"><h2 style="display:flex;justify-content:space-between">💻 机器管理 (%d) <a href="/" style="font-size:14px;color:#0071e3;text-decoration:none">返回首页</a></h2><table><thead><tr><th style="width:50px;text-align:center">#</th><th>机器码</th><th>最后生成时间</th><th style="width:110px;text-align:center">操作</th></tr></thead><tbody>%s</tbody></table></div>
	<script>function copyText(t){navigator.clipboard.writeText(t).then(()=>alert("已复制"))}
	async function delMachine(mid){if(!confirm('确定要删除该机器码记录吗？'))return;try {let res = await fetch('/api/machines/delete', {method: 'POST', headers: {'Content-Type': 'application/json'},body: JSON.stringify({token: '%s', machine_id: mid})});if(res.ok) location.reload(); else alert(await res.text());} catch(e){alert(e)}}</script></body></html>`, len(machineList), rowsHtml, token)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

func handleHistory(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token != SecurityToken { http.Error(w, "Forbidden", 403); return }

	pageStr := r.URL.Query().Get("page")
	page := 1
	if p, err := strconv.Atoi(pageStr); err == nil && p > 0 { page = p }

	mutex.Lock()
	total := len(historyList)
	startIndex := (page - 1) * PageSize
	endIndex := startIndex + PageSize
	if endIndex > total { endIndex = total }

	var displayRows []HistoryRecord
	for i := startIndex; i < endIndex; i++ {
		realIndex := total - 1 - i
		if realIndex >= 0 { displayRows = append(displayRows, historyList[realIndex]) }
	}
	mutex.Unlock()

	rowsHtml := ""
	for i, rec := range displayRows {
		rowNum := startIndex + i + 1
		short := rec.LicenseCode
		if len(short) > 10 { short = short[:10] + "..." }
		rowsHtml += fmt.Sprintf(`<tr><td style="text-align:center;color:#888;font-weight:bold">%d</td><td>%s</td><td style="font-family:monospace;color:#0071e3">%s</td><td>%s</td><td onclick="navigator.clipboard.writeText('%s').then(()=>alert('已复制'))" style="cursor:pointer;color:blue" title="点击复制">%s</td></tr>`, rowNum, rec.GenerateTime, rec.MachineID, rec.ExpiryDate, rec.LicenseCode, short)
	}

	totalPages := int(math.Ceil(float64(total) / float64(PageSize)))
	navHtml := `<div style="margin-top:20px;text-align:center;">`
	if page > 1 { navHtml += fmt.Sprintf(`<a href="/history?token=%s&page=%d" style="text-decoration:none;padding:5px 15px;background:#0071e3;color:white;border-radius:4px;font-size:14px">上一页</a> `, token, page-1) }
	navHtml += fmt.Sprintf(`<span style="margin:0 10px">第 %d / %d 页 (共 %d 条)</span>`, page, totalPages, total)
	if page < totalPages { navHtml += fmt.Sprintf(`<a href="/history?token=%s&page=%d" style="text-decoration:none;padding:5px 15px;background:#0071e3;color:white;border-radius:4px;font-size:14px">下一页</a>`, token, page+1) }
	navHtml += `</div>`

	html := fmt.Sprintf(`<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>历史记录</title>
	<style>body{font-family:-apple-system,sans-serif;max-width:900px;margin:20px auto;padding:10px;background:#f5f5f7}.card{background:white;padding:20px;border-radius:12px;box-shadow:0 2px 10px rgba(0,0,0,0.1)}table{width:100%%;border-collapse:collapse;margin-top:10px;font-size:14px}th{text-align:left;background:#fafafa;padding:10px;border-bottom:2px solid #eee}td{padding:12px 10px;border-bottom:1px solid #f5f5f5;color:#333}tr:hover{background:#f9f9f9}</style></head><body>
	<div class="card"><h2 style="display:flex;justify-content:space-between">📜 历史记录 <a href="/" style="font-size:14px;color:#0071e3;text-decoration:none">返回首页</a></h2><table><thead><tr><th style="width:50px;text-align:center">序号</th><th>时间</th><th>机器码</th><th>到期</th><th>激活码</th></tr></thead><tbody>%s</tbody></table>%s</div></body></html>`, rowsHtml, navHtml)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// 🔥 这里是处理生成的入口，也是发送通知的地方 (唯一的一个)
func handleAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" { http.Error(w, "405", 405); return }
	var req GenerateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil { http.Error(w, err.Error(), 400); return }
	if req.Token != SecurityToken { http.Error(w, "Token 错误", 403); return }

	code, err := generateLicenseCore(req.MachineID, req.Expiry)
	if err != nil { log.Printf("生成失败: %v", err); http.Error(w, err.Error(), 500); return }

	saveData(req.MachineID, req.Expiry, code)
	// 推送 Telegram 通知
	sendTelegramNotification(req.MachineID, req.Expiry, req.Token)

	w.Write([]byte(code))
}

func handleDeleteHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" { http.Error(w, "Method Not Allowed", 405); return }
	var req DeleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil { http.Error(w, "JSON Error", 400); return }
	if req.Token != SecurityToken { http.Error(w, "Token Error", 403); return }
	mutex.Lock(); defer mutex.Unlock()
	total := len(historyList)
	if req.No <= 0 || req.No > total { http.Error(w, "序号不存在", 404); return }
	historyList = append(historyList[:total-req.No], historyList[total-req.No+1:]...)
	if f, err := os.Create(historyFile); err == nil { json.NewEncoder(f).Encode(historyList); f.Close() }
	w.Write([]byte(fmt.Sprintf("✅ 成功删除序号: %d", req.No)))
}

func handleDeleteMachine(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" { http.Error(w, "Method Not Allowed", 405); return }
	var req DeleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil { http.Error(w, "JSON Error", 400); return }
	if req.Token != SecurityToken { http.Error(w, "Token Error", 403); return }
	if req.MachineID == "" { http.Error(w, "MachineID Empty", 400); return }

	mutex.Lock(); defer mutex.Unlock()
	newMachines := make([]MachineRecord, 0, len(machineList))
	found := false
	for _, m := range machineList {
		if m.MachineID == req.MachineID { found = true; continue }
		newMachines = append(newMachines, m)
	}
	if !found { http.Error(w, "机器码未找到", 404); return }
	machineList = newMachines
	if f, err := os.Create(machineFile); err == nil { json.NewEncoder(f).Encode(machineList); f.Close() }
	w.Write([]byte("✅ 机器码已删除"))
}

func saveData(mid, expiry, code string) {
	mutex.Lock(); defer mutex.Unlock()
	nowStr := time.Now().Format("2006-01-02 15:04:05")
	rec := HistoryRecord{GenerateTime: nowStr, MachineID: mid, ExpiryDate: expiry, LicenseCode: code}
	historyList = append(historyList, rec)
	if f, err := os.Create(historyFile); err == nil { json.NewEncoder(f).Encode(historyList); f.Close() }

	found := false
	for i, m := range machineList {
		if m.MachineID == mid { machineList[i].LastSeen = nowStr; found = true; break }
	}
	if !found { machineList = append(machineList, MachineRecord{MachineID: mid, LastSeen: nowStr}) }
	if f, err := os.Create(machineFile); err == nil { json.NewEncoder(f).Encode(machineList); f.Close() }
}

func safeLoadData() {
	mutex.Lock(); defer mutex.Unlock()
	log.Println(">>> 正在加载数据文件...")
	if f, err := os.Open(historyFile); err == nil { json.NewDecoder(f).Decode(&historyList); f.Close() } else { log.Printf(">>> 提示: 无法读取历史文件: %v", err) }
	if f, err := os.Open(machineFile); err == nil { json.NewDecoder(f).Decode(&machineList); f.Close() } else { log.Printf(">>> 提示: 无法读取机器码文件: %v", err) }
}

func getEnv(k, def string) string { if v := os.Getenv(k); v != "" { return v }; return def }
