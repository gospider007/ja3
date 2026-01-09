package ja3

import (
	"net/http"
	"net/url"
	"path"
	"strings"
)

// sameOrigin 判断两个 URL 是否同源（协议 + 域名 + 端口）
func sameOrigin(u1, u2 *url.URL) bool {
	port1 := u1.Port()
	if port1 == "" {
		port1 = defaultPort(u1.Scheme)
	}
	port2 := u2.Port()
	if port2 == "" {
		port2 = defaultPort(u2.Scheme)
	}
	return u1.Scheme == u2.Scheme && u1.Hostname() == u2.Hostname() && port1 == port2
}

// sameSite 判断两个 URL 是否同站（主域名相同）
func sameSite(u1, u2 *url.URL) bool {
	return getSite(u1.Hostname()) == getSite(u2.Hostname())
}

// getSite 获取主域名，例如 "sub.example.com" -> "example.com"
func getSite(host string) string {
	parts := strings.Split(host, ".")
	n := len(parts)
	if n >= 2 {
		return parts[n-2] + "." + parts[n-1]
	}
	return host
}

// defaultPort 根据协议返回默认端口
func defaultPort(scheme string) string {
	if scheme == "https" {
		return "443"
	}
	return "80"
}

// inferFetchDest 根据请求的 Accept 和 URL 后缀推断 sec-fetch-dest
func inferFetchDest(req *http.Request) string {
	accept := req.Header.Get("Accept")
	urlPath := req.URL.Path
	ext := strings.ToLower(path.Ext(urlPath)) // 获取后缀，例如 .js, .css, .png

	// 根据 URL 后缀判断
	switch ext {
	case ".html", ".htm":
		return "document"
	case ".css":
		return "style"
	case ".js":
		return "script"
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico":
		return "image"
	case ".woff", ".woff2", ".ttf", ".otf", ".eot":
		return "font"
	case ".mp4", ".webm", ".ogg":
		return "video"
	case ".mp3", ".wav", ".aac":
		return "audio"
	}
	// 默认 fallback
	return "empty"
}

// inferAndSetFetchMode 根据请求头和请求方法推断 sec-fetch-mode，并自动写入请求头
func inferFetchMode(req *http.Request) string {
	// 1️⃣ websocket 判断
	if strings.Contains(strings.ToLower(req.Header.Get("Upgrade")), "websocket") {
		return "websocket"
	}
	accept := req.Header.Get("Accept")
	contentType := req.Header.Get("Content-Type")
	xRequestedWith := req.Header.Get("X-Requested-With")
	method := strings.ToUpper(req.Method)

	// 2️⃣ navigate（页面导航）
	if strings.Contains(accept, "text/html") && method == "GET" {
		return "navigate"
	}

	// 3️⃣ cors（XHR / Fetch / API 请求）
	if strings.Contains(accept, "application/json") ||
		strings.Contains(contentType, "application/json") ||
		xRequestedWith != "" ||
		method == "POST" || method == "PUT" || method == "DELETE" {
		return "cors"
	}

	// 4️⃣ no-cors（静态资源，如 script/css/img/font/media）
	if strings.Contains(accept, "text/css") ||
		strings.Contains(accept, "image/") ||
		strings.Contains(accept, "javascript") ||
		strings.Contains(accept, "application/font") ||
		strings.Contains(accept, "video/") ||
		strings.Contains(accept, "audio/") {
		return "no-cors"
	}
	// 5️⃣ 兜底，默认 cors
	return "cors"
}

// inferSecFetchSite 根据请求的 URL 和 Referer 自动判断 Sec-Fetch-Site
func inferSecFetchSite(req *http.Request) string {
	referer := req.Header.Get("Referer")
	if referer == "" {
		return "none" // 没有 Referer 时返回 none
	}
	reqURL := req.URL
	refURL, err := url.Parse(referer)
	if err != nil {
		return "none" // 解析 Referer 失败，返回 none
	}
	if sameOrigin(reqURL, refURL) {
		return "same-origin"
	}
	if sameSite(reqURL, refURL) {
		return "same-site"
	}
	return "cross-site"
}
