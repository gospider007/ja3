package ja3

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gospider007/gtls"
	"github.com/gospider007/re"
	"github.com/gospider007/tools"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/cryptobyte"
)

type FpContextData struct {
	clientHelloData []byte
	h2Ja3Spec       H2Ja3Spec
	connectionState tls.ConnectionState
	orderHeaders    []string
}

func GetFpContextData(ctx context.Context) (*FpContextData, bool) {
	data, ok := ctx.Value(keyPrincipalID).(*FpContextData)
	return data, ok
}

type ClientHello struct {
	ContentType        uint8             //contentType
	MessageVersion     uint16            //MessageVersion
	HandshakeVersion   uint16            //HandshakeVersion
	HandShakeType      uint8             //HandShakeType
	RandomTime         uint32            //RandomTime
	RandomBytes        []byte            //RandomBytes
	SessionId          cryptobyte.String //sessionId
	CipherSuites       []uint16          //cipherSuites
	CompressionMethods cryptobyte.String //CompressionMethods
	Extensions         []Extension
}
type Extension struct {
	Type uint16
	Data cryptobyte.String
}

func (obj Extension) utlsExt() utls.TLSExtension {
	ext, _ := createExtension(obj.Type, extensionOption{data: obj.Data})
	return ext
}

func (obj ClientHello) UtlsExtensions() map[uint16]utls.TLSExtension {
	exts := make(map[uint16]utls.TLSExtension)
	for i := 0; i < len(obj.Extensions); i++ {
		ext, _ := createExtension(obj.Extensions[i].Type, extensionOption{data: obj.Extensions[i].Data})
		exts[obj.Extensions[i].Type] = ext
	}
	return exts
}

type TlsData struct {
	connectionState    tls.ConnectionState
	Ciphers            []uint16
	Curves             []uint16
	Extensions         []uint16
	Points             []uint16
	Protocols          []string
	Versions           []uint16
	Algorithms         []uint16
	RandomTime         string
	RandomBytes        string
	SessionId          string
	CompressionMethods string
}

func (tlsData TlsData) Fp() (string, string) {
	tlsVersion := fmt.Sprintf("%d", tlsData.connectionState.Version)
	ciphers := clearGreas(tlsData.Ciphers)
	extensions := clearGreas(tlsData.Extensions)
	curves := clearGreas(tlsData.Curves)
	points := clearGreas(tlsData.Points)
	ja3Str := strings.Join([]string{
		tlsVersion,
		tools.AnyJoin(ciphers, "-"),
		tools.AnyJoin(extensions, "-"),
		tools.AnyJoin(curves, "-"),
		tools.AnyJoin(points, "-"),
	}, ",")
	ja3nStr := strings.Join([]string{
		tlsVersion,
		tools.AnyJoin(ciphers, "-"),
		"",
		tools.AnyJoin(curves, "-"),
		tools.AnyJoin(points, "-"),
	}, ",")
	return ja3Str, ja3nStr
}

func clearGreas(values []uint16) []uint16 {
	results := []uint16{}
	for _, value := range values {
		if !IsGREASEUint16(value) {
			results = append(results, value)
		}
	}
	return results
}

func (obj FpContextData) TlsData() (tlsData TlsData, err error) {
	clientHello, err := obj.ClientHello()
	if err != nil {
		return tlsData, err
	}
	tlsData.connectionState = obj.connectionState
	tlsData.Ciphers = clientHello.CipherSuites
	tlsData.Curves = clientHello.Curves()
	tlsData.Extensions = []uint16{}
	for _, extension := range clientHello.Extensions {
		tlsData.Extensions = append(tlsData.Extensions, extension.Type)
	}
	tlsData.Points = []uint16{}
	for _, point := range clientHello.Points() {
		tlsData.Points = append(tlsData.Points, uint16(point))
	}
	tlsData.Protocols = clientHello.Protocols()
	tlsData.Versions = clientHello.Versions()
	tlsData.Algorithms = clientHello.Algorithms()
	tlsData.RandomTime = time.Unix(int64(clientHello.RandomTime), 0).String()
	tlsData.RandomBytes = tools.Hex(clientHello.RandomBytes)
	tlsData.SessionId = tools.Hex(clientHello.SessionId)
	tlsData.CompressionMethods = tools.Hex(clientHello.CompressionMethods)
	return
}

// type:  11 : utls.SupportedPointsExtension
func (obj ClientHello) Points() []uint8 {
	for _, ext := range obj.Extensions {
		if ext.Type == 11 {
			if utlsExt, ok := createExtension(ext.Type, extensionOption{data: ext.Data}); ok {
				return utlsExt.(*utls.SupportedPointsExtension).SupportedPoints
			}
		}
	}
	return nil
}

// type:  16 : utls.ALPNExtension
func (obj ClientHello) Protocols() []string {
	for _, ext := range obj.Extensions {
		if ext.Type == 16 {
			if utlsExt, ok := createExtension(ext.Type, extensionOption{data: ext.Data}); ok {
				return utlsExt.(*utls.ALPNExtension).AlpnProtocols
			}
		}
	}
	return nil
}

// type:  43 : utls.SupportedVersionsExtension
func (obj ClientHello) Versions() []uint16 {
	for _, ext := range obj.Extensions {
		if ext.Type == 43 {
			if utlsExt, ok := createExtension(ext.Type, extensionOption{data: ext.Data}); ok {
				return utlsExt.(*utls.SupportedVersionsExtension).Versions
			}
		}
	}
	return nil
}

// type:  13 : utls.SignatureAlgorithmsExtension
func (obj ClientHello) Algorithms() []uint16 {
	for _, ext := range obj.Extensions {
		if ext.Type == 13 {
			if utlsExt, ok := createExtension(ext.Type, extensionOption{data: ext.Data}); ok {
				algorithms := []uint16{}
				for _, algorithm := range utlsExt.(*utls.SignatureAlgorithmsExtension).SupportedSignatureAlgorithms {
					algorithms = append(algorithms, uint16(algorithm))
				}
				return algorithms
			}
		}
	}
	return nil
}

// type:  10 : utls.SupportedCurvesExtension
func (obj ClientHello) Curves() []uint16 {
	for _, ext := range obj.Extensions {
		if ext.Type == 10 {
			if utlsExt, ok := createExtension(ext.Type, extensionOption{data: ext.Data}); ok {
				algorithms := []uint16{}
				for _, algorithm := range utlsExt.(*utls.SupportedCurvesExtension).Curves {
					algorithms = append(algorithms, uint16(algorithm))
				}
				return algorithms
			}
		}
	}
	return nil
}

func decodeClientHello(clienthello []byte) (clientHelloInfo ClientHello, err error) {
	plaintext := cryptobyte.String(clienthello)
	if !plaintext.ReadUint8(&clientHelloInfo.ContentType) {
		err = errors.New("contentType error")
		return
	}
	if !plaintext.ReadUint16(&clientHelloInfo.MessageVersion) {
		err = errors.New("tlsMinVersion error")
		return
	}
	//handShakeProtocol
	var handShakeProtocol cryptobyte.String
	if !plaintext.ReadUint16LengthPrefixed(&handShakeProtocol) {
		err = errors.New("handShakeProtocol error")
		return
	}
	if !handShakeProtocol.ReadUint8(&clientHelloInfo.HandShakeType) {
		err = errors.New("handShakeType error")
		return
	}
	//read  helloData
	var handShakeData cryptobyte.String
	if !handShakeProtocol.ReadUint24LengthPrefixed(&handShakeData) {
		err = errors.New("handShakeData error")
		return
	}
	if !handShakeData.ReadUint16(&clientHelloInfo.HandshakeVersion) {
		err = errors.New("tlsMaxVersion error")
		return
	}
	if !handShakeData.ReadUint32(&clientHelloInfo.RandomTime) {
		err = errors.New("randomTime error")
		return
	}
	if !handShakeData.ReadBytes(&clientHelloInfo.RandomBytes, 28) {
		err = errors.New("randomTime error")
		return
	}
	if !handShakeData.ReadUint8LengthPrefixed(&clientHelloInfo.SessionId) {
		err = errors.New("sessionId error")
		return
	}
	var cipherSuitesData cryptobyte.String
	if !handShakeData.ReadUint16LengthPrefixed(&cipherSuitesData) {
		err = errors.New("cipherSuites error")
		return
	}
	clientHelloInfo.CipherSuites = []uint16{}
	for !cipherSuitesData.Empty() {
		var cipherSuite uint16
		if cipherSuitesData.ReadUint16(&cipherSuite) {
			clientHelloInfo.CipherSuites = append(clientHelloInfo.CipherSuites, cipherSuite)
		}
	}
	if !handShakeData.ReadUint8LengthPrefixed(&clientHelloInfo.CompressionMethods) {
		err = errors.New("compressionMethods error")
		return
	}
	var extensionsData cryptobyte.String
	if !handShakeData.ReadUint16LengthPrefixed(&extensionsData) {
		err = errors.New("handShakeData error")
		return
	}
	clientHelloInfo.Extensions = []Extension{}
	for !extensionsData.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if extensionsData.ReadUint16(&extension) && extensionsData.ReadUint16LengthPrefixed(&extData) {
			clientHelloInfo.Extensions = append(clientHelloInfo.Extensions, Extension{
				Type: extension,
				Data: extData,
			})
		}
	}
	return
}
func (clientHelloParseData TlsData) Ja4() string {
	ja4aStr := "t"
	switch clientHelloParseData.connectionState.Version {
	case tls.VersionTLS10:
		ja4aStr += "10"
	case tls.VersionTLS11:
		ja4aStr += "11"
	case tls.VersionTLS12:
		ja4aStr += "12"
	case tls.VersionTLS13:
		ja4aStr += "13"
	default:
		ja4aStr += "00"
	}
	if clientHelloParseData.connectionState.ServerName == "" {
		ja4aStr += "i"
	} else if _, addTyp := gtls.ParseHost(clientHelloParseData.connectionState.ServerName); addTyp != 0 {
		ja4aStr += "i"
	} else {
		ja4aStr += "d"
	}
	ciphers := clearGreas(clientHelloParseData.Ciphers)
	ciphersNum := fmt.Sprint(len(ciphers))
	if len(ciphersNum) < 2 {
		ciphersNum = "0" + ciphersNum
	}
	ja4aStr += ciphersNum
	extsNum := fmt.Sprint(len(clearGreas(clientHelloParseData.Extensions)))
	if len(extsNum) < 2 {
		extsNum = "0" + extsNum
	}
	ja4aStr += extsNum
	switch len(clientHelloParseData.connectionState.NegotiatedProtocol) {
	case 0:
		ja4aStr += "00"
	case 1:
		ja4aStr += clientHelloParseData.connectionState.NegotiatedProtocol + "0"
	case 2:
		ja4aStr += clientHelloParseData.connectionState.NegotiatedProtocol
	default:
		if clientHelloParseData.connectionState.NegotiatedProtocol == "http/1.1" {
			ja4aStr += "h1"
		} else {
			ja4aStr += clientHelloParseData.connectionState.NegotiatedProtocol[:2]
		}
	}
	sort.Slice(ciphers, func(i, j int) bool { return ciphers[i] < ciphers[j] })
	ja4bStr := tools.Hex(sha256.Sum256([]byte(tools.AnyJoin(ciphers, ","))))[:12]
	exts := []uint16{}
	for _, ext := range clearGreas(clientHelloParseData.Extensions) {
		if ext != 0 && ext != 10 {
			exts = append(exts, ext)
		}
	}
	sort.Slice(exts, func(i, j int) bool { return exts[i] < exts[j] })
	ja4cStr := tools.Hex(sha256.Sum256([]byte(tools.AnyJoin(exts, ",") + "," + tools.AnyJoin(clientHelloParseData.Algorithms, ","))))[:12]
	ja4 := tools.AnyJoin([]string{ja4aStr, ja4bStr, ja4cStr}, "_")
	return ja4
}
func (obj *FpContextData) Ja4H(req *http.Request) string {
	ja4HaStr := "ge" + fmt.Sprintf("%d%d", req.ProtoMajor, req.ProtoMinor)
	headNum := len(req.Header)
	if req.Header.Get("Cookie") == "" {
		headNum--
		ja4HaStr += "n"
	} else {
		ja4HaStr += "c"
	}
	if req.Header.Get("Referer") == "" {
		headNum--
		ja4HaStr += "n"
	} else {
		ja4HaStr += "r"
	}
	headNumStr := fmt.Sprintf("%d", headNum)
	if len(headNumStr) < 2 {
		headNumStr = "0" + headNumStr
	}
	ja4HaStr += headNumStr
	lang := strings.ToLower(re.Sub(`[\s-,;\.=]`, "", req.Header.Get("Accept-Language")))
	if len(lang) < 4 {
		ja4HaStr += lang
		for i := 0; i < 4-len(lang); i++ {
			ja4HaStr += "0"
		}
	} else {
		ja4HaStr += lang[:4]
	}
	var ja4HbStr string
	orderHeaders := []string{}
	if obj.orderHeaders != nil {
		for _, cook := range obj.orderHeaders {
			if cook != "Cookie" && cook != "Referer" {
				orderHeaders = append(orderHeaders, cook)
			}
		}
	} else if obj.H2Ja3Spec().OrderHeaders != nil {
		for _, cook := range obj.H2Ja3Spec().OrderHeaders {
			if cook != "Cookie" && cook != "Referer" {
				orderHeaders = append(orderHeaders, cook)
			}
		}
	}
	ja4HbStr = tools.Hex(sha256.Sum256([]byte(strings.Join(orderHeaders, ","))))[:12]
	keys := []string{}
	vals := []string{}
	for _, cookie := range req.Cookies() {
		keys = append(keys, cookie.Name)
		vals = append(vals, fmt.Sprintf("%s=%s", cookie.Name, cookie.Value))
	}
	sort.Strings(keys)
	sort.Strings(vals)
	ja4HcStr := tools.Hex(sha256.Sum256([]byte(strings.Join(keys, ","))))[:12]
	ja4HdStr := tools.Hex(sha256.Sum256([]byte(strings.Join(vals, ","))))[:12]
	ja4H := tools.AnyJoin([]string{ja4HaStr, ja4HbStr, ja4HcStr, ja4HdStr}, "_")
	return ja4H
}
func (obj *FpContextData) ConnectionState() tls.ConnectionState {
	return obj.connectionState
}
func (obj *FpContextData) SetConnectionState(val tls.ConnectionState) {
	obj.connectionState = val
}

func (obj *FpContextData) ClientHello() (ClientHello, error) {
	return decodeClientHello(obj.clientHelloData)
}
func (obj *FpContextData) H2Ja3Spec() H2Ja3Spec {
	return obj.h2Ja3Spec
}

func (obj *FpContextData) SetClientHelloData(data []byte) {
	obj.clientHelloData = data
}
func (obj *FpContextData) SetInitialSetting(data []Setting) {
	obj.h2Ja3Spec.InitialSetting = data
}
func (obj *FpContextData) SetConnFlow(data uint32) {
	obj.h2Ja3Spec.ConnFlow = data
}
func (obj *FpContextData) OrderHeaders() []string {
	return obj.orderHeaders
}
func (obj *FpContextData) SetH2OrderHeaders(data []string) {
	obj.h2Ja3Spec.OrderHeaders = data
}
func (obj *FpContextData) SetOrderHeaders(data []string) {
	obj.orderHeaders = data
}
func (obj *FpContextData) SetPriority(data Priority) {
	obj.h2Ja3Spec.Priority = data
}

type keyPrincipal string

const keyPrincipalID keyPrincipal = "FpContextData"

func CreateContext(ctx context.Context) (ja3Ctx context.Context, ja3Context *FpContextData) {
	ja3Context = &FpContextData{}
	ja3Ctx = context.WithValue(ctx, keyPrincipalID, ja3Context)
	return
}
