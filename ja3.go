package ja3

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/textproto"
	"strconv"
	"strings"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/exp/slices"
)

type ClientHelloId = utls.ClientHelloID

func ShuffleExtensions(chs *Ja3Spec) {
	chs.Extensions = utls.ShuffleChromeTLSExtensions(chs.Extensions)
}

var (
	// HelloGolang will use default "crypto/tls" handshake marshaling codepath, which WILL
	// overwrite your changes to Hello(Config, Session are fine).
	// You might want to call BuildHandshakeState() before applying any changes.
	// UConn.Extensions will be completely ignored.
	HelloGolang = utls.HelloGolang

	// HelloCustom will prepare ClientHello with empty uconn.Extensions so you can fill it with
	// TLSExtensions manually or use ApplyPreset function
	HelloCustom = utls.HelloCustom

	// HelloRandomized* randomly adds/reorders extensions, ciphersuites, etc.
	HelloRandomized       = utls.HelloRandomized
	HelloRandomizedALPN   = utls.HelloRandomizedALPN
	HelloRandomizedNoALPN = utls.HelloRandomizedNoALPN

	// The rest will will parrot given browser.
	HelloFirefox_Auto = utls.HelloFirefox_Auto
	HelloFirefox_55   = utls.HelloFirefox_55
	HelloFirefox_56   = utls.HelloFirefox_56
	HelloFirefox_63   = utls.HelloFirefox_63
	HelloFirefox_65   = utls.HelloFirefox_65
	HelloFirefox_99   = utls.HelloFirefox_99
	HelloFirefox_102  = utls.HelloFirefox_102
	HelloFirefox_105  = utls.HelloFirefox_105

	HelloChrome_Auto        = utls.HelloChrome_Auto
	HelloChrome_58          = utls.HelloChrome_58
	HelloChrome_62          = utls.HelloChrome_62
	HelloChrome_70          = utls.HelloChrome_70
	HelloChrome_72          = utls.HelloChrome_72
	HelloChrome_83          = utls.HelloChrome_83
	HelloChrome_87          = utls.HelloChrome_87
	HelloChrome_96          = utls.HelloChrome_96
	HelloChrome_100         = utls.HelloChrome_100
	HelloChrome_102         = utls.HelloChrome_102
	HelloChrome_106_Shuffle = utls.HelloChrome_106_Shuffle

	// Chrome w/ PSK: Chrome start sending this ClientHello after doing TLS 1.3 handshake with the same server.
	// Beta: PSK extension added. However, uTLS doesn't ship with full PSK support.
	// Use at your own discretion.
	HelloChrome_100_PSK              = utls.HelloChrome_100_PSK
	HelloChrome_112_PSK_Shuf         = utls.HelloChrome_112_PSK_Shuf
	HelloChrome_114_Padding_PSK_Shuf = utls.HelloChrome_114_Padding_PSK_Shuf

	// Chrome w/ Post-Quantum Key Agreement
	// Beta: PQ extension added. However, uTLS doesn't ship with full PQ support. Use at your own discretion.
	HelloChrome_115_PQ     = utls.HelloChrome_115_PQ
	HelloChrome_115_PQ_PSK = utls.HelloChrome_115_PQ_PSK

	HelloChrome_120    = utls.HelloChrome_120
	HelloChrome_120_PQ = utls.HelloChrome_120_PQ

	HelloIOS_Auto = utls.HelloIOS_Auto
	HelloIOS_11_1 = utls.HelloIOS_11_1
	HelloIOS_12_1 = utls.HelloIOS_12_1
	HelloIOS_13   = utls.HelloIOS_13
	HelloIOS_14   = utls.HelloIOS_14

	HelloAndroid_11_OkHttp = utls.HelloAndroid_11_OkHttp

	HelloEdge_Auto = utls.HelloEdge_Auto
	HelloEdge_85   = utls.HelloEdge_85
	HelloEdge_106  = utls.HelloEdge_106

	HelloSafari_Auto = utls.HelloSafari_Auto
	HelloSafari_16_0 = utls.HelloSafari_16_0

	Hello360_Auto = utls.Hello360_Auto
	Hello360_7_5  = utls.Hello360_7_5
	Hello360_11_0 = utls.Hello360_11_0

	HelloQQ_Auto = utls.HelloQQ_Auto
	HelloQQ_11_1 = utls.HelloQQ_11_1
)

func NewClient(ctx context.Context, conn net.Conn, ja3Spec Ja3Spec, disHttp2 bool, utlsConfig *utls.Config) (utlsConn *utls.UConn, err error) {
	utlsConfig.NextProtos = []string{"h2", "http/1.1"}
	utlsSpec := utls.ClientHelloSpec(ja3Spec)
	total := len(ja3Spec.Extensions)
	utlsSpec.Extensions = make([]utls.TLSExtension, total)
	lastIndex := -1
	for i := 0; i < total; i++ {
		extId, extType := getExtensionId(ja3Spec.Extensions[i])
		if extId == 41 {
			lastIndex = i
		}
		switch extType {
		case 3:
			return nil, fmt.Errorf("unknow extentsion：%T", ja3Spec.Extensions[i])
		case 0:
			if ext, _ := createExtension(extId, extensionOption{ext: ja3Spec.Extensions[i]}); ext != nil {
				utlsSpec.Extensions[i] = ext
			} else {
				utlsSpec.Extensions[i] = ja3Spec.Extensions[i]
			}
		default:
			utlsSpec.Extensions[i] = ja3Spec.Extensions[i]
		}
	}
	if lastIndex != -1 {
		utlsSpec.Extensions[lastIndex], utlsSpec.Extensions[total-1] = utlsSpec.Extensions[total-1], utlsSpec.Extensions[lastIndex]
	}
	if disHttp2 {
		for _, Extension := range utlsSpec.Extensions {
			alpns, ok := Extension.(*utls.ALPNExtension)
			if ok {
				if i := slices.Index(alpns.AlpnProtocols, "h2"); i != -1 {
					alpns.AlpnProtocols = slices.Delete(alpns.AlpnProtocols, i, i+1)
				}
				if !slices.Contains(alpns.AlpnProtocols, "http/1.1") {
					alpns.AlpnProtocols = append([]string{"http/1.1"}, alpns.AlpnProtocols...)
				}
				break
			}
		}
	}
	utlsConn = utls.UClient(conn, utlsConfig, utls.HelloCustom)
	if err = utlsConn.ApplyPreset(&utlsSpec); err != nil {
		return nil, err
	}
	err = utlsConn.HandshakeContext(ctx)
	return utlsConn, err
}

// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
type extensionOption struct {
	data []byte
	ext  utls.TLSExtension
}

func createExtension(extensionId uint16, options ...extensionOption) (utls.TLSExtension, bool) {
	var option extensionOption
	if len(options) > 0 {
		option = options[0]
	}
	switch extensionId {
	case 0:
		if option.ext != nil {
			extV := *(option.ext.(*utls.SNIExtension))
			return &extV, true
		}
		extV := new(utls.SNIExtension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 5:
		if option.ext != nil {
			extV := *(option.ext.(*utls.StatusRequestExtension))
			return &extV, true
		}
		extV := new(utls.StatusRequestExtension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 10:
		if option.ext != nil {
			extV := *(option.ext.(*utls.SupportedCurvesExtension))
			return &extV, true
		}
		extV := new(utls.SupportedCurvesExtension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 11:
		if option.ext != nil {
			extV := *(option.ext.(*utls.SupportedPointsExtension))
			return &extV, true
		}
		extV := new(utls.SupportedPointsExtension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 13:
		if option.ext != nil {
			extV := *(option.ext.(*utls.SignatureAlgorithmsExtension))
			return &extV, true
		}
		extV := new(utls.SignatureAlgorithmsExtension)
		if option.data != nil {
			extV.Write(option.data)
		} else {
			extV.SupportedSignatureAlgorithms = []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.PSSWithSHA256,
				utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.PSSWithSHA384,
				utls.PKCS1WithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA512,
			}
		}
		return extV, true
	case 16:
		if option.ext != nil {
			extV := *(option.ext.(*utls.ALPNExtension))
			exts := []string{}
			for _, alp := range extV.AlpnProtocols {
				if alp != "" {
					exts = append(exts, alp)
				}
			}
			extV.AlpnProtocols = exts
			return &extV, true
		}
		extV := new(utls.ALPNExtension)
		if option.data != nil {
			extV.Write(option.data)
		} else {
			extV.AlpnProtocols = []string{"h2", "http/1.1"}
		}
		return extV, true
	case 17:
		if option.ext != nil {
			extV := *(option.ext.(*utls.StatusRequestV2Extension))
			return &extV, true
		}
		extV := new(utls.StatusRequestV2Extension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 18:
		if option.ext != nil {
			extV := *(option.ext.(*utls.SCTExtension))
			return &extV, true
		}
		extV := new(utls.SCTExtension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 21:
		if option.ext != nil {
			extV := *(option.ext.(*utls.UtlsPaddingExtension))
			return &extV, true
		}
		extV := new(utls.UtlsPaddingExtension)
		if option.data != nil {
			extV.Write(option.data)
		} else {
			extV.GetPaddingLen = utls.BoringPaddingStyle
		}
		return extV, true
	case 23:
		if option.ext != nil {
			extV := *(option.ext.(*utls.ExtendedMasterSecretExtension))
			return &extV, true
		}
		extV := new(utls.ExtendedMasterSecretExtension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 24:
		if option.ext != nil {
			extV := *(option.ext.(*utls.FakeTokenBindingExtension))
			return &extV, true
		}
		extV := new(utls.FakeTokenBindingExtension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 27:
		if option.ext != nil {
			extV := *(option.ext.(*utls.UtlsCompressCertExtension))
			return &extV, true
		}
		extV := new(utls.UtlsCompressCertExtension)
		if option.data != nil {
			extV.Write(option.data)
		} else {
			extV.Algorithms = []utls.CertCompressionAlgo{utls.CertCompressionBrotli}
		}
		return extV, true
	case 28:
		if option.ext != nil {
			extV := *(option.ext.(*utls.FakeRecordSizeLimitExtension))
			return &extV, true
		}
		extV := new(utls.FakeRecordSizeLimitExtension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 34:
		if option.ext != nil {
			extV := *(option.ext.(*utls.FakeDelegatedCredentialsExtension))
			return &extV, true
		}
		extV := new(utls.FakeDelegatedCredentialsExtension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 35:
		if option.ext != nil {
			extV := *(option.ext.(*utls.SessionTicketExtension))
			return &extV, true
		}
		extV := new(utls.SessionTicketExtension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 41:
		if option.ext != nil {
			extV := *(option.ext.(*utls.UtlsPreSharedKeyExtension))
			return &extV, true
		}
		extV := new(utls.UtlsPreSharedKeyExtension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 43:
		if option.ext != nil {
			extV := *(option.ext.(*utls.SupportedVersionsExtension))
			return &extV, true
		}
		extV := new(utls.SupportedVersionsExtension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 44:
		if option.ext != nil {
			extV := *(option.ext.(*utls.CookieExtension))
			return &extV, true
		}
		extV := new(utls.CookieExtension)
		if option.data != nil {
			extV.Cookie = option.data
		}
		return extV, true
	case 45:
		if option.ext != nil {
			extV := *(option.ext.(*utls.PSKKeyExchangeModesExtension))
			return &extV, true
		}
		extV := new(utls.PSKKeyExchangeModesExtension)
		if option.data != nil {
			extV.Write(option.data)
		} else {
			extV.Modes = []uint8{utls.PskModeDHE}
		}
		return extV, true
	case 50:
		if option.ext != nil {
			extV := *(option.ext.(*utls.SignatureAlgorithmsCertExtension))
			return &extV, true
		}
		extV := new(utls.SignatureAlgorithmsCertExtension)
		if option.data != nil {
			extV.Write(option.data)
		} else {
			extV.SupportedSignatureAlgorithms = []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.ECDSAWithP521AndSHA512,
				utls.PSSWithSHA256,
				utls.PSSWithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA256,
				utls.PKCS1WithSHA384,
				utls.PKCS1WithSHA512,
				utls.ECDSAWithSHA1,
				utls.PKCS1WithSHA1,
			}
		}
		return extV, true
	case 51:
		extV := new(utls.KeyShareExtension)
		if option.data != nil {
			extV.Write(option.data)
		} else {
			extV.KeyShares = []utls.KeyShare{
				{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
				{Group: utls.X25519},
			}
		}
		return extV, true
	case 57:
		if option.ext != nil {
			extV := *(option.ext.(*utls.QUICTransportParametersExtension))
			return &extV, true
		}
		return new(utls.QUICTransportParametersExtension), true
	case 13172:
		if option.ext != nil {
			extV := *(option.ext.(*utls.NPNExtension))
			return &extV, true
		}
		extV := new(utls.NPNExtension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 17513:
		if option.ext != nil {
			extV := *(option.ext.(*utls.ApplicationSettingsExtension))
			return &extV, true
		}
		extV := new(utls.ApplicationSettingsExtension)
		if option.data != nil {
			extV.Write(option.data)
		} else {
			extV.SupportedProtocols = []string{"h2", "http/1.1"}
		}
		return extV, true
	case 30031:
		if option.ext != nil {
			extV := *(option.ext.(*utls.FakeChannelIDExtension))
			return &extV, true
		}
		extV := new(utls.FakeChannelIDExtension)
		if option.data != nil {
			extV.Write(option.data)
		} else {
			extV.OldExtensionID = true
		}
		return extV, true
	case 30032:
		if option.ext != nil {
			extV := *(option.ext.(*utls.FakeChannelIDExtension))
			return &extV, true
		}
		extV := new(utls.FakeChannelIDExtension)
		if option.data != nil {
			extV.Write(option.data)
		}
		return extV, true
	case 65037:
		if option.ext != nil {
			return option.ext, true
		}
		return utls.BoringGREASEECH(), true
	case 65281:
		if option.ext != nil {
			extV := *(option.ext.(*utls.RenegotiationInfoExtension))
			return &extV, true
		}
		extV := new(utls.RenegotiationInfoExtension)
		if option.data != nil {
			extV.Write(option.data)
		} else {
			extV.Renegotiation = utls.RenegotiateOnceAsClient
		}
		return extV, true
	default:
		if option.data != nil {
			return &utls.GenericExtension{
				Id:   extensionId,
				Data: option.data,
			}, false
		}
		return option.ext, false
	}
}

// type,0: is ext, 1：custom ext，2：grease ext , 3：unknow ext
func getExtensionId(extension utls.TLSExtension) (uint16, uint8) {
	switch ext := extension.(type) {
	case *utls.SNIExtension:
		return 0, 0
	case *utls.StatusRequestExtension:
		return 5, 0
	case *utls.SupportedCurvesExtension:
		return 10, 0
	case *utls.SupportedPointsExtension:
		return 11, 0
	case *utls.SignatureAlgorithmsExtension:
		return 13, 0
	case *utls.ALPNExtension:
		return 16, 0
	case *utls.StatusRequestV2Extension:
		return 17, 0
	case *utls.SCTExtension:
		return 18, 0
	case *utls.UtlsPaddingExtension:
		return 21, 0
	case *utls.ExtendedMasterSecretExtension:
		return 23, 0
	case *utls.FakeTokenBindingExtension:
		return 24, 0
	case *utls.UtlsCompressCertExtension:
		return 27, 0
	case *utls.FakeDelegatedCredentialsExtension:
		return 34, 0
	case *utls.SessionTicketExtension:
		return 35, 0
	case *utls.UtlsPreSharedKeyExtension:
		return 41, 0
	case *utls.SupportedVersionsExtension:
		return 43, 0
	case *utls.CookieExtension:
		return 44, 0
	case *utls.PSKKeyExchangeModesExtension:
		return 45, 0
	case *utls.SignatureAlgorithmsCertExtension:
		return 50, 0
	case *utls.KeyShareExtension:
		return 51, 0
	case *utls.QUICTransportParametersExtension:
		return 57, 0
	case *utls.NPNExtension:
		return 13172, 0
	case *utls.ApplicationSettingsExtension:
		return 17513, 0
	case *utls.FakeChannelIDExtension:
		if ext.OldExtensionID {
			return 30031, 0
		} else {
			return 30031, 0
		}
	case *utls.FakeRecordSizeLimitExtension:
		return 28, 0
	case *utls.GREASEEncryptedClientHelloExtension:
		return 65037, 0
	case *utls.RenegotiationInfoExtension:
		return 65281, 0
	case *utls.GenericExtension:
		return ext.Id, 1
	case *utls.UtlsGREASEExtension:
		return 0, 2
	default:
		return 0, 3
	}
}
func IsGREASEUint16(v uint16) bool {
	// First byte is same as second byte
	// and lowest nibble is 0xa
	return ((v >> 8) == v&0xff) && v&0xf == 0xa
}

type Ja3Spec utls.ClientHelloSpec

func (obj Ja3Spec) String() string {
	tlsVersions := "771"
	cipherSuites := []string{}
	for _, cipcipherSuite := range obj.CipherSuites {
		if cipcipherSuite != utls.GREASE_PLACEHOLDER {
			cipherSuites = append(cipherSuites, strconv.Itoa(int(cipcipherSuite)))
		}
	}
	extIds := []int{}
	curves := []string{}
	points := []string{}

	for _, Extension := range obj.Extensions {
		extId, extType := getExtensionId(Extension)
		switch extType {
		case 0:
			extIds = append(extIds, int(extId))
			switch extId {
			case 43:
				for _, tlsVersion := range Extension.(*utls.SupportedVersionsExtension).Versions {
					if tlsVersion != utls.GREASE_PLACEHOLDER {
						tlsVersions = strconv.Itoa(int(tlsVersion))
						break
					}
				}
			case 10:
				for _, curve := range Extension.(*utls.SupportedCurvesExtension).Curves {
					if curve != utls.GREASE_PLACEHOLDER {
						curves = append(curves, strconv.Itoa(int(curve)))
					}
				}
			case 11:
				for _, point := range Extension.(*utls.SupportedPointsExtension).SupportedPoints {
					points = append(points, strconv.Itoa(int(point)))
				}
			}
		case 1:
			extIds = append(extIds, int(Extension.(*utls.GenericExtension).Id))
		}

	}
	// slices.Sort(extIds)
	extIdsr := make([]string, len(extIds))
	for i, extId := range extIds {
		extIdsr[i] = strconv.Itoa(extId)
	}
	return strings.Join([]string{
		tlsVersions,
		strings.Join(cipherSuites, "-"),
		strings.Join(extIdsr, "-"),
		strings.Join(curves, "-"),
		strings.Join(points, "-"),
	}, ",")
}

// have value
func (obj Ja3Spec) IsSet() bool {
	if obj.CipherSuites != nil || obj.Extensions != nil || obj.CompressionMethods != nil ||
		obj.TLSVersMax != 0 || obj.TLSVersMin != 0 {
		return true
	}
	return false
}

type Setting struct {
	// ID is which setting is being set.
	// See https://httpwg.org/specs/rfc7540.html#SettingFormat
	Id uint16
	// Val is the value.
	Val uint32
}
type Priority struct {
	// StreamDep is a 31-bit stream identifier for the
	// stream that this stream depends on. Zero means no
	// dependency.
	StreamDep uint32

	// Exclusive is whether the dependency is exclusive.
	Exclusive bool

	// Weight is the stream's zero-indexed weight. It should be
	// set together with StreamDep, or neither should be set. Per
	// the spec, "Add one to the value to obtain a weight between
	// 1 and 256."
	Weight uint8
}

// have value
func (obj Priority) IsSet() bool {
	if obj.StreamDep != 0 || obj.Exclusive || obj.Weight != 0 {
		return true
	}
	return false
}

func DefaultJa3Spec() Ja3Spec {
	spec, _ := CreateSpecWithId(HelloChrome_Auto)
	return spec
}

var defaultOrderHeadersH2 = []string{
	":method",
	":authority",
	":scheme",
	":path",
}
var defaultOrderHeaders = []string{
	":method",
	":authority",
	":scheme",
	":path",
	"Host",
	"Connection",
	"Content-Length",
	"pragma",
	"cache-control",
	"sec-ch-ua",
	"sec-ch-ua-mobile",
	"sec-ch-ua-platform",
	"upgrade-insecure-requests",
	"accept",
	"user-agent",
	"origin",
	"Referer",
	"sec-fetch-site",
	"sec-fetch-mode",
	"sec-fetch-user",
	"sec-fetch-dest",
	"accept-encoding",
	"accept-language",
	"Cookie",
}

func DefaultOrderHeaders() []string {
	headers := make([]string, len(defaultOrderHeaders))
	for i, key := range defaultOrderHeaders {
		headers[i] = textproto.CanonicalMIMEHeaderKey(key)
	}
	return headers
}
func DefaultOrderHeadersWithH2() []string {
	headers := make([]string, len(defaultOrderHeadersH2))
	copy(headers, defaultOrderHeaders)
	return headers
}
func DefaultH2Ja3Spec() H2Ja3Spec {
	var h2Ja3Spec H2Ja3Spec
	h2Ja3Spec.InitialSetting = []Setting{
		{Id: 1, Val: 65536},
		{Id: 2, Val: 0},
		{Id: 3, Val: 1000},
		{Id: 4, Val: 6291456},
		{Id: 6, Val: 262144},
	}
	h2Ja3Spec.Priority = Priority{
		Exclusive: true,
		StreamDep: 0,
		Weight:    255,
	}
	h2Ja3Spec.OrderHeaders = DefaultOrderHeaders()
	h2Ja3Spec.ConnFlow = 15663105
	return h2Ja3Spec
}

type H2Ja3Spec struct {
	InitialSetting []Setting
	ConnFlow       uint32   //WINDOW_UPDATE:15663105
	OrderHeaders   []string //example：[]string{":method",":authority",":scheme",":path"}
	Priority       Priority
}

// have value
func (obj H2Ja3Spec) IsSet() bool {
	if obj.InitialSetting != nil || obj.ConnFlow != 0 || obj.OrderHeaders != nil || obj.Priority.IsSet() {
		return true
	}
	return false
}

func (obj H2Ja3Spec) Fp() string {
	settings := []string{}
	for _, setting := range obj.InitialSetting {
		settings = append(settings, fmt.Sprintf("%d:%d", setting.Id, setting.Val))
	}
	heads := []string{}
	for _, head := range obj.OrderHeaders {
		head = strings.ToLower(head)
		switch head {
		case ":method":
			heads = append(heads, "m")
		case ":authority":
			heads = append(heads, "a")
		case ":scheme":
			heads = append(heads, "s")
		case ":path":
			heads = append(heads, "p")
		}
	}
	return strings.Join([]string{
		strings.Join(settings, ","),
		fmt.Sprint(obj.ConnFlow),
		"0",
		strings.Join(heads, ","),
	}, "|")
}

func CreateSpecWithId(ja3Id ClientHelloId) (clientHelloSpec Ja3Spec, err error) {
	spec, err := utls.UTLSIdToSpec(ja3Id)
	if err != nil {
		return clientHelloSpec, err
	}
	return Ja3Spec(spec), nil
}

// TLSVersion，Ciphers，Extensions，EllipticCurves，EllipticCurvePointFormats
func createTlsVersion(ver uint16) (tlsMaxVersion uint16, tlsMinVersion uint16, tlsSuppor utls.TLSExtension, err error) {
	switch ver {
	case utls.VersionTLS13:
		tlsMaxVersion = utls.VersionTLS13
		tlsMinVersion = utls.VersionTLS12
		tlsSuppor = &utls.SupportedVersionsExtension{
			Versions: []uint16{
				utls.GREASE_PLACEHOLDER,
				utls.VersionTLS13,
				utls.VersionTLS12,
			},
		}
	case utls.VersionTLS12:
		tlsMaxVersion = utls.VersionTLS12
		tlsMinVersion = utls.VersionTLS11
		tlsSuppor = &utls.SupportedVersionsExtension{
			Versions: []uint16{
				utls.GREASE_PLACEHOLDER,
				utls.VersionTLS12,
				utls.VersionTLS11,
			},
		}
	case utls.VersionTLS11:
		tlsMaxVersion = utls.VersionTLS11
		tlsMinVersion = utls.VersionTLS10
		tlsSuppor = &utls.SupportedVersionsExtension{
			Versions: []uint16{
				utls.GREASE_PLACEHOLDER,
				utls.VersionTLS11,
				utls.VersionTLS10,
			},
		}
	default:
		err = errors.New("ja3Str tls version error")
	}
	return
}
func createCiphers(ciphers []string) ([]uint16, error) {
	cipherSuites := []uint16{}
	for i, val := range ciphers {
		var cipherSuite uint16
		if n, err := strconv.ParseUint(val, 10, 16); err != nil {
			return nil, errors.New("ja3Str cipherSuites error")
		} else {
			cipherSuite = uint16(n)
		}
		if i == 0 {
			if cipherSuite != utls.GREASE_PLACEHOLDER {
				cipherSuites = append(cipherSuites, utls.GREASE_PLACEHOLDER)
			}
		}
		cipherSuites = append(cipherSuites, cipherSuite)
	}
	return cipherSuites, nil
}
func createCurves(curves []string) (curvesExtension utls.TLSExtension, err error) {
	curveIds := []utls.CurveID{}
	for i, val := range curves {
		var curveId utls.CurveID
		if n, err := strconv.ParseUint(val, 10, 16); err != nil {
			return nil, errors.New("ja3Str curves error")
		} else {
			curveId = utls.CurveID(uint16(n))
		}
		if i == 0 {
			if curveId != utls.GREASE_PLACEHOLDER {
				curveIds = append(curveIds, utls.GREASE_PLACEHOLDER)
			}
		}
		curveIds = append(curveIds, curveId)
	}
	return &utls.SupportedCurvesExtension{Curves: curveIds}, nil
}
func createPointFormats(points []string) (curvesExtension utls.TLSExtension, err error) {
	supportedPoints := []uint8{}
	for _, val := range points {
		if n, err := strconv.ParseUint(val, 10, 8); err != nil {
			return nil, errors.New("ja3Str point error")
		} else {
			supportedPoints = append(supportedPoints, uint8(n))
		}
	}
	return &utls.SupportedPointsExtension{SupportedPoints: supportedPoints}, nil
}

func createExtensions(extensions []string, tlsExtension, curvesExtension, pointExtension utls.TLSExtension) ([]utls.TLSExtension, error) {
	allExtensions := []utls.TLSExtension{}
	for i, extension := range extensions {
		var extensionId uint16
		if n, err := strconv.ParseUint(extension, 10, 16); err != nil {
			return nil, errors.New("ja3Str extension error,utls not support: " + extension)
		} else {
			extensionId = uint16(n)
		}
		var ext utls.TLSExtension
		switch extensionId {
		case 10:
			ext = curvesExtension
		case 11:
			ext = pointExtension
		case 43:
			ext = tlsExtension
		default:
			ext, _ = createExtension(extensionId)
			if ext == nil {
				ext = &utls.GenericExtension{Id: extensionId}
			}
		}
		if i == 0 {
			if _, ok := ext.(*utls.UtlsGREASEExtension); !ok {
				allExtensions = append(allExtensions, &utls.UtlsGREASEExtension{})
			}
		}
		allExtensions = append(allExtensions, ext)
	}
	if l := len(allExtensions); l > 0 {
		if _, ok := allExtensions[l-1].(*utls.UtlsGREASEExtension); !ok {
			allExtensions = append(allExtensions, &utls.UtlsGREASEExtension{})
		}
	}
	return allExtensions, nil
}

// ja3 字符串中生成 clientHello
func CreateSpecWithStr(ja3Str string) (clientHelloSpec Ja3Spec, err error) {
	tokens := strings.Split(ja3Str, ",")
	if len(tokens) != 5 {
		return clientHelloSpec, errors.New("ja3Str format error")
	}
	ver, err := strconv.ParseUint(tokens[0], 10, 16)
	if err != nil {
		return clientHelloSpec, errors.New("ja3Str tlsVersion error")
	}
	ciphers := strings.Split(tokens[1], "-")
	extensions := strings.Split(tokens[2], "-")
	curves := strings.Split(tokens[3], "-")
	pointFormats := strings.Split(tokens[4], "-")
	tlsMaxVersion, tlsMinVersion, tlsExtension, err := createTlsVersion(uint16(ver))
	if err != nil {
		return clientHelloSpec, err
	}
	clientHelloSpec.TLSVersMax = tlsMaxVersion
	clientHelloSpec.TLSVersMin = tlsMinVersion
	if clientHelloSpec.CipherSuites, err = createCiphers(ciphers); err != nil {
		return
	}
	curvesExtension, err := createCurves(curves)
	if err != nil {
		return clientHelloSpec, err
	}
	pointExtension, err := createPointFormats(pointFormats)
	if err != nil {
		return clientHelloSpec, err
	}
	clientHelloSpec.CompressionMethods = []byte{0}
	clientHelloSpec.GetSessionID = sha256.Sum256
	clientHelloSpec.Extensions, err = createExtensions(extensions, tlsExtension, curvesExtension, pointExtension)
	return
}

func CreateH2SpecWithStr(h2ja3SpecStr string) (h2ja3Spec H2Ja3Spec, err error) {
	tokens := strings.Split(h2ja3SpecStr, "|")
	if len(tokens) != 4 {
		err = errors.New("h2 spec format error")
		return
	}
	h2ja3Spec.InitialSetting = []Setting{}
	for _, setting := range strings.Split(tokens[0], ",") {
		tts := strings.Split(setting, ":")
		if len(tts) != 2 {
			err = errors.New("h2 setting error")
			return
		}
		var ttKey, ttVal int
		if ttKey, err = strconv.Atoi(tts[0]); err != nil {
			return
		}
		if ttVal, err = strconv.Atoi(tts[1]); err != nil {
			return
		}
		h2ja3Spec.InitialSetting = append(h2ja3Spec.InitialSetting, Setting{
			Id:  uint16(ttKey),
			Val: uint32(ttVal),
		})
	}
	var connFlow int
	if connFlow, err = strconv.Atoi(tokens[1]); err != nil {
		return
	}
	h2ja3Spec.ConnFlow = uint32(connFlow)
	h2ja3Spec.OrderHeaders = []string{}
	for _, hkey := range strings.Split(tokens[3], ",") {
		switch hkey {
		case "m":
			h2ja3Spec.OrderHeaders = append(h2ja3Spec.OrderHeaders, ":method")
		case "a":
			h2ja3Spec.OrderHeaders = append(h2ja3Spec.OrderHeaders, ":authority")
		case "s":
			h2ja3Spec.OrderHeaders = append(h2ja3Spec.OrderHeaders, ":scheme")
		case "p":
			h2ja3Spec.OrderHeaders = append(h2ja3Spec.OrderHeaders, ":path")
		}
	}
	return
}

func CreateSpecWithClientHello(clienthello any) (clientHelloSpec Ja3Spec, err error) {
	var clientHelloInfo ClientHello
	switch value := clienthello.(type) {
	case []byte:
		clientHelloInfo, err = decodeClientHello(value)
	case string:
		v, err := hex.DecodeString(value)
		if err != nil {
			return clientHelloSpec, err
		}
		clientHelloInfo, err = decodeClientHello(v)
		if err != nil {
			return clientHelloSpec, err
		}
	default:
		return clientHelloSpec, errors.New("clienthello type error")
	}
	if err != nil {
		return clientHelloSpec, err
	}
	clientHelloSpec.CipherSuites = clientHelloInfo.CipherSuites
	clientHelloSpec.CompressionMethods = clientHelloInfo.CompressionMethods
	clientHelloSpec.Extensions = make([]utls.TLSExtension, len(clientHelloInfo.Extensions))
	for i, ext := range clientHelloInfo.Extensions {
		clientHelloSpec.Extensions[i] = ext.utlsExt()
	}
	clientHelloSpec.GetSessionID = sha256.Sum256
	return clientHelloSpec, nil
}
