package ja3

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/gospider007/tools"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/cryptobyte"
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
	utlsSpec := utls.ClientHelloSpec(ja3Spec)
	utlsSpec.Extensions = make([]utls.TLSExtension, len(ja3Spec.Extensions))
	for i := 0; i < len(ja3Spec.Extensions); i++ {
		extId, extType := getExtensionId(ja3Spec.Extensions[i])
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
	if err = utlsConn.HandshakeContext(ctx); err != nil {
		if err == io.EOF {
			err = nil
		} else if strings.HasSuffix(err.Error(), "bad record MAC") {
			err = fmt.Errorf("%w,%s", err, "this 22 extension is error")
		}
	}
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
	case 16:
		if option.ext != nil {
			extV := *(option.ext.(*utls.ALPNExtension))
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
		if option.ext != nil {
			extt := new(utls.KeyShareExtension)
			if keyShares := option.ext.(*utls.KeyShareExtension).KeyShares; keyShares != nil {
				extt.KeyShares = make([]utls.KeyShare, len(keyShares))
				copy(extt.KeyShares, keyShares)
			}
			return extt, true
		}
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
	tlsVersions := []string{}
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
						tlsVersions = append(tlsVersions, strconv.Itoa(int(tlsVersion)))
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
		strings.Join(tlsVersions, "-"),
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
	spec, _ := CreateSpecWithId(HelloChrome_114_Padding_PSK_Shuf)
	return spec
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
	h2Ja3Spec.OrderHeaders = []string{":method", ":authority", ":scheme", ":path"}
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
	cipherSuites := []uint16{utls.GREASE_PLACEHOLDER}
	for _, val := range ciphers {
		if n, err := strconv.ParseUint(val, 10, 16); err != nil {
			return nil, errors.New("ja3Str cipherSuites error")
		} else {
			cipherSuites = append(cipherSuites, uint16(n))
		}
	}
	return cipherSuites, nil
}
func createCurves(curves []string) (curvesExtension utls.TLSExtension, err error) {
	curveIds := []utls.CurveID{utls.GREASE_PLACEHOLDER}
	for _, val := range curves {
		if n, err := strconv.ParseUint(val, 10, 16); err != nil {
			return nil, errors.New("ja3Str curves error")
		} else {
			curveIds = append(curveIds, utls.CurveID(uint16(n)))
		}
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
	allExtensions := []utls.TLSExtension{&utls.UtlsGREASEExtension{}}
	for _, extension := range extensions {
		var extensionId uint16
		if n, err := strconv.ParseUint(extension, 10, 16); err != nil {
			return nil, errors.New("ja3Str extension error,utls not support: " + extension)
		} else {
			extensionId = uint16(n)
		}
		switch extensionId {
		case 10:
			allExtensions = append(allExtensions, curvesExtension)
		case 11:
			allExtensions = append(allExtensions, pointExtension)
		case 43:
			allExtensions = append(allExtensions, tlsExtension)
		default:
			ext, _ := createExtension(extensionId)
			if ext == nil {
				if IsGREASEUint16(extensionId) {
					allExtensions = append(allExtensions, &utls.UtlsGREASEExtension{})
				}
				allExtensions = append(allExtensions, &utls.GenericExtension{Id: extensionId})
			} else {
				if ext == nil {
					return nil, errors.New("ja3Str extension error,utls not support: " + extension)
				}
				if extensionId == 21 {
					allExtensions = append(allExtensions, &utls.UtlsGREASEExtension{})
				}
				allExtensions = append(allExtensions, ext)
			}
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

type FpContextData struct {
	clientHelloInfo tls.ClientHelloInfo
	clientHelloData []byte
	h2Ja3Spec       H2Ja3Spec
}

func GetFpContextData(ctx context.Context) (*FpContextData, bool) {
	data, ok := ctx.Value(keyPrincipalID).(*FpContextData)
	return data, ok
}

type ClientHelloInfo struct {
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

func (obj ClientHelloInfo) UtlsExtensions() map[uint16]utls.TLSExtension {
	exts := make(map[uint16]utls.TLSExtension)
	for i := 0; i < len(obj.Extensions); i++ {
		ext, _ := createExtension(obj.Extensions[i].Type, extensionOption{data: obj.Extensions[i].Data})
		exts[obj.Extensions[i].Type] = ext
	}
	return exts
}

// func (obj ClientHelloInfo) Ja3() {

// }
type ClientHelloParseData struct {
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

func (obj ClientHelloParseData) Fp() (string, string) {
	tlsVersion := fmt.Sprint(ClearGreas(obj.Versions)[0])
	ciphers := ClearGreas(obj.Ciphers)
	extensions := ClearGreas(obj.Extensions)
	curves := ClearGreas(obj.Curves)
	points := ClearGreas(obj.Points)
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

func ClearGreas(values []uint16) []uint16 {
	results := []uint16{}
	for _, value := range values {
		if !IsGREASEUint16(value) {
			results = append(results, value)
		}
	}
	return results
}

func (obj ClientHelloInfo) Parse() (clientHelloParseData ClientHelloParseData) {
	clientHelloParseData.Ciphers = obj.CipherSuites
	clientHelloParseData.Curves = obj.Curves()
	clientHelloParseData.Extensions = []uint16{}
	for _, extension := range obj.Extensions {
		clientHelloParseData.Extensions = append(clientHelloParseData.Extensions, extension.Type)
	}
	clientHelloParseData.Points = []uint16{}
	for _, point := range obj.Points() {
		clientHelloParseData.Points = append(clientHelloParseData.Points, uint16(point))
	}
	clientHelloParseData.Protocols = obj.Protocols()
	clientHelloParseData.Versions = obj.Versions()
	clientHelloParseData.Algorithms = obj.Algorithms()
	clientHelloParseData.RandomTime = time.Unix(int64(obj.RandomTime), 0).String()
	clientHelloParseData.RandomBytes = tools.Hex(obj.RandomBytes)
	clientHelloParseData.SessionId = tools.Hex(obj.SessionId)
	clientHelloParseData.CompressionMethods = tools.Hex(obj.CompressionMethods)
	return
}

// type:  11 : utls.SupportedPointsExtension
func (obj ClientHelloInfo) Points() []uint8 {
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
func (obj ClientHelloInfo) Protocols() []string {
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
func (obj ClientHelloInfo) Versions() []uint16 {
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
func (obj ClientHelloInfo) Algorithms() []uint16 {
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
func (obj ClientHelloInfo) Curves() []uint16 {
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

func decodeClientHello(clienthello []byte) (clientHelloInfo ClientHelloInfo, err error) {
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

func (obj *FpContextData) ClientHelloInfo() tls.ClientHelloInfo {
	return obj.clientHelloInfo
}
func (obj *FpContextData) RawClientHelloInfo() (ClientHelloInfo, error) {
	return decodeClientHello(obj.clientHelloData)
}
func (obj *FpContextData) H2Ja3Spec() H2Ja3Spec {
	return obj.h2Ja3Spec
}
func (obj *FpContextData) SetClientHelloInfo(data tls.ClientHelloInfo) {
	obj.clientHelloInfo = data
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
func (obj *FpContextData) SetOrderHeaders(data []string) {
	obj.h2Ja3Spec.OrderHeaders = data
}
func (obj *FpContextData) SetPriority(data Priority) {
	obj.h2Ja3Spec.Priority = data
}

type keyPrincipal string

const keyPrincipalID keyPrincipal = "FpContextData"

func ConnContext(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, keyPrincipalID, &FpContextData{})
}
func CreateContext(ctx context.Context) (ja3Ctx context.Context, ja3Context *FpContextData) {
	ja3Context = &FpContextData{}
	ja3Ctx = context.WithValue(ctx, keyPrincipalID, ja3Context)
	return
}
