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
	"sync"

	"net/http"

	"gitee.com/baixudong/tools"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/exp/slices"
)

func NewOneSessionCache(session *utls.ClientSessionState) *OneSessionCache {
	return &OneSessionCache{session: session}
}

type OneSessionCache struct {
	session    *utls.ClientSessionState
	newSession *utls.ClientSessionState
}

func (obj *OneSessionCache) Get(sessionKey string) (*utls.ClientSessionState, bool) {
	return obj.session, obj.session != nil
}
func (obj *OneSessionCache) Put(sessionKey string, cs *utls.ClientSessionState) {
	if cs != nil {
		obj.newSession = cs
	}
}
func (obj *OneSessionCache) Session() *utls.ClientSessionState {
	return obj.newSession
}

type ClientSessionCache struct {
	sessionKeyMap map[string]*utls.ClientSessionState
	newSession    *utls.ClientSessionState
	lock          sync.RWMutex
}

func NewClientSessionCache() *ClientSessionCache {
	return &ClientSessionCache{
		sessionKeyMap: make(map[string]*utls.ClientSessionState),
	}
}
func (obj *ClientSessionCache) Get(sessionKey string) (session *utls.ClientSessionState, ok bool) {
	obj.lock.RLock()
	defer obj.lock.RUnlock()
	session, ok = obj.sessionKeyMap[sessionKey]
	return
}

func (obj *ClientSessionCache) Put(sessionKey string, cs *utls.ClientSessionState) {
	obj.lock.Lock()
	defer obj.lock.Unlock()
	obj.sessionKeyMap[sessionKey] = cs
	obj.newSession = cs
}

func (obj *ClientSessionCache) Session() *utls.ClientSessionState {
	return obj.newSession
}

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
			return nil, fmt.Errorf("未知的扩展：%T", ja3Spec.Extensions[i])
		case 0:
			if ext := getExtensionWithId(extId, ja3Spec.Extensions[i]); ext != nil {
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
			err = tools.WrapError(err, "检测到22扩展异常,请删除此扩展后重试")
		}
	}
	return utlsConn, err
}

// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
func getExtensionWithId(extensionId uint16, exts ...utls.TLSExtension) utls.TLSExtension {
	var ext utls.TLSExtension
	if len(exts) > 0 {
		ext = exts[0]
	}
	switch extensionId {
	case 0:
		if ext != nil {
			extV := *(ext.(*utls.SNIExtension))
			return &extV
		}
		return &utls.SNIExtension{}
	case 5:
		return &utls.StatusRequestExtension{}
	case 10:
		if ext != nil {
			extV := *(ext.(*utls.SupportedCurvesExtension))
			return &extV
		}
		return &utls.SupportedCurvesExtension{}
	case 11:
		if ext != nil {
			extV := *(ext.(*utls.SupportedPointsExtension))
			return &extV
		}
		return &utls.SupportedPointsExtension{}
	case 13:
		if ext != nil {
			extV := *(ext.(*utls.SignatureAlgorithmsExtension))
			return &extV
		}
		return &utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
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
		}}
	case 16:
		if ext != nil {
			extV := *(ext.(*utls.ALPNExtension))
			return &extV
		}
		return &utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}}
	case 17:
		return &utls.StatusRequestV2Extension{}
	case 18:
		return &utls.SCTExtension{}
	case 21:
		if ext != nil {
			extV := *(ext.(*utls.UtlsPaddingExtension))
			return &extV
		}
		return &utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle}
	case 23:
		return &utls.ExtendedMasterSecretExtension{}
	case 24:
		if ext != nil {
			extV := *(ext.(*utls.FakeTokenBindingExtension))
			return &extV
		}
		return &utls.FakeTokenBindingExtension{}
	case 27:
		if ext != nil {
			extV := *(ext.(*utls.UtlsCompressCertExtension))
			return &extV
		}
		return &utls.UtlsCompressCertExtension{
			Algorithms: []utls.CertCompressionAlgo{utls.CertCompressionBrotli},
		}
	case 34:
		if ext != nil {
			extV := *(ext.(*utls.FakeDelegatedCredentialsExtension))
			return &extV
		}
		return &utls.FakeDelegatedCredentialsExtension{}
	case 35:
		if ext != nil {
			extV := *(ext.(*utls.SessionTicketExtension))
			return &extV
		}
		return &utls.SessionTicketExtension{}
	case 41:
		if ext != nil {
			extV := *(ext.(*utls.UtlsPreSharedKeyExtension))
			return &extV
		}
		return &utls.UtlsPreSharedKeyExtension{}
	case 43:
		if ext != nil {
			extV := *(ext.(*utls.SupportedVersionsExtension))
			return &extV
		}
		return &utls.SupportedVersionsExtension{}
	case 44:
		if ext != nil {
			extV := *(ext.(*utls.CookieExtension))
			return &extV
		}
		return &utls.CookieExtension{}
	case 45:
		if ext != nil {
			extV := *(ext.(*utls.PSKKeyExchangeModesExtension))
			return &extV
		}
		return &utls.PSKKeyExchangeModesExtension{Modes: []uint8{
			utls.PskModeDHE,
		}}
	case 50:
		if ext != nil {
			extV := *(ext.(*utls.SignatureAlgorithmsCertExtension))
			return &extV
		}
		return &utls.SignatureAlgorithmsCertExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
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
		}}
	case 51:
		if ext != nil {
			return &utls.KeyShareExtension{
				KeyShares: tools.CopySlices(ext.(*utls.KeyShareExtension).KeyShares),
			}
		}
		return &utls.KeyShareExtension{
			KeyShares: []utls.KeyShare{
				{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
				{Group: utls.X25519},
			},
		}
	case 57:
		if ext != nil {
			extV := *(ext.(*utls.QUICTransportParametersExtension))
			return &extV
		}
		return &utls.QUICTransportParametersExtension{}
	case 13172:
		if ext != nil {
			extV := *(ext.(*utls.NPNExtension))
			return &extV
		}
		return &utls.NPNExtension{}
	case 17513:
		if ext != nil {
			extV := *(ext.(*utls.ApplicationSettingsExtension))
			return &extV
		}
		return &utls.ApplicationSettingsExtension{SupportedProtocols: []string{"h2", "http/1.1"}}
	case 30031:
		if ext != nil {
			extV := *(ext.(*utls.FakeChannelIDExtension))
			return &extV
		}
		return &utls.FakeChannelIDExtension{OldExtensionID: true} //FIXME
	case 30032:
		if ext != nil {
			extV := *(ext.(*utls.FakeChannelIDExtension))
			return &extV
		}
		return &utls.FakeChannelIDExtension{} //FIXME
	case 0x001c:
		if ext != nil {
			extV := *(ext.(*utls.FakeRecordSizeLimitExtension))
			return &extV
		}
		return &utls.FakeRecordSizeLimitExtension{} //Limit: 0x4001
	case 0xff01:
		if ext != nil {
			extV := *(ext.(*utls.RenegotiationInfoExtension))
			return &extV
		}
		return &utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient}
	default:
		return ext
	}
}

// type,0:是一个扩展，1：自定义扩展，2：无用扩展，3：未知扩展
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
		return 0x001c, 0
	case *utls.RenegotiationInfoExtension:
		return 0xff01, 0
	case *utls.GenericExtension:
		return ext.Id, 1
	case *utls.UtlsGREASEExtension:
		return 0, 2
	default:
		return 0, 3
	}
}
func isGREASEUint16(v uint16) bool {
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
func (obj Ja3Spec) IsSet() bool { //是否设置了
	if obj.CipherSuites != nil || obj.Extensions != nil || obj.CompressionMethods != nil ||
		obj.TLSVersMax != 0 || obj.TLSVersMin != 0 {
		return true
	}
	return false
}
func (obj Ja3Spec) HasPsk() bool { //是否存在psk
	for _, extension := range obj.Extensions {
		if _, ok := extension.(*utls.UtlsPreSharedKeyExtension); ok {
			return ok
		}
	}
	return false
}
func AddPsk(obj *Ja3Spec) { //添加psk
	obj.Extensions = append(obj.Extensions, &utls.UtlsPreSharedKeyExtension{})
}

func DelPsk(obj *Ja3Spec) { //删除psk
	extensions := []utls.TLSExtension{}
	for _, extension := range obj.Extensions {
		if _, ok := extension.(*utls.UtlsPreSharedKeyExtension); !ok {
			extensions = append(extensions, extension)
		}
	}
	obj.Extensions = extensions
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
	OrderHeaders   []string //伪标头顺序,例如：[]string{":method",":authority",":scheme",":path"}
	Priority       Priority
}

// 是否设置了
func (obj H2Ja3Spec) IsSet() bool {
	if obj.InitialSetting != nil || obj.ConnFlow != 0 || obj.OrderHeaders != nil || obj.Priority.IsSet() {
		return true
	}
	return false
}

// ja3 clientHelloId 生成 clientHello
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
		err = errors.New("ja3Str 字符串中tls 版本错误")
	}
	return
}
func createCiphers(ciphers []string) ([]uint16, error) {
	cipherSuites := []uint16{utls.GREASE_PLACEHOLDER}
	for _, val := range ciphers {
		if n, err := strconv.ParseUint(val, 10, 16); err != nil {
			return nil, errors.New("ja3Str 字符串中cipherSuites错误")
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
			return nil, errors.New("ja3Str 字符串中cipherSuites错误")
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
			return nil, errors.New("ja3Str 字符串中cipherSuites错误")
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
			return nil, errors.New("ja3Str 字符串中extension错误,utls不支持的扩展: " + extension)
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
			ext := getExtensionWithId(extensionId)
			if ext == nil {
				if isGREASEUint16(extensionId) {
					allExtensions = append(allExtensions, &utls.UtlsGREASEExtension{})
				}
				allExtensions = append(allExtensions, &utls.GenericExtension{Id: extensionId})
			} else {
				if ext == nil {
					return nil, errors.New("ja3Str 字符串中extension错误,utls不支持的扩展: " + extension)
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
		return clientHelloSpec, errors.New("ja3Str 字符串格式不正确")
	}
	ver, err := strconv.ParseUint(tokens[0], 10, 16)
	if err != nil {
		return clientHelloSpec, errors.New("ja3Str 字符串中tls 版本错误")
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

type ClientHello struct {
	ServerName        string
	SupportedProtos   []string      //列出客户端支持的应用协议。[h2 http/1.1]
	SupportedPoints   []uint8       //列出了客户端支持的点格式[0]
	SupportedCurves   []tls.CurveID //列出了客户端支持的椭圆曲线。 [CurveID(2570) X25519 CurveP256 CurveP384]
	SupportedVersions []uint16      //列出了客户端支持的TLS版本。[2570 772 771]

	CipherSuites     []uint16              //客户端支持的密码套件 [14906 4865 4866 4867 49195 49199 49196 49200 52393 52392 49171 49172 156 157 47 53]
	SignatureSchemes []tls.SignatureScheme //列出了客户端愿意验证的签名和散列方案[ECDSAWithP256AndSHA256 PSSWithSHA256 PKCS1WithSHA256 ECDSAWithP384AndSHA384 PSSWithSHA384 PKCS1WithSHA384 PSSWithSHA512 PKCS1WithSHA512]
}

var ja3Db = map[string]string{
	"41c1a0a0b7fea468f579fe3100c6d48a": "Firefox",
	"149e406721fa906e06d7f44589139e0e": "Firefox",
	"e92a163261a4777ba6ae540f587468ea": "Firefox",
	"ff5fb9c500cb93592dc619b21746d610": "Firefox",
	"88bd3cb92eb400fabc11d5c7ef336658": "Chrome",
	"43818547191c95092fd5c7145d07ca33": "Chrome",
	"4297e191aadbb83bcca9ad0a824c5d18": "Chrome",
	"ebcb348cdbaaf5e7a47b197bb9b1255f": "Chrome",
	"2a5649bb0a3c364491777ddf2678b396": "iOS",
	"2dcb3f02b926b086a068d10db1c5ea63": "iOS",
	"7e8d9723c8236b9e159d2310c574054f": "iOS",
	"0062ef304d078cdf567bbe32349fd446": "iOS",
	"811b5bb18faa39a6927a393b4a084249": "Android",
	"3a2220ccf3b251502c646249252d8fe5": "Safari",
	"e58713f1e65a280ce3bec3b85e6a3485": "360Browser",
}

func newClientHello(chi *tls.ClientHelloInfo) ClientHello {
	if chi.SupportedCurves[0] != tls.X25519 {
		chi.SupportedCurves = chi.SupportedCurves[1:]
	}
	if chi.SupportedVersions[0] != 772 {
		chi.SupportedVersions = chi.SupportedVersions[1:]
	}
	if chi.CipherSuites[0] != 4865 {
		chi.CipherSuites = chi.CipherSuites[1:]
	}
	var CipherSuites []uint16
	for _, CipherSuite := range chi.CipherSuites {
		if !slices.Contains(CipherSuites, CipherSuite) {
			CipherSuites = append(CipherSuites, CipherSuite)
		}
	}
	chi.CipherSuites = CipherSuites
	return ClientHello{
		ServerName:        chi.ServerName,
		CipherSuites:      chi.CipherSuites,
		SupportedCurves:   chi.SupportedCurves,
		SupportedPoints:   chi.SupportedPoints,
		SignatureSchemes:  chi.SignatureSchemes,
		SupportedProtos:   chi.SupportedProtos,
		SupportedVersions: chi.SupportedVersions,
	}
}

type Ja3ContextData struct {
	ClientHello ClientHello `json:"clientHello"`
	Init        bool        `json:"init"`
}

func (obj Ja3ContextData) Md5() string {
	var md5Str string
	for _, val := range obj.ClientHello.SupportedPoints {
		md5Str += fmt.Sprintf("%d", val)
	}
	for _, val := range obj.ClientHello.SupportedCurves {
		md5Str += val.String()
	}
	for _, val := range obj.ClientHello.SupportedVersions {
		md5Str += fmt.Sprintf("%d", val)
	}
	for _, val := range obj.ClientHello.CipherSuites {
		md5Str += fmt.Sprintf("%d", val)
	}
	for _, val := range obj.ClientHello.SignatureSchemes {
		md5Str += val.String()
	}
	return tools.Hex(tools.Md5(md5Str))
}

func VerifyWithMd5(md string) (string, bool) {
	ja3Name, ja3Ok := ja3Db[md]
	return ja3Name, ja3Ok
}
func (obj Ja3ContextData) Verify() (string, bool) {
	return VerifyWithMd5(obj.Md5())
}

type keyPrincipal string

const keyPrincipalID keyPrincipal = "Ja3ContextData"

func ConnContext(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, keyPrincipalID, &Ja3ContextData{})
}
func GetConfigForClient(chi *tls.ClientHelloInfo) (*tls.Config, error) {
	chi.Context().Value(keyPrincipalID).(*Ja3ContextData).ClientHello = newClientHello(chi)
	return nil, nil
}
func GetRequestJa3Data(r *http.Request) *Ja3ContextData {
	return r.Context().Value(keyPrincipalID).(*Ja3ContextData)
}
