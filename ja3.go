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

	"github.com/gospider007/http3"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/exp/slices"
)

func CreateSpecWithSpec(utlsSpec Spec, h2 bool, h3 bool) (Spec, error) {
	if h3 {
		for _, Extension := range utlsSpec.Extensions {
			alpns, ok := Extension.(*utls.ALPNExtension)
			if ok {
				alpns.AlpnProtocols = []string{http3.NextProtoH3}
				break
			}
		}
	} else if !h2 {
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
	return utlsSpec, nil
}
func NewClient(ctx context.Context, conn net.Conn, ja3Spec Spec, h2 bool, utlsConfig *utls.Config) (utlsConn *utls.UConn, err error) {
	utlsSpec, err := CreateSpecWithSpec(ja3Spec, h2, false)
	if err != nil {
		return nil, err
	}
	utlsConn = utls.UClient(conn, utlsConfig, utls.HelloCustom)
	uspec := utls.ClientHelloSpec(utlsSpec)
	if err = utlsConn.ApplyPreset(&uspec); err != nil {
		return nil, err
	}
	err = utlsConn.HandshakeContext(ctx)
	// log.Print(err)
	return utlsConn, err
}

// type,0: is ext, 1：custom ext，2：grease ext , 3：unknow ext
func getExtensionId(extension utls.TLSExtension) (utls.TLSExtension, uint16, uint8) {
	switch ext := extension.(type) {
	case *utls.SNIExtension:
		extClone := *ext
		return &extClone, 0, 0
	case *utls.StatusRequestExtension:
		extClone := *ext
		return &extClone, 5, 0
	case *utls.SupportedCurvesExtension:
		extClone := *ext
		return &extClone, 10, 0
	case *utls.SupportedPointsExtension:
		extClone := *ext
		return &extClone, 11, 0
	case *utls.SignatureAlgorithmsExtension:
		extClone := *ext
		return &extClone, 13, 0
	case *utls.ALPNExtension:
		extClone := *ext
		return &extClone, 16, 0
	case *utls.StatusRequestV2Extension:
		extClone := *ext
		return &extClone, 17, 0
	case *utls.SCTExtension:
		extClone := *ext
		return &extClone, 18, 0
	case *utls.UtlsPaddingExtension:
		extClone := *ext
		return &extClone, 21, 0
	case *utls.ExtendedMasterSecretExtension:
		extClone := *ext
		return &extClone, 23, 0
	case *utls.FakeTokenBindingExtension:
		extClone := *ext
		return &extClone, 24, 0
	case *utls.UtlsCompressCertExtension:
		extClone := *ext
		return &extClone, 27, 0
	case *utls.FakeRecordSizeLimitExtension:
		extClone := *ext
		return &extClone, 28, 0
	case *utls.FakeDelegatedCredentialsExtension:
		extClone := *ext
		return &extClone, 34, 0
	case *utls.SessionTicketExtension:
		extClone := *ext
		return &extClone, 35, 0
	case *utls.UtlsPreSharedKeyExtension:
		extClone := *ext
		return &extClone, 41, 0
	case *utls.SupportedVersionsExtension:
		extClone := *ext
		return &extClone, 43, 0
	case *utls.CookieExtension:
		extClone := *ext
		return &extClone, 44, 0
	case *utls.PSKKeyExchangeModesExtension:
		extClone := *ext
		return &extClone, 45, 0
	case *utls.SignatureAlgorithmsCertExtension:
		extClone := *ext
		return &extClone, 50, 0
	case *utls.KeyShareExtension:
		extClone := *ext
		return &extClone, 51, 0
	case *utls.QUICTransportParametersExtension:
		extClone := *ext
		return &extClone, 57, 0
	case *utls.NPNExtension:
		extClone := *ext
		return &extClone, 13172, 0
	case *utls.ApplicationSettingsExtension:
		extClone := *ext
		return &extClone, 17513, 0
	case *utls.FakeChannelIDExtension:
		if ext.OldExtensionID {
			extClone := *ext
			return &extClone, 30031, 0
		} else {
			extClone := *ext
			return &extClone, 30032, 0
		}
	case *utls.GREASEEncryptedClientHelloExtension:
		return ext, 65037, 0
	case *utls.RenegotiationInfoExtension:
		extClone := *ext
		return &extClone, 65281, 0
	case *utls.GenericExtension:
		extClone := *ext
		return &extClone, ext.Id, 1
	case *utls.UtlsGREASEExtension:
		extClone := *ext
		return &extClone, 0, 2
	default:
		return nil, 0, 3
	}
}

type Spec utls.ClientHelloSpec

func (obj Spec) String() string {
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
		_, extId, extType := getExtensionId(Extension)
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
func (obj Spec) IsSet() bool {
	return len(obj.Extensions) != 0
}

type Http2SettingID uint16

const (
	Http2SettingHeaderTableSize      Http2SettingID = 0x1
	Http2SettingEnablePush           Http2SettingID = 0x2
	Http2SettingMaxConcurrentStreams Http2SettingID = 0x3
	Http2SettingInitialWindowSize    Http2SettingID = 0x4
	Http2SettingMaxFrameSize         Http2SettingID = 0x5
	Http2SettingMaxHeaderListSize    Http2SettingID = 0x6
)

type Setting struct {
	// ID is which setting is being set.
	// See https://httpwg.org/specs/rfc7540.html#SettingFormat
	Id Http2SettingID
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

func DefaultSpec() Spec {
	return CreateSpecWithId(utls.HelloChrome_Auto)
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
func DefaultH2Spec() H2Spec {
	var h2Spec H2Spec
	h2Spec.InitialSetting = []Setting{
		{Id: 1, Val: 65536},
		{Id: 2, Val: 0},
		{Id: 3, Val: 1000},
		{Id: 4, Val: 6291456},
		{Id: 6, Val: 262144},
	}
	h2Spec.Priority = Priority{
		Exclusive: true,
		StreamDep: 0,
		Weight:    255,
	}
	h2Spec.OrderHeaders = DefaultOrderHeaders()
	h2Spec.ConnFlow = 15663105
	return h2Spec
}

type H2Spec struct {
	InitialSetting []Setting
	ConnFlow       uint32   //WINDOW_UPDATE:15663105
	OrderHeaders   []string //example：[]string{":method",":authority",":scheme",":path"}
	Priority       Priority
}

// have value
func (obj H2Spec) IsSet() bool {
	if obj.InitialSetting != nil || obj.ConnFlow != 0 || obj.OrderHeaders != nil || obj.Priority.IsSet() {
		return true
	}
	return false
}

func (obj H2Spec) Fp() string {
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

func CreateSpecWithId(ja3Id utls.ClientHelloID) Spec {
	spec, _ := utls.UTLSIdToSpec(ja3Id)
	spec.Extensions = clearExtensions(spec.Extensions)
	return Spec(spec)
}

// example："1:65536,2:0,4:6291456,6:262144|15663105|0|m,a,s,p"
func CreateH2SpecWithStr(h2ja3SpecStr string) (h2ja3Spec H2Spec, err error) {
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
			Id:  Http2SettingID(ttKey),
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

func CreateSpecWithClientHello(clienthello any) (clientHelloSpec Spec, err error) {
	var clientHelloInfo ClientHello
	switch value := clienthello.(type) {
	case []byte:
		clientHelloInfo, err = decodeClientHello(value)
		if err != nil {
			return clientHelloSpec, err
		}
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
	clientHelloSpec.CipherSuites = clientHelloInfo.CipherSuites
	clientHelloSpec.CompressionMethods = clientHelloInfo.CompressionMethods
	clientHelloSpec.Extensions = make([]utls.TLSExtension, len(clientHelloInfo.Extensions))
	for i, ext := range clientHelloInfo.Extensions {
		clientHelloSpec.Extensions[i] = ext.utlsExt()
	}
	clientHelloSpec.GetSessionID = sha256.Sum256
	return clientHelloSpec, nil
}
