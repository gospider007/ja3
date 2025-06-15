package ja3

import (
	"crypto/sha256"
	"errors"

	"github.com/gospider007/tools"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/cryptobyte"
)

type Spec struct {
	raw                []byte
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

func createExtension(extensionId uint16, data []byte) utls.TLSExtension {
	switch extensionId {
	case 0:
		return new(utls.SNIExtension)
	case 5:
		return new(utls.StatusRequestExtension)
	case 17:
		return new(utls.StatusRequestV2Extension)
	case 18:
		return new(utls.SCTExtension)
	case 23:
		return new(utls.ExtendedMasterSecretExtension)
	case 35:
		return new(utls.SessionTicketExtension)
	case 41:
		return new(utls.UtlsPreSharedKeyExtension)
	case 44:
		return new(utls.CookieExtension)
	case 57:
		return new(utls.QUICTransportParametersExtension)
	case 30031:
		extV := new(utls.FakeChannelIDExtension)
		extV.OldExtensionID = true
		return extV
	case 30032:
		extV := new(utls.FakeChannelIDExtension)
		return extV
	case 65037:
		return utls.BoringGREASEECH()
	default:
		ext := utls.ExtensionFromID(extensionId)
		if ext == nil {
			return &utls.GenericExtension{
				Id:   extensionId,
				Data: data,
			}
		}
		extWriter, ok := ext.(utls.TLSExtensionWriter)
		if ok {
			extWriter.Write(data)
			return ext
		}
		return &utls.GenericExtension{
			Id:   extensionId,
			Data: data,
		}
	}
}

func (obj Extension) utlsExt() utls.TLSExtension {
	return createExtension(obj.Type, obj.Data)
}

// type:  11 : utls.SupportedPointsExtension
func (obj *Spec) Points() []uint8 {
	for _, ext := range obj.Extensions {
		if ext.Type == 11 {
			ex := new(utls.SupportedPointsExtension)
			ex.Write(ext.Data)
			return ex.SupportedPoints
		}
	}
	return nil
}

// type:  16 : utls.ALPNExtension
func (obj *Spec) Protocols() []string {
	for _, ext := range obj.Extensions {
		if ext.Type == 16 {
			ex := new(utls.ALPNExtension)
			ex.Write(ext.Data)
			return ex.AlpnProtocols
		}
	}
	return nil
}

// type:  43 : utls.SupportedVersionsExtension
func (obj *Spec) Versions() []uint16 {
	for _, ext := range obj.Extensions {
		if ext.Type == 43 {
			ex := new(utls.SupportedVersionsExtension)
			ex.Write(ext.Data)
			return ex.Versions
		}
	}
	return nil
}

// type:  13 : utls.SignatureAlgorithmsExtension
func (obj *Spec) Algorithms() []uint16 {
	for _, ext := range obj.Extensions {
		if ext.Type == 13 {
			ex := new(utls.SignatureAlgorithmsExtension)
			ex.Write(ext.Data)
			algorithms := make([]uint16, len(ex.SupportedSignatureAlgorithms))
			for i, algorithm := range ex.SupportedSignatureAlgorithms {
				algorithms[i] = uint16(algorithm)
			}
			return algorithms
		}
	}
	return nil
}

// type:  10 : utls.SupportedCurvesExtension
func (obj *Spec) Curves() []uint16 {
	for _, ext := range obj.Extensions {
		if ext.Type == 10 {
			ex := new(utls.SupportedCurvesExtension)
			ex.Write(ext.Data)
			algorithms := make([]uint16, len(ex.Curves))
			for i, algorithm := range ex.Curves {
				algorithms[i] = uint16(algorithm)
			}
			return algorithms
		}
	}
	return nil
}
func (obj *Spec) ServerName() string {
	for _, ext := range obj.Extensions {
		if ext.Type == 0 {
			ex := new(utls.SNIExtension)
			ex.Write(ext.Data)
			return ex.ServerName
		}
	}
	return ""
}
func (obj *Spec) utlsClientHelloSpec() utls.ClientHelloSpec {
	// fingerprinter := &utls.Fingerprinter{
	// 	// AllowBluntMimicry: true,
	// 	// RealPSKResumption: true,
	// 	// AlwaysAddPadding:  true,
	// }
	// generatedSpec, _ := fingerprinter.FingerprintClientHello(obj.raw)
	// return *generatedSpec
	var clientHelloSpec utls.ClientHelloSpec
	clientHelloSpec.CipherSuites = obj.CipherSuites
	clientHelloSpec.CompressionMethods = obj.CompressionMethods
	clientHelloSpec.Extensions = make([]utls.TLSExtension, len(obj.Extensions))
	for i, ext := range obj.Extensions {
		clientHelloSpec.Extensions[i] = ext.utlsExt()
	}
	clientHelloSpec.GetSessionID = sha256.Sum256
	return clientHelloSpec
}
func (obj *Spec) Bytes() []byte {
	return obj.raw
}
func (obj *Spec) Hex() string {
	return tools.Hex(obj.Bytes())
}
func (obj *Spec) Map() map[string]any {
	extensions := make([]map[string]any, len(obj.Extensions))
	for i, ext := range obj.Extensions {
		extensions[i] = map[string]any{
			"type": ext.Type,
			"data": tools.Hex(ext.Data),
		}
	}
	results := map[string]any{
		"points":         obj.Points(),
		"protocols":      obj.Protocols(),
		"versions":       obj.Versions(),
		"algorithms":     obj.Algorithms(),
		"curves":         obj.Curves(),
		"serverName":     obj.ServerName(),
		"contentType":    obj.ContentType,
		"messageVersion": obj.MessageVersion,

		"handshakeVersion":   obj.HandshakeVersion,
		"handShakeType":      obj.HandShakeType,
		"randomTime":         obj.RandomTime,
		"randomBytes":        obj.RandomBytes,
		"sessionId":          obj.SessionId,
		"cipherSuites":       obj.CipherSuites,
		"compressionMethods": obj.CompressionMethods,
		"extensions":         extensions,
	}
	return results
}

func ParseSpec(clienthello []byte) (clientHelloInfo *Spec, err error) {
	clientHelloInfo = new(Spec)
	clientHelloInfo.raw = clienthello
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
