package ja3

import (
	"crypto/sha256"
	"errors"

	"github.com/gospider007/tools"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/cryptobyte"
)

type TlsSpec struct {
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
func (obj *TlsSpec) Points() []uint8 {
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
func (obj *TlsSpec) Protocols() []string {
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
func (obj *TlsSpec) Versions() []uint16 {
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
func (obj *TlsSpec) Algorithms() []uint16 {
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
func (obj *TlsSpec) Curves() []uint16 {
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
func (obj *TlsSpec) ServerName() string {
	for _, ext := range obj.Extensions {
		if ext.Type == 0 {
			ex := new(utls.SNIExtension)
			ex.Write(ext.Data)
			return ex.ServerName
		}
	}
	return ""
}
func (obj *TlsSpec) utlsClientHelloSpec() utls.ClientHelloSpec {
	// fingerprinter := &utls.Fingerprinter{
	// 	AllowBluntMimicry: true,
	// 	RealPSKResumption: true,
	// 	AlwaysAddPadding:  true,
	// }
	// generatedSpec, _ := fingerprinter.FingerprintClientHello(obj.raw)
	// return *generatedSpec
	// spec, _ := utls.UTLSIdToSpec(utls.HelloChrome_131)
	// return spec
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
func (obj *TlsSpec) Bytes() []byte {
	return obj.raw
}
func (obj *TlsSpec) Hex() string {
	return tools.Hex(obj.Bytes())
}
func (obj *TlsSpec) Map() map[string]any {
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

func ParseTlsSpec(clienthello []byte) (clientHelloInfo *TlsSpec, err error) {
	clientHelloInfo = new(TlsSpec)
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

var FpCmd = `(()=>{
document.cookie = "key=value";
fetch("https://localhost:8999/", {
  "headers": {
    "A": "gospider_test_value",
    "B": "gospider_test_value",
    "C": "gospider_test_value",
    "D": "gospider_test_value",
    "E": "gospider_test_value",
	"F": "gospider_test_value",
    "G": "gospider_test_value",
    "H": "gospider_test_value",
    "I": "gospider_test_value",
    "J": "gospider_test_value",
    "K": "gospider_test_value",
    "L": "gospider_test_value",
    "M": "gospider_test_value",
    "N": "gospider_test_value",
    "O": "gospider_test_value",
    "P": "gospider_test_value",
	"Q": "gospider_test_value",
    "R": "gospider_test_value",
    "S": "gospider_test_value",
    "T": "gospider_test_value",
    "U": "gospider_test_value",
    "V": "gospider_test_value",
    "W": "gospider_test_value",
    "X": "gospider_test_value",
    "Y": "gospider_test_value",
    "Z": "gospider_test_value",
  },
  "referrer": "/",
  "method": "GET",
}).then(response => {return response.json()}).then(data => {console.log(data.goSpiderSpec)})
})()`

var Chrome_Mac_arm64_137 = ParseGospiderSpecNoError("160301076a0100076603037894337c7c858ccc35b93590111f3422fce8907d087e915fae826858e2aac44620ca937ca4249c8139781bbeee94e0c892b9c55619a5f32f6cb4dfd3132f03e57b00200a0a130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010006fd6a6a00000005000501000000000023000000170000ff0100010000120000003304ef04eddada00010011ec04c04a244ec5f5282871a6b1d20861e23845a3169da69c559bb6ca19029ba95233b2cdfcf4075a4793c1f3023a1b77a83118ef125ea18019d2a6c51570c09e27b0161c4b7b195e9d85958f0c67c0c4b144183784db59a0ca2129669dc52b11d5502a007a5184f83b83660cb5c57399d69a7c9b9474a7153da297d5d04856734791c63b18eaa861080847c1452c24555b3837f1287a8a4a94ed130188317fc279be2b80ce0277317588b76ed913c9cb28a44b3783ab6cf627cc569c26f6e080c3362f5fd7667651caaf669ad92744eef598c485c8a6b47cc33707a77c8176849fc96c113ba8b2ebd77f2f330208c80a5d508f1ab2bc165ba954c08d31949a5cc2cbcaa6427d4b38c263c5966a981871c541ec6d8af94617fc05d23b1a8e4b7f6321b885d89d4e507d5c0b123b8c9c826b0e43920d5637083d54c1c4abc07b3786ae059a9944c038583eede14b5c54c147012fe5695adc001da93c2622237fe755ce92d81516d77f5ac2195cac2b7d001477f6c452064c95507c8e831852c1be5f524b03341be3b759dc56b6bd99bdb1244d61a81988d25c9bdab3aed83d8994816646c76dc54943ab6f400522a651cecbcc780e409f99086f547b51ce86b0278782c5c184b9e7532770b4b37b2073e271540a38a8c3991ee4b180c14e2b80acb303576afa08e7a9ba88501f88e59c51d170fcb91cb33b3ba550422d38336071398e6479f38babd4c860f1f42fef120c7bb6a917c812fc6b144f3557c6976b1c8a794340b7a781903a077caf0549e95c634bf3220acb042fe61b94490cd542b38e4188957081be459683563b3527748156c2782540efa24993024d56ec10092a3fb53805265306887a32bcd38f4deb06b1063eee5b6c9914b83c78028a232b76847fa7cc2211c193fac055287c38a96a4cde5b1ce51c2119c31d404837a4a23f0f0c12559c9db65cb0baaacb70d2596547cd6ec572d598640ca203e15880a3d7a82b13cfc6461f68c596c2864abc9384bc28b09fd33185c5c968d483864667f130c3a8eb4264d64b6ec84325b23dca50042d15c8a7923a00d96aba905042a106d3b55d7dc8af9ba805bdd617f82b3b6bc3c418a9aa3dd6132ef60d68061a7a6258147b79e9c24fcb760c1eb28fbee9c6130ccdbd0817994053a588339df585f2bc2ae15c0a36bc0b43154f08fa86eef65258ec7956ec427bc3c794532fb46c449132c79e777f578a5f0b20a7b9827514a907a199c05ab1b024ccb661505060888678769b951924110c26d1e0aa55bb3444574510f8bc837561a21c67f06ca8f54a2b2cbbaefe25877a786715d70a2b94a4f6d20f0dfb6cc78a09b7247858f97d1a91bbb912b627157b548a084093128d801b86d027e039244fd63e3156354d505a211311253548e763c34cd938719341286815a7d630db678f40f3b76be35a3ac77214bbcd3d37c0557733e747374305c1b5e81600cb003716b947966a45f02a38780aec205b44c904c50779e6d97e07764259b7459996aa79617ef62ab471d4aec7a63e409c31a564025cb99ab26743dc373e0f97bf39acbbeda6131d535f4223bb35155aa46a228cf63f00909e0a805277a689e9f11697a19b6efa879bc41a6dab6475c2cf0c4b46a8a7ca6925f8190e9c467dd5883923d1ad9fc73eb27ad095110ca8c1ff633f10fe5d1689b76057714c84af32a221b27c4c922b7e280a13ccd94b001d00206246c9e77988e628cb5e14cd306fff38ca19fff73906cd81dae91adf32048b21001b0003020002000a000c000adada11ec001d00170018002d00020101000b0002010044cd00050003026832fe0d00da00000100011300200b680bd48685d196c906d728e3739dddbfae76f34c413b8873860a708bc27a2100b037e522271bcb52e651989aae0858ebe9950a1f460b7b6a89fccc40be3f7e1d5df375805cd6e3001ee7cbd029cecf848bf227fe6f2e383b739ade87f2d573a97e268a46cb1046a415b5095f12c83b7aa8690005e3407157aef9955798e24a1a0ea453bd0cbf913415cf0463dbbcbc65efcb72df1eae91ae6522adbfdd94cf4f558674e97d67a1dea7c81a346203b22d0a9018dc8eea044e8aa95bc8bd029779fd226aa56bc4ca51f770d4b9ae7b295bce0010000e000c02683208687474702f312e310000000e000c0000096c6f63616c686f7374002b000706dada03040303000d00120010040308040401050308050501080606015a5a00010000290094006f0069132346d60f25dcfb09d3a96f19d69d8f15bbd935e226d52e7b650c7d3bd1703208fe4cad7e911275c5b0faff16a5897da3ee267e0aa77590e8b2979a69abff8dca8cb66838496e9548a8bb6c579ae75ec85d9251561ee5fa368f334968e448cc564c56718d0dd8e74d89020cc10021206fadd0b4d7f9bc060fcc52e63b619bcc77917a50c98605964f1babfe3418c331@@505249202a20485454502f322e300d0a0d0a534d0d0a0d0a00001804000000000000010001000000020000000000040060000000060004000000000408000000000000ef000100000004010000000000034901250000000180000000db82418aa0e41d139d09b8f3efbf87844085aec1cd48ff86a8eb10649cbf5886a8eb10649cbf408d4148b1275ad1ad5d034ca7b29f07226d61634f532240016a8e98e8acd216c89254262ee3a2d2ff40016f8e98e8acd216c89254262ee3a2d2ff4001658e98e8acd216c89254262ee3a2d2ff4001648e98e8acd216c89254262ee3a2d2ff40016b8e98e8acd216c89254262ee3a2d2ff4001628e98e8acd216c89254262ee3a2d2ff40874148b1275ad1ffb8fe711cf350552f4f61e92ff3f7de0fe42cbbfcfd29fcde9ec3d26b69fe7efbc1fc85977f9fa53f9d274b10ff776c1d527f3f7de0fe44d7f34001708e98e8acd216c89254262ee3a2d2ff408b4148b1275ad1ad49e33505023f304001668e98e8acd216c89254262ee3a2d2ff4001768e98e8acd216c89254262ee3a2d2ff4001758e98e8acd216c89254262ee3a2d2ff40017a8e98e8acd216c89254262ee3a2d2ff4001778e98e8acd216c89254262ee3a2d2ff4001618e98e8acd216c89254262ee3a2d2ff4001718e98e8acd216c89254262ee3a2d2ff40016c8e98e8acd216c89254262ee3a2d2ff4001728e98e8acd216c89254262ee3a2d2ff4001738e98e8acd216c89254262ee3a2d2ff4001638e98e8acd216c89254262ee3a2d2ff4001788e98e8acd216c89254262ee3a2d2ff4001798e98e8acd216c89254262ee3a2d2ff4001698e98e8acd216c89254262ee3a2d2ff40016d8e98e8acd216c89254262ee3a2d2ff40016e8e98e8acd216c89254262ee3a2d2ff4001678e98e8acd216c89254262ee3a2d2ff7ad9d07f66a281b0dae053fad0321aa49d13fda992a49685340c8a6adca7e28104416e277fb521aeba0bc8b1e632586d975765c53facd8f7e8cff4a506ea5531149d4ffda97a7b0f49580b2eae05c0b814dc394761986d975765cf4001748e98e8acd216c89254262ee3a2d2ff4001688e98e8acd216c89254262ee3a2d2ff53032a2f2a408a4148b4a549275906497f8840e92ac7b0d31aaf408a4148b4a549275a93c85f8321ec47408a4148b4a549275a42a13f842d35a7d773919d29ad1718628390744e7426e3cfbefb1f50929bd9abfa5242cb40d25fa523b3e94f684c9f518cf73ad7b4fd7b9fefb4005dff6087ea5f50771d16974086aec31ec327d785b600fd286f")
var Firefox_Mac_arm64_140 = ParseGospiderSpecNoError("1603010895010008910303fabb285aa168a4e344a9b9ff32e7103b0b42753f43c2ebc9a030e52834e7da8420540f3791329a3e21650ec7c6f8dfef2a3577ec2b6e301be484b499c1f5dcb63a0022130113031302c02bc02fcca9cca8c02cc030c00ac009c013c014009c009d002f0035010008260000000e000c0000096c6f63616c686f737400170000ff01000100000a0010000e11ec001d00170018001901000101000b000201000010000e000c02683208687474702f312e310005000501000000000022000a00080403050306030203001200000033052f052d11ec04c09e676125a7932744befd3c1e6720485cbc11f72ac3cd498c19e035763bca6344bb50c12cd54466ce023c6844af0092bd72d36d226c263b0675a7415860f5084ce9b1b0249b2830abc778c32fc6aeee42963b693bd59bab11d095c451805c3cc6388779cf4a97ece27641d19def16a57ef57331b9210e0b60661a4af073445edb01216994b0c2be60b203aea67957ab09398998cf3b47c894bfea61ced5bcae0628281c171eaf11438b481d3e728315976440a5b7c1303c73f945acd67271828bb99394e609b309f0cecd73affe86a9c925212042bb9fb457fc213c63f58ee8fc16eaf79ebf33203e3cb73b8a8f2724a525d97abe34cb02154131f81317fb44766caf39fbc84d22b010bb0389124f1c70873bb0a89ee1601aba9b46f2540c2414600947de265ceee6acbe277d29d05010d50d0934b2bd985145537211f6681eb5362ca604dd2226be4b457f4c96dc5bb9366a230546b0386389b18469574b6697607f5ed3c4c91463fa49087ce403671148e32186c7741ff107b73c3813392c424a4b71fe915bb470cab3f7bccf1961116755809b1ce4cb0a29d04422f0c0fe1a0b04dc178f573558b255f803c9d8495005a738f6c73cc1b56d1599604a514d7c347315fc7866706f0513ccf7d98fdbc70f931cbf9ebba18d976953099e45cb5ea58b4f51d182e1c99961ec2ffc338ffa8996edfabd122c0ea04a1e7be310e0934620812c8d708d50fca53f2c3250c80accea4f8f560ff916026b652d2c28404d4688d5d4638ec819571104de14aaf5234ffb574ec9339ae0f06d78647ac393b012f38db812c8fe128af8e742e7336a9ffc49720aabc1840064ba5d82c846f2390580b751be440f1edb6a03920be6e03324c6bc37032e57c9ca5354adb555843ef6ab8ec46971156574033617a3aca86b72db94a6ec6c4ce1c60d5eb02142396808936727256001e5312bea0fecdaafc71c0f0912972312a71301b6d04598a853933ee6210478510c0790602c50996c0386b6aa13a61f19b52904605aaef53751e1053bb2cbc46310fd2462b736ac2aaa6a50422a42c0b3d5d8a0fd5194b4672e3e396737694b0bfc4e2707a80d050161e975a6537595c59c3725c63e3a2dc93c555d6090c6acbd2dec8be97910ceb17a65d13bd259317b128851d4b630aa1ac6f43b67f89078b5bc925911063089218487fe382527c1bf8d976903d497d369986a1c716c74093ab57af39b2613fb27ae06bb47046a3e7b911f1badde3a75c615052f940a2b912aa8015db854be23e91d27870b2019375b7441fdc3c8c97068883aa07593707cc49950c6911a006f9b36a8a6fbbbf34c07cc549e1db92b1b7011e7f07ab17740972c7b71a6a0dc8cc35f5128d4f86e1da20f3b428f859b8aad97962db4c025c567b25c6283e2180557988f0a28964021ac329920bc7b5da4b08e5911db8485f1f707fcab5d71ec1d1fe973f079a55ba43d0495769490ad7804c3364b690463ad7245ca2ec54a575a43f6ba1c680561c39069b80665b7d42635104d864749f3d05ce9b3b29460278c56756fb9a67e62397a4a2905b383319a25885b5e64e9569904027fc5b78402493ba233aa1856a0427b1fb980e6608fadd79c7d4343f34926de385072b385d1ee78080bdaa9a58751e5328d707482d03dc3368ba3de755b94ed24e60bb387f418b02c79e7db1c919e3ad2cf39b2971a556124001d00208ba3de755b94ed24e60bb387f418b02c79e7db1c919e3ad2cf39b2971a556124001700410423de197b380e908685e0048054c85acf08a9749e10bfcaff91d3f30a736a79b7f5a7bc0cc2d94de9700820fff338d4c6224ade58fb7cd2817e2c62038327a8f5002b00050403040303000d0018001604030503060308040805080604010501060102030201002d00020101001c00024001001b000706000100020003fe0d01b90000010003b400200f5568a7748fc404fae5996e68e29a984ff345847cb0bb320b8edd448217cbf5018f728215741f57ec050f8c1ce81112a6fde9b1de12bc78a71f21282693ed44bc9550f81e6e310d9563d73354f8572a03377b06952713364a8eca199c11db8e27cf79a5e8046a80b30eb3e3a4287915103ee42b62e93d5ff55977191138548b6d4a309d53a375ef374e3851836a86bdc7934c42a479564bbcefad48ac48ad18de3b82b097966c1f5b9433c5177231c0acc1daf8326730261805f4ff394ba78b233f076ac3994743ffdec09bab56e9d9431e366de7b1858d22eeef5ab7421a6da721c8a2dc7b8b97229e9fd5ac8f5000822363f9378ac9b355692723c50a9a7e17749c3ea592df3b7dcd8dbc61b4b7d0412098f6c89558cbb03a57cf81525323082ba048bbb818d130b24a61dcb629e1a0f523587a9538bafad077670953b82fcec52a692866b96220d4aad44bde56e9086cb63efd7f45c0daba6409d24567d33048d6fbd9dbf5fdb4543b4d8b6cc4552a01c1d7c2e32962974a40e103abef6e8c518133e748792519b035b82a61aef2f57cc75b9fc4edc1489ad9ba1f12a61679896d5898d9b12753bf4d3a446c4cc1d700290094006f00694bc41df38cca8adb15be2ef5d0729e4a354f5e399a6f3a1e6e03d135db68b449cdf4963097cd00d23481be13f54217871ccba0f1ab05e093d903b549e1d3d57a90bc321427b5e27a37bd6d3e3b13c42b14c1c6a383a7756252b7d75b939546bbd1420b695e35a7478c8d36f00c00212044fd8e5f62610c8db647eeaa32b68e4741cc9aa93fa0b727702d07872946981d@@505249202a20485454502f322e300d0a0d0a534d0d0a0d0a00001804000000000000010001000000020000000000040002000000050000400000000408000000000000bf00010002df012500000003000000001582048163418aa0e41d139d09b8f3efbf877abed07f66a281b0dae053fad0321aa49d13fda992a49685340c8a6adca7e28102e16fed4b3bdc0b405c1fda988a4ea76040080010054c26b0b29fcb01680b835383f963e751b0f73ad7b4fd7b9fefb4005defaf73adbf97df6800bbbf5ee75b1e6fbed00176fe8b52dc377df6800bb3f45abefb4005c550929bd9abfa5242cb40d25fa523b3e94f684c9f73919d29ad1718628390744e7426e3cfbefb1f40811f8e98e8acd216c89254262ee3a2d2ff40818f8e98e8acd216c89254262ee3a2d2ff4081278e98e8acd216c89254262ee3a2d2ff4081938e98e8acd216c89254262ee3a2d2ff40812f8e98e8acd216c89254262ee3a2d2ff4081978e98e8acd216c89254262ee3a2d2ff40819b8e98e8acd216c89254262ee3a2d2ff40819f8e98e8acd216c89254262ee3a2d2ff4081378e98e8acd216c89254262ee3a2d2ff4081e98e98e8acd216c89254262ee3a2d2ff4081eb8e98e8acd216c89254262ee3a2d2ff4081a38e98e8acd216c89254262ee3a2d2ff4081a78e98e8acd216c89254262ee3a2d2ff4081ab8e98e8acd216c89254262ee3a2d2ff40813f8e98e8acd216c89254262ee3a2d2ff4081af8e98e8acd216c89254262ee3a2d2ff4081ed8e98e8acd216c89254262ee3a2d2ff4081b38e98e8acd216c89254262ee3a2d2ff4081478e98e8acd216c89254262ee3a2d2ff40814f8e98e8acd216c89254262ee3a2d2ff4081b78e98e8acd216c89254262ee3a2d2ff4081ef8e98e8acd216c89254262ee3a2d2ff4081f18e98e8acd216c89254262ee3a2d2ff4081f38e98e8acd216c89254262ee3a2d2ff4081f58e98e8acd216c89254262ee3a2d2ff4081f78e98e8acd216c89254262ee3a2d2ff1f1187ea5f50771d1697408a4148b4a549275a42a13f842d35a7d7408a4148b4a549275a93c85f8321ec47408a4148b4a549275906497f8840e92ac7b0d31aaf4086aec31ec327d783b606bf4082497f864d833505b11f")
var Safari_Mac_arm64_18 = ParseGospiderSpecNoError("1603010200010001fc030328164c50c4f3c5e1370b5a5d93de8ec923dc9bf12294edd9cba2409413cfdda3201b47193e1616368cd43ad0391c3064a34b8a01b84d44312e132ec46cc77f8e9f002a2a2a130113021303c02cc02bcca9c030c02fcca8c00ac009c014c013009d009c0035002fc008c012000a010001893a3a00000000000e000c0000096c6f63616c686f737400170000ff01000100000a000c000a5a5a001d001700180019000b000201000010000e000c02683208687474702f312e31000500050100000000000d001600140403080404010503080508050501080606010201001200000033002b00295a5a000100001d002060cdc373e7d1278668cf1de66a08372bee38edd15b15b526c4a4d551dde0e632002d00020101002b000b0a9a9a0304030303020301001b00030200012a2a000100001500c700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000@@505249202a20485454502f322e300d0a0d0a534d0d0a0d0a000018040000000000000200000000000300000064000400200000000900000001000004080000000000009f00010002da0105000000018287418aa0e41d139d09b8f3efbf844001628e98e8acd216c89254262ee3a2d2ff40017a8e98e8acd216c89254262ee3a2d2ff4001638e98e8acd216c89254262ee3a2d2ff4001648e98e8acd216c89254262ee3a2d2ff53032a2f2a4001658e98e8acd216c89254262ee3a2d2ff4001668e98e8acd216c89254262ee3a2d2ff4001678e98e8acd216c89254262ee3a2d2ff7ad8d07f66a281b0dae053fad0321aa49d13fda992a49685340c8a6adca7e28104416e277fb521aeba0bc8b1e63258700dae15c2da9fd66c7bf467fa5283752a988a4ea7fed4e25b1063d4c05e5db5370e51d8661c036b8570b74001688e98e8acd216c89254262ee3a2d2ff408a4148b4a549275906497f8840e92ac7b0d31aaf4001698e98e8acd216c89254262ee3a2d2ff40016a8e98e8acd216c89254262ee3a2d2ff40016b8e98e8acd216c89254262ee3a2d2ff40016c8e98e8acd216c89254262ee3a2d2ff73919d29ad1718628390744e7426e3cfbefb1f40016d8e98e8acd216c89254262ee3a2d2ff40016e8e98e8acd216c89254262ee3a2d2ff40016f8e98e8acd216c89254262ee3a2d2ff4001708e98e8acd216c89254262ee3a2d2ff408a4148b4a549275a93c85f8321ec475886a8eb10649cbf4001718e98e8acd216c89254262ee3a2d2ff4001728e98e8acd216c89254262ee3a2d2ff4085aec1cd48ff86a8eb10649cbf4001738e98e8acd216c89254262ee3a2d2ff4001748e98e8acd216c89254262ee3a2d2ff4001758e98e8acd216c89254262ee3a2d2ff4001768e98e8acd216c89254262ee3a2d2ff408a4148b4a549275a42a13f842d35a7d74001778e98e8acd216c89254262ee3a2d2ff4001788e98e8acd216c89254262ee3a2d2ff4001618e98e8acd216c89254262ee3a2d2ff4001798e98e8acd216c89254262ee3a2d2ff5190f73ad7b4fd7b9d6c63a91f7da002efff4086aec31ec327d785b6067e9437508d9bd9abfa5242cb40d25fa523b31f1187ea5f50771d1697")
