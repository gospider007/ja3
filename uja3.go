package ja3

import (
	uquic "github.com/refraction-networking/uquic"
	utls "github.com/refraction-networking/utls"
)

type USpec uquic.QUICSpec

func DefaultUSpec() USpec {
	return CreateUSpecWithId(uquic.QUICChrome_115)
}
func (obj USpec) IsSet() bool {
	return obj.ClientHelloSpec != nil
}
func clearExtensions(extensions []utls.TLSExtension) []utls.TLSExtension {
	for i, extextension := range extensions {
		ext, _, extType := getExtensionId(extextension)
		if extType == 3 {
			extensions[i] = extextension
		} else {
			extensions[i] = ext
		}
	}
	return extensions
}

func CreateUSpecWithId(uja3Id uquic.QUICID) USpec {
	spec, _ := uquic.QUICID2Spec(uja3Id)
	spec.ClientHelloSpec.Extensions = clearExtensions(spec.ClientHelloSpec.Extensions)
	return USpec(spec)
}
