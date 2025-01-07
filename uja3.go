package ja3

import (
	uquic "github.com/refraction-networking/uquic"
)

var (
	QUICFirefox_116  = uquic.QUICFirefox_116A
	QUICFirefox_116A = uquic.QUICFirefox_116A
	QUICFirefox_116B = uquic.QUICFirefox_116B
	QUICFirefox_116C = uquic.QUICFirefox_116C

	QUICChrome_115      = uquic.QUICChrome_115
	QUICChrome_115_IPv4 = uquic.QUICChrome_115_IPv4
	QUICChrome_115_IPv6 = uquic.QUICChrome_115_IPv6
)

type QUICID = uquic.QUICID
type USpec struct {
	InitialPacketSpec  uquic.InitialPacketSpec
	ClientHelloSpec    Spec
	UDPDatagramMinSize int
}

func DefaultUSpec() USpec {
	return CreateUSpecWithId(QUICChrome_115)
}
func (obj USpec) IsSet() bool {
	return obj.UDPDatagramMinSize != 0 || obj.ClientHelloSpec.IsSet()
}

func CreateUSpecWithId(uja3Id QUICID) USpec {
	spec, _ := uquic.QUICID2Spec(uja3Id)
	return USpec{
		InitialPacketSpec:  spec.InitialPacketSpec,
		ClientHelloSpec:    Spec(*spec.ClientHelloSpec),
		UDPDatagramMinSize: spec.UDPDatagramMinSize,
	}
}

func CreateSpecWithUSpec(spec USpec) (uquic.QUICSpec, error) {
	utlsSpec, err := CreateSpecWithSpec(spec.ClientHelloSpec, false, true)
	if err != nil {
		return uquic.QUICSpec{}, err
	}
	return uquic.QUICSpec{
		ClientHelloSpec:    &utlsSpec,
		UDPDatagramMinSize: spec.UDPDatagramMinSize,
		InitialPacketSpec:  spec.InitialPacketSpec,
	}, nil
}
