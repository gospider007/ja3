package ja3

import (
	uquic "github.com/refraction-networking/uquic"
)

func DefaultUSpec() uquic.QUICSpec {
	spec, _ := uquic.QUICID2Spec(uquic.QUICChrome_115)
	return spec
}
