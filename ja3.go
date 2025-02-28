package ja3

import (
	"context"
	"net"
	"strconv"
	"sync"

	"github.com/gospider007/kinds"
	"github.com/gospider007/re"
	utls "github.com/refraction-networking/utls"
)

type specErr struct {
	KeyShareExtension *kinds.Set[uint16]
}
type Client struct {
	specErrData sync.Map
}

func NewClient() *Client {
	return &Client{}
}
func (obj *Client) setSpecErrWithKeyShareExtension(key string, value uint16) (change bool) {
	errData, ok := obj.specErrData.Load(key)
	if ok {
		specErr := errData.(*specErr)
		if !specErr.KeyShareExtension.Has(value) {
			change = true
			specErr.KeyShareExtension.Add(value)
		}
	} else {
		change = true
		obj.specErrData.Store(key, &specErr{KeyShareExtension: kinds.NewSet(value)})
	}
	return
}
func (obj *Client) setSpecErrWithError(key string, err error) (change bool) {
	keyShareExtensionRs := re.Search(`unsupported Curve in KeyShareExtension: CurveID\((\d+)\)`, err.Error())
	if keyShareExtensionRs != nil {
		i, err := strconv.Atoi(keyShareExtensionRs.Group(1))
		if err == nil {
			if obj.setSpecErrWithKeyShareExtension(key, uint16(i)) {
				change = true
			}
		}
	}
	return
}
func (obj *Client) changeSpec(key string, spec utls.ClientHelloSpec) (change bool) {
	errData, ok := obj.specErrData.Load(key)
	if !ok {
		return
	}
	specErr := errData.(*specErr)
	for _, ext := range spec.Extensions {
		switch extData := ext.(type) {
		case *utls.KeyShareExtension:
			if specErr.KeyShareExtension.Len() > 0 {
				keyShares := []utls.KeyShare{}
				for _, keyShare := range extData.KeyShares {
					if !specErr.KeyShareExtension.Has(uint16(keyShare.Group)) {
						change = true
						keyShares = append(keyShares, keyShare)
					}
				}
				extData.KeyShares = keyShares
			}
		case *utls.SupportedCurvesExtension:
			if specErr.KeyShareExtension.Len() > 0 {
				keyShares := []utls.CurveID{}
				for _, keyShare := range extData.Curves {
					if !specErr.KeyShareExtension.Has(uint16(keyShare)) {
						change = true
						keyShares = append(keyShares, keyShare)
					}
				}
				extData.Curves = keyShares
			}
		}
	}
	return
}

func (obj *Client) Client(ctx context.Context, conn net.Conn, spec *Spec, utlsConfig *utls.Config, serverName string, forceHttp1 bool) (utlsConn *utls.UConn, err error) {
	utlsSpec := spec.utlsClientHelloSpec()
	if forceHttp1 {
		utlsConfig.NextProtos = []string{"http/1.1"}
		for _, Extension := range utlsSpec.Extensions {
			alpns, ok := Extension.(*utls.ALPNExtension)
			if ok {
				alpns.AlpnProtocols = []string{"http/1.1"}
				break
			}
		}
	} else {
		utlsConfig.NextProtos = []string{"h2", "http/1.1"}
	}
	utlsConfig.ServerName = serverName
	obj.changeSpec(serverName, utlsSpec)
	utlsConn = utls.UClient(conn, utlsConfig, utls.HelloCustom)
	uspec := utls.ClientHelloSpec(utlsSpec)
	for {
		err = utlsConn.ApplyPreset(&uspec)
		if err == nil {
			break
		}
		if !obj.setSpecErrWithError(serverName, err) {
			return nil, err
		}
		if !obj.changeSpec(serverName, utlsSpec) {
			return nil, err
		}
	}
	err = utlsConn.HandshakeContext(ctx)
	return utlsConn, err
}
