package ja3

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/gospider007/tools"
)

func (obj *H1Spec) Map() map[string]any {
	results := map[string]any{
		"orderHeaders": obj.OrderHeaders,
		"raw":          obj.String(),
	}
	return results
}
func (obj *H1Spec) Hex() string {
	return tools.Hex(obj.raw)
}
func (obj *H1Spec) Bytes() []byte {
	return obj.raw
}
func (obj *H1Spec) String() string {
	return tools.BytesToString(obj.raw)
}

type H1Spec struct {
	OrderHeaders [][2]string
	raw          []byte
}

func ParseH1Spec(raw []byte) (*H1Spec, error) {
	i := bytes.Index(raw, []byte("\r\n\r\n"))
	if i == -1 {
		return nil, errors.New("not found \\r\\n")
	}
	rawContent := raw[:i]
	orderHeaders := [][2]string{}
	for i, line := range bytes.Split(rawContent, []byte("\r\n")) {
		if i == 0 {
			continue
		}
		ols := bytes.Split(line, []byte(": "))
		if len(ols) < 2 {
			return nil, errors.New("not found header")
		}
		orderHeaders = append(orderHeaders, [2]string{
			tools.BytesToString(ols[0]),
			tools.BytesToString(bytes.Join(ols[1:], []byte(": "))),
		})
	}
	return &H1Spec{
		raw:          raw,
		OrderHeaders: orderHeaders,
	}, nil
}

type GospiderSpec struct {
	TLSSpec *TlsSpec
	H1Spec  *H1Spec
	H2Spec  *H2Spec
}

func (obj *GospiderSpec) Clone() *GospiderSpec {
	spec := new(GospiderSpec)
	if obj.TLSSpec != nil {
		spec.TLSSpec, _ = ParseTlsSpec(obj.TLSSpec.raw)
	}
	if obj.H1Spec != nil {
		spec.H1Spec, _ = ParseH1Spec(obj.H1Spec.raw)
	}
	if obj.H2Spec != nil {
		spec.H2Spec, _ = ParseH2Spec(obj.H2Spec.raw)
	}
	return spec
}
func ParseGospiderSpec(value string) (*GospiderSpec, error) {
	specs := strings.Split(value, "@")
	spec := new(GospiderSpec)
	if len(specs) != 3 {
		return nil, errors.New("spec format error")
	}
	if specs[0] != "" {
		b, err := hex.DecodeString(specs[0])
		if err != nil {
			return nil, err
		}
		if spec.TLSSpec, err = ParseTlsSpec(b); err != nil {
			return nil, err
		}
	}
	if specs[1] != "" {
		b, err := hex.DecodeString(specs[1])
		if err != nil {
			return nil, err
		}
		if spec.H1Spec, err = ParseH1Spec(b); err != nil {
			return nil, err
		}
	}
	if specs[2] != "" {
		b, err := hex.DecodeString(specs[2])
		if err != nil {
			return nil, err
		}
		if spec.H2Spec, err = ParseH2Spec(b); err != nil {
			return nil, err
		}
	}
	return spec, nil
}
func ParseGospiderSpecNoError(value string) *GospiderSpec {
	spec, err := ParseGospiderSpec(value)
	if err != nil {
		panic(err)
	}
	return spec
}
