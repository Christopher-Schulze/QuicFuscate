package main

import (
	"github.com/QuicSand/QuicSand/fec"
)

// fecEncoder encodes data using RaptorQ FEC
type fecEncoder struct {
	encoder *fec.RaptorQEncoder
}

// newFECEncoder creates a new FEC encoder
func newFECEncoder() (*fecEncoder, error) {
	encoder, err := fec.NewRaptorQEncoder(fec.DefaultConfig())
	if err != nil {
		return nil, err
	}
	return &fecEncoder{encoder: encoder}, nil
}

// encode encodes data using RaptorQ FEC
func (e *fecEncoder) encode(data []byte) ([]byte, error) {
	encoded, err := e.encoder.Encode(data)
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

// fecDecoder decodes data using RaptorQ FEC
type fecDecoder struct {
	decoder *fec.RaptorQDecoder
}

// newFECDecoder creates a new FEC decoder
func newFECDecoder() (*fecDecoder, error) {
	decoder, err := fec.NewRaptorQDecoder(fec.DefaultConfig())
	if err != nil {
		return nil, err
	}
	return &fecDecoder{decoder: decoder}, nil
}

// decode decodes data using RaptorQ FEC
func (d *fecDecoder) decode(encoded []byte) ([]byte, error) {
	decoded, err := d.decoder.Decode(encoded)
	if err != nil {
		return nil, err
	}
	return decoded, nil
}
