package main

import (
	"github.com/lajosbencz/gos"
	"github.com/xtaci/tetrys"
)

// FEC-Interface für verschiedene FEC-Codecs
type FEC interface {
	Encode(data []byte) []byte
	Decode(data []byte) []byte
}

// RaptorQEncoder implementiert FEC mit RaptorQ
type RaptorQEncoder struct {
	*gos.Encoder
}

// NewRaptorQEncoder erstellt einen neuen RaptorQ-Encoder
func NewRaptorQEncoder(redundancy float32) *RaptorQEncoder {
	return &RaptorQEncoder{
		Encoder: gos.NewEncoder(redundancy),
	}
}

// TetrysEncoder implementiert FEC mit Tetrys
type TetrysEncoder struct {
	*tetrys.Encoder
}

// NewTetrysEncoder erstellt einen neuen Tetrys-Encoder
func NewTetrysEncoder(redundancy float32) *TetrysEncoder {
	return &TetrysEncoder{
		Encoder: tetrys.NewEncoder(redundancy),
	}
}
