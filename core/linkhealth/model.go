// Package linkhealth evaluates aggregate measurements from a Cuven connection.
package linkhealth

import (
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
)

const width = 6

// Model is a small, versioned feed-forward network for link health diagnostics.
type Model struct {
	Version int                `json:"version"`
	Hidden  [width][4]float64  `json:"hidden"`
	Output  [width + 1]float64 `json:"output"`
}

func Load(path string) (*Model, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	decoder := json.NewDecoder(io.LimitReader(f, 8193))
	decoder.DisallowUnknownFields()
	var model Model
	if err := decoder.Decode(&model); err != nil {
		return nil, err
	}
	if model.Version != 1 {
		return nil, errors.New("unsupported Cuven link health model version")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("trailing data in Cuven link health model")
	}
	return &model, nil
}

// Score uses actual RTT and variation in milliseconds and a bounded loss ratio.
// Decisions about authentication and IP filtering are independent of the score.
func (m *Model) Score(rtt, minimum, variation, loss float64) float64 {
	base := max(minimum, 1)
	input := [4]float64{
		min(max(rtt/base-1, 0), 8) / 8,
		min(max(variation/base, 0), 8) / 8,
		min(max(loss, 0), 1),
		1,
	}
	logit := m.Output[width]
	for j, weights := range m.Hidden {
		var value float64
		for k, weight := range weights {
			value += weight * input[k]
		}
		logit += m.Output[j] * math.Tanh(value)
	}
	return 1 / (1 + math.Exp(-logit))
}
