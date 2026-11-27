package cuventransport

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

const (
	ConnectUDPPath         = "/.well-known/masque/udp/cuven/51821/"
	ConnectUDPProtocol     = "connect-udp"
	ConnectUDPCapsuleValue = "?1"
	datagramCapsule        = http3.CapsuleType(0)
)

// DatagramWriter is the writable part of an HTTP/3 request stream.
type DatagramWriter interface {
	SendDatagram([]byte) error
	TryWriteAll([]byte) error
}

// HTTPS3Authorization returns the CONNECT-UDP bearer value for one TLS session.
// The relay key itself is never sent in HTTP headers.
func HTTPS3Authorization(key []byte, state tls.ConnectionState) (string, error) {
	if err := validateKey(key); err != nil {
		return "", err
	}
	material, err := exportHTTPS3Key(state, "EXPORTER-Cuven-HTTP3-Authorization", nil)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(material)
	return "Bearer " + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// NewHTTPS3Codec binds the relay key to one CONNECT-UDP request so its v2
// envelopes cannot be reused on another stream or on the raw UDP relay.
func NewHTTPS3Codec(key []byte, state tls.ConnectionState, streamID quic.StreamID) (*Codec, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}
	var stream [8]byte
	binary.BigEndian.PutUint64(stream[:], uint64(streamID))
	material, err := exportHTTPS3Key(state, "EXPORTER-Cuven-HTTP3-WireGuard", stream[:])
	if err != nil {
		return nil, err
	}
	derived, err := hkdf.Key(sha256.New, key, material, "cuven/wireguard-envelope/https3", KeySize)
	if err != nil {
		return nil, err
	}
	return NewCodecVersion(derived, Version2)
}

func exportHTTPS3Key(state tls.ConnectionState, label string, context []byte) ([]byte, error) {
	if !state.HandshakeComplete || state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != http3.NextProtoH3 {
		return nil, errors.New("Cuven CONNECT-UDP requires an authenticated HTTP/3 TLS session")
	}
	return state.ExportKeyingMaterial(label, context, KeySize)
}

// SendConnectUDP sends a context-zero HTTP Datagram. If path MTU is too small,
// it uses a DATAGRAM capsule on the same request stream. Calls on one stream
// must be serialized so writes to the capsule stream cannot interleave.
func SendConnectUDP(stream DatagramWriter, envelope []byte) error {
	if len(envelope) == 0 || len(envelope) > MaxDatagramSize {
		return errFrame
	}
	const capsuleHeaderSize = 3 // One-byte type and at most two bytes for length.
	var datagram [capsuleHeaderSize + 1 + MaxDatagramSize]byte
	data := datagram[capsuleHeaderSize : capsuleHeaderSize+1+copy(datagram[capsuleHeaderSize+1:], envelope)]
	err := stream.SendDatagram(data)
	var tooLarge *quic.DatagramTooLargeError
	if !errors.As(err, &tooLarge) {
		return err
	}
	capsule := quicvarint.Append(datagram[:0], uint64(datagramCapsule))
	capsule = quicvarint.Append(capsule, uint64(len(data)))
	capsule = append(capsule, data...)
	if err := stream.TryWriteAll(capsule); !errors.Is(err, quic.ErrWouldBlock) {
		return err
	}
	return nil // Preserve best-effort UDP semantics under flow-control pressure.
}

func ParseConnectUDPDatagram(data []byte) ([]byte, bool) {
	contextID, prefix, err := quicvarint.Parse(data)
	if err != nil || contextID != 0 || len(data) == prefix || len(data)-prefix > MaxDatagramSize {
		return nil, false
	}
	return data[prefix:], true
}

// ReadConnectUDPCapsule reads the next context-zero DATAGRAM capsule into scratch.
// The scratch buffer must be at least MaxDatagramSize bytes long.
func ReadConnectUDPCapsule(parser *http3.CapsuleParser, scratch []byte) ([]byte, error) {
	for {
		kind, payload, err := parser.Next()
		if err != nil {
			return nil, err
		}
		if payload.Remaining() > MaxDatagramSize+8 {
			return nil, errFrame
		}
		if kind == datagramCapsule {
			id, err := quicvarint.Read(payload)
			if err != nil {
				return nil, err
			}
			if id == 0 {
				length := int(payload.Remaining())
				if length == 0 || length > MaxDatagramSize || length > len(scratch) {
					return nil, errFrame
				}
				_, err := io.ReadFull(payload, scratch[:length])
				return scratch[:length], err
			}
		}
		if err := payload.Discard(); err != nil {
			return nil, err
		}
	}
}
