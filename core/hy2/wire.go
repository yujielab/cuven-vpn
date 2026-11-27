package hy2

import (
	"encoding/binary"
	"errors"
	"io"
	"slices"

	"github.com/quic-go/quic-go/quicvarint"
)

const (
	tcpRequestType   = 0x401
	maxAddressLength = 2048
	maxMessageLength = 2048
	maxPaddingLength = 4096
	maxUDPPayload    = 65527 // Maximum payload in an IPv6 UDP packet without a jumbogram.
	udpPrefixSize    = 8
)

var errInvalidDatagram = errors.New("invalid Hysteria UDP datagram")

func encodeTCPRequest(address string) []byte {
	padding := randomPadding(64, 512)
	request := make([]byte, 0, 10+len(address)+len(padding))
	request = quicvarint.Append(request, tcpRequestType)
	request = quicvarint.Append(request, uint64(len(address)))
	request = append(request, address...)
	request = quicvarint.Append(request, uint64(len(padding)))
	return append(request, padding...)
}

func readTCPResponse(stream io.Reader) error {
	reader := quicvarint.NewReader(stream)
	status, err := reader.ReadByte()
	if err != nil {
		return err
	}
	if err := skipField(stream, reader, maxMessageLength); err != nil {
		return err
	}
	if err := skipField(stream, reader, maxPaddingLength); err != nil {
		return err
	}
	if status != 0 {
		return errors.New("Hysteria server rejected the TCP destination")
	}
	return nil
}

// quicvarint.Reader does not buffer, so reading from the underlying stream
// consumes exactly the specified bytes without touching the proxy payload.
func skipField(stream io.Reader, reader io.ByteReader, maximum uint64) error {
	length, err := quicvarint.Read(reader)
	if err != nil {
		return err
	}
	if length > maximum {
		return errors.New("invalid Hysteria TCP response length")
	}
	_, err = io.CopyN(io.Discard, stream, int64(length))
	return err
}

type udpMessage struct {
	sessionID     uint32
	packetID      uint16
	fragmentIndex uint8
	fragmentCount uint8
	address       string
	payload       []byte
}

func (m udpMessage) headerSize() int {
	return udpPrefixSize + int(quicvarint.Len(uint64(len(m.address)))) + len(m.address)
}

func (m udpMessage) encode(dst []byte) []byte {
	buf := slices.Grow(dst[:0], m.headerSize()+len(m.payload))[:udpPrefixSize]
	binary.BigEndian.PutUint32(buf, m.sessionID)
	binary.BigEndian.PutUint16(buf[4:], m.packetID)
	buf[6] = m.fragmentIndex
	buf[7] = m.fragmentCount
	buf = quicvarint.Append(buf, uint64(len(m.address)))
	buf = append(buf, m.address...)
	return append(buf, m.payload...)
}

func decodeUDP(datagram []byte) (udpMessage, error) {
	if len(datagram) <= udpPrefixSize || datagram[7] == 0 ||
		(datagram[7] > 1 && datagram[6] >= datagram[7]) {
		return udpMessage{}, errInvalidDatagram
	}
	length, width, err := quicvarint.Parse(datagram[udpPrefixSize:])
	if err != nil || length == 0 || length > maxAddressLength ||
		length > uint64(len(datagram)-udpPrefixSize-width) {
		return udpMessage{}, errInvalidDatagram
	}
	addressStart := udpPrefixSize + width
	payloadStart := addressStart + int(length)
	if len(datagram)-payloadStart > maxUDPPayload {
		return udpMessage{}, errInvalidDatagram
	}
	return udpMessage{
		sessionID:     binary.BigEndian.Uint32(datagram),
		packetID:      binary.BigEndian.Uint16(datagram[4:]),
		fragmentIndex: datagram[6],
		fragmentCount: datagram[7],
		address:       string(datagram[addressStart:payloadStart]),
		payload:       datagram[payloadStart:],
	}, nil
}
