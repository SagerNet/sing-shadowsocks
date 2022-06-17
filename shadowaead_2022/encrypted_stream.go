package shadowaead_2022

import (
	"encoding/binary"
	"io"

	"github.com/sagernet/sing-shadowsocks/shadowaead"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
)

const (
	recordTypeHandshake       = 22
	recordTypeApplicationData = 23

	tlsVersion10 = 0x0301
	tlsVersion11 = 0x0302
	tlsVersion12 = 0x0303
	tlsVersion13 = 0x0304

	tlsEncryptedLengthChunkLength = 5 + shadowaead.Overhead
)

func isTLSHandshake(payload []byte) bool {
	if len(payload) < 5 {
		return false
	}
	if payload[0] != recordTypeHandshake {
		return false
	}
	tlsVersion := binary.BigEndian.Uint16(payload[1:])
	if tlsVersion != tlsVersion10 && tlsVersion != tlsVersion12 {
		return false
	}
	return true
}

func readTLSChunkEnd(payload []byte) int {
	pLen := len(payload)
	index := 0
	for index < pLen {
		if pLen-index < 5 {
			break
		}
		dataLen := binary.BigEndian.Uint16(payload[index+3 : index+5])
		nextIndex := index + 5 + int(dataLen)
		if nextIndex > pLen {
			return index
		}
		index = nextIndex
	}
	return index
}

type TLSEncryptedStreamReader struct {
	upstream *shadowaead.Reader
	raw      io.Reader
	buffer   *buf.Buffer
}

func NewTLSEncryptedStreamReader(upstream *shadowaead.Reader) *TLSEncryptedStreamReader {
	var reader TLSEncryptedStreamReader
	reader.upstream = upstream
	reader.raw = upstream.Upstream().(io.Reader)
	reader.buffer = upstream.Buffer()
	return &reader
}

func (r *TLSEncryptedStreamReader) Read(p []byte) (n int, err error) {
	if !r.buffer.IsEmpty() {
		return r.buffer.Read(p)
	}
	data := r.buffer.Slice()
	_, err = io.ReadFull(r.raw, data[:tlsEncryptedLengthChunkLength])
	if err != nil {
		return
	}
	r.buffer.FullReset()
	err = r.upstream.ReadChunk(r.buffer, data[:tlsEncryptedLengthChunkLength])
	if err != nil {
		return
	}
	recordType := data[0]
	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	if recordType == recordTypeApplicationData {
		_, err = r.buffer.ReadFullFrom(r.raw, recordLen)
		if err != nil {
			return
		}
	} else {
		_, err = io.ReadFull(r.raw, data[5:5+recordLen+shadowaead.Overhead])
		if err != nil {
			return
		}
		err = r.upstream.ReadChunk(r.buffer, data[5:5+recordLen+shadowaead.Overhead])
		if err != nil {
			return
		}
	}
	return r.buffer.Read(p)
}

type TLSEncryptedStreamWriter struct {
	upstream *shadowaead.Writer
	raw      io.Writer
	buffer   *buf.Buffer
	pipeIn   *io.PipeReader
	pipeOut  *io.PipeWriter
}

func NewTLSEncryptedStreamWriter(upstream *shadowaead.Writer) *TLSEncryptedStreamWriter {
	var writer TLSEncryptedStreamWriter
	writer.upstream = upstream
	writer.raw = upstream.Upstream().(io.Writer)
	writer.buffer = upstream.Buffer()
	writer.pipeIn, writer.pipeOut = io.Pipe()
	go writer.loopOut()
	return &writer
}

func (w *TLSEncryptedStreamWriter) Write(p []byte) (n int, err error) {
	return w.pipeOut.Write(p)
}

func (w *TLSEncryptedStreamWriter) loopOut() {
	data := w.buffer.Slice()
	var err error
	for {
		_, err = io.ReadFull(w.pipeIn, data[:5])
		if err != nil {
			break
		}
		recordType := data[0]
		recordLen := int(binary.BigEndian.Uint16(data[3:5]))

		w.buffer.FullReset()
		w.upstream.WriteChunk(w.buffer, data[:5])

		if recordType != recordTypeApplicationData {
			_, err = io.ReadFull(w.pipeIn, data[tlsEncryptedLengthChunkLength:tlsEncryptedLengthChunkLength+recordLen])
			if err != nil {
				return
			}
			w.upstream.WriteChunk(w.buffer, data[tlsEncryptedLengthChunkLength:tlsEncryptedLengthChunkLength+recordLen])
		} else {
			_, err = w.buffer.ReadFullFrom(w.pipeIn, recordLen)
			if err != nil {
				break
			}
		}

		_, err = w.raw.Write(w.buffer.Bytes())
		if err != nil {
			break
		}
	}
	w.pipeIn.CloseWithError(err)
}

func (w *TLSEncryptedStreamWriter) Close() error {
	return common.Close(
		w.upstream,
		w.pipeOut,
	)
}

func (w *TLSEncryptedStreamWriter) Upstream() any {
	return w.upstream
}
