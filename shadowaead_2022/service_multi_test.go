package shadowaead_2022_test

import (
	"context"
	"crypto/rand"
	"net"
	"sync"
	"testing"

	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestMultiService(t *testing.T) {
	t.Parallel()
	method := "2022-blake3-aes-128-gcm"
	var iPSK [16]byte
	rand.Reader.Read(iPSK[:])

	var wg sync.WaitGroup

	multiService, err := shadowaead_2022.NewMultiService[string](method, iPSK[:], 500, &multiHandler{t, &wg})
	if err != nil {
		t.Fatal(err)
	}

	var uPSK [16]byte
	rand.Reader.Read(uPSK[:])
	multiService.UpdateUsers([]string{"my user"}, [][]byte{uPSK[:]})

	client, err := shadowaead_2022.New(method, [][]byte{iPSK[:], uPSK[:]})
	if err != nil {
		t.Fatal(err)
	}
	wg.Add(1)

	serverConn, clientConn := net.Pipe()
	defer common.Close(serverConn, clientConn)
	go func() {
		err := multiService.NewConnection(context.Background(), serverConn, M.Metadata{})
		if err != nil {
			serverConn.Close()
			t.Error(E.Cause(err, "server"))
			return
		}
	}()
	_, err = client.DialConn(clientConn, M.ParseSocksaddr("test.com:443"))
	if err != nil {
		t.Fatal(err)
	}
	wg.Wait()
}

type multiHandler struct {
	t  *testing.T
	wg *sync.WaitGroup
}

func (h *multiHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	if metadata.Destination.String() != "test.com:443" {
		h.t.Error("bad destination")
	}
	h.wg.Done()
	return nil
}

func (h *multiHandler) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	return nil
}

func (h *multiHandler) NewError(ctx context.Context, err error) {
	h.t.Error(ctx, err)
}
