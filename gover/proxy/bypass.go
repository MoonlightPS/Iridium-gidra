package proxy

import (
	"net"
	"sync"

	"github.com/MoonlightPS/Iridium-gidra/gover/kcp"
	"github.com/MoonlightPS/Iridium-gidra/gover/proxy/bypass"
	"github.com/MoonlightPS/Iridium-gidra/gover/utils"
	"github.com/yezihack/colorlog"
)

var prng *utils.CompatPrng

func genPrngSeed(seed uint64) uint64 {
	return utils.NewCompatPrng(int32(seed)).SafeUInt64()
}

func sniffKey(mSeed, sentMs uint64, packet []byte) uint64 {
	key := utils.NewPacketKey()
	buf := make([]byte, 4)
	sniff := func(seed uint64) bool {
		key.GenKey(seed)
		copy(buf, packet)
		key.Xor(buf)
		if be.Uint16(buf) == 0x4567 {
			return true
		}
		return false
	}
	for times := uint64(0); times < 1e4; times++ {
		seed := genPrngSeed(sentMs+times) ^ mSeed
		if sniff(seed) {
			colorlog.Debug("key found, seed: %d", seed)
			return seed
		}
		seed = genPrngSeed(sentMs-times) ^ mSeed
		if sniff(seed) {
			colorlog.Debug("key found, seed: %d", seed)
			return seed
		}
	}
	colorlog.Debug("key not found")
	return 0
}

func (c *KCPConn) StartBypass() {
	go func() {
		// process client req
		ch, recorder, parser, server := c.cChan, c.recorder, c.parser, c.server
		for packet := range ch {
			// now := time.Now()
			cmd, err := parser.ParseCmd(packet)
			if err != nil && c.clientSeed != 0 {
				c.seed = sniffKey(c.seed, c.clientSeed, packet)
				c.key.GenKey(c.seed)
				c.clientSeed = 0
				cmd, err = parser.ParseCmd(packet)
			}
			if err != nil {
				colorlog.Error("parse client packet failed! err: %+v", err)
				continue
			}
			recorder.Record(packet, utils.SOURCE_CLIENT, cmd)

			// colorlog.Debug("client recv packet cmd:%d, n:%d", cmd, len(packet))

			if handler, ok := handlersMap[cmd]; ok {
				_, err = handler(c, packet, true)
				if err != nil {
					colorlog.Error("handle client packet %d failed! err: %+v", cmd, err)
					continue
				}
			}
			server.Update(kcp.CurrentMs())
			// colorlog.Debug("client packet handle take: %v", time.Since(now))
		}
		colorlog.Warn("processor client quit")
	}()
	go func() {
		// process server rsp
		ch, recorder, parser, client := c.sChan, c.recorder, c.parser, c.client
		for packet := range ch {
			// now := time.Now()
			cmd, err := parser.ParseCmd(packet)
			if err != nil {
				colorlog.Error("parse server packet failed! err: %+v", err)
				continue
			}
			recorder.Record(packet, utils.SOURCE_SERVER, cmd)

			// colorlog.Debug("server recv packet cmd:%d, n:%d", cmd, len(packet))

			if handler, ok := handlersMap[cmd]; ok {
				_, err = handler(c, packet, true)
				if err != nil {
					colorlog.Error("handle server packet %d failed! err: %+v", cmd, err)
					continue
				}
			}
			client.Update(kcp.CurrentMs())
			// colorlog.Debug("server packet handle take: %v", time.Since(now))
		}
		colorlog.Warn("processor server quit")
	}()

	c.recorder.Start()
}

func (c *KCPConn) InputServer(data []byte, size int) int {
	res := c.server.Input(data[:size])
	if res != 0 {
		return res
	}
	n := c.server.Recv(c.recv)
	for n > 0 {
		packet := make([]byte, n)
		copy(packet, c.recv)
		c.sChan <- packet
		n = c.server.Recv(c.recv)
	}
	return 0
}

func ConstructBypassConn(hs *Handshake, key *utils.PacketKey, keyID int) (*KCPConn, error) {
	client, err := kcp.NewKCPWithToken(hs.conv, hs.token, nil)
	if err != nil {
		return nil, err
	}
	client.SetMtu(1200)
	client.WndSize(1024, 1024)
	client.NoDelay(1, 10, 2, 1)

	server, err := kcp.NewKCPWithToken(hs.conv, hs.token, nil)
	if err != nil {
		return nil, err
	}
	server.SetMtu(1200)
	server.WndSize(1024, 1024)
	server.NoDelay(1, 10, 2, 1)

	parser := utils.NewPacketHandler()
	parser.SetKey(key)

	kConn := &KCPConn{
		client:   client,
		cChan:    make(chan []byte, 8192),
		server:   server,
		sChan:    make(chan []byte, 8192),
		key:      key,
		parser:   parser,
		recorder: utils.NewRecorder(16384, parser),
		hs:       hs,
		running:  true,
		keyID:    keyID,
		recv:     make([]byte, BUFFER_SIZE),
		send:     make([]byte, BUFFER_SIZE),
	}

	kConn.StartBypass()

	colorlog.Info("conn sniffed")

	return kConn, nil
}

type BypassSocket struct {
	remote *net.UDPAddr
	key    *utils.PacketKey
	keyID  int
	conns  *sync.Map
}

func (b *BypassSocket) Start() {
	conns := &sync.Map{}
	b.conns = conns
	bypass.RegisterCallback(&bypass.CallbackDesc{
		IP:   b.remote.IP.To4(),
		Port: uint16(b.remote.Port),
		Func: func(buf []byte, source int) {
			if IsHandshakePacket(buf) {
				handshake, err := ParseHandshakePacket(buf)
				if err != nil {
					colorlog.Error("handle handshake failed, err: %+v", err)
					return
				}
				switch handshake.m1 {
				case HANDSHAKE_ACK:
					conn, err := ConstructBypassConn(handshake, b.key.Duplicate(), b.keyID)
					if err != nil {
						colorlog.Error("construct kcp conn failed, err: %+v", err)
						return
					}
					conns.Store(conn.hs.lid, conn)
				case HANDSHAKE_FIN:
					if i, ok := conns.LoadAndDelete(handshake.lid); ok {
						i.(*KCPConn).Close(handshake)
					}
				}
				return
			}
			lid := ToLID(le.Uint32(buf), le.Uint32(buf[4:]))
			if i, ok := conns.Load(lid); ok {
				var res int
				if source == utils.SOURCE_CLIENT {
					res = i.(*KCPConn).Input(buf, len(buf))
				} else {
					res = i.(*KCPConn).InputServer(buf, len(buf))
				}
				if res != 0 {
					colorlog.Error("write kcp packet failed, lid: %d", lid)
				}
			} else {
				colorlog.Warn("not found session with %d", lid)
			}
		},
	})
}
func (b *BypassSocket) Stop() {
	bypass.RemoveCallback(&bypass.CallbackDesc{
		IP:   b.remote.IP.To4(),
		Port: uint16(b.remote.Port),
	})
	b.conns.Range(func(key, value interface{}) bool {
		value.(*KCPConn).Close(nil)
		return true
	})
	b.conns = nil
}

func NewBypassSocket(remote *net.UDPAddr, dispatchKey *utils.PacketKey, keyID int) ProxyInterface {
	return &BypassSocket{
		remote: remote,
		key:    dispatchKey,
		keyID:  keyID,
		conns:  nil,
	}
}
