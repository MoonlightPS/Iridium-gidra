package proxy

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/MoonlightPS/Iridium-gidra/gover/kcp"
	"github.com/MoonlightPS/Iridium-gidra/gover/utils"
	"github.com/yezihack/colorlog"
)

var be = binary.BigEndian

type WriteFunc = func([]byte) (int, error)

const BUFFER_SIZE = 4 * 1024 * 1024

type KCPConn struct {
	client     *kcp.KCP
	cChan      chan []byte
	server     *kcp.KCP
	sChan      chan []byte
	writeLocal WriteFunc
	remote     *net.UDPConn
	key        *utils.PacketKey
	parser     *utils.PacketHandler
	recorder   *utils.Recorder
	hs         *Handshake
	running    bool
	keyID      int
	seed       uint64
	clientSeed uint64
	recv       []byte
	send       []byte
	once       sync.Once
	mu         sync.RWMutex
}

func (c *KCPConn) Start() {
	go func() {
		// recv from server
		buf := make([]byte, 4096)
		remote, server := c.remote, c.server
		for {
			n, err := remote.Read(buf)
			// colorlog.Debug("read from server, n: %d", n)
			if err != nil {
				colorlog.Error("read udp from server failed, err: %+v", err)
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
			if IsHandshakePacket(buf[:n]) {
				handshake, err := ParseHandshakePacket(buf[:n])
				if err != nil {
					colorlog.Error("handle handshake failed, err: %+v", err)
					continue
				}
				switch handshake.m1 {
				case HANDSHAKE_FIN:
					c.Close(handshake)
					return
				}
				continue
			}
			res := server.Input(buf[:n])
			if res != 0 {
				colorlog.Error("recv kcp packet failed, lid: %d", c.hs.lid)
				continue
			}

			n = server.Recv(c.recv)
			for n > 0 {
				packet := make([]byte, n)
				copy(packet, c.recv)
				c.sChan <- packet
				n = server.Recv(c.recv)
			}
		}
	}()
	go func() {
		// update client
		for c.running {
			cur := kcp.CurrentMs()
			c.client.Update(cur)
			next := c.client.Check(cur) - cur
			if next > 0 {
				time.Sleep(time.Millisecond * time.Duration(next))
			}
		}
	}()
	go func() {
		// update server
		for c.running {
			cur := kcp.CurrentMs()
			c.server.Update(cur)
			next := c.server.Check(cur) - cur
			if next > 0 {
				time.Sleep(time.Millisecond * time.Duration(next))
			}
		}
	}()
	go func() {
		// process client req
		ch, recorder, parser, server := c.cChan, c.recorder, c.parser, c.server
		for packet := range ch {
			// now := time.Now()
			cmd, err := parser.ParseCmd(packet)
			if err != nil {
				colorlog.Error("parse client packet failed! err: %+v", err)
				continue
			}
			recorder.Record(packet, utils.SOURCE_CLIENT, cmd)

			// colorlog.Debug("client recv packet cmd:%d, n:%d", cmd, len(packet))

			if handler, ok := handlersMap[cmd]; ok {
				packet, err = handler(c, packet, false)
				if err != nil {
					colorlog.Error("handle client packet %d failed! err: %+v", cmd, err)
					continue
				}
			}

			res := server.Send(packet)
			if res != 0 {
				colorlog.Error("send client packet failed! err: %+v", cmd)
			}
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

			// if cmd == utils.WindSeedClientNotify {
			// 	colorlog.Warn("Blocked WindSeedClientNotify")
			// 	continue
			// }

			if handler, ok := handlersMap[cmd]; ok {
				packet, err = handler(c, packet, false)
				if err != nil {
					colorlog.Error("handle server packet %d failed! err: %+v", cmd, err)
					continue
				}
			}

			res := client.Send(packet)
			// colorlog.Debug("enqueue packet to client cmd:%d, n:%d", cmd, len(packet))
			if res != 0 {
				colorlog.Error("send server packet failed! err: %+v", cmd)
			}
			// colorlog.Debug("server packet handle take: %v", time.Since(now))
		}
		colorlog.Warn("processor server quit")
	}()

	c.recorder.Start()
}

func (c *KCPConn) Input(data []byte, size int) int {
	res := c.client.Input(data[:size])
	if res != 0 {
		return res
	}
	n := c.client.Recv(c.send)
	for n > 0 {
		packet := make([]byte, n)
		copy(packet, c.send)
		c.cChan <- packet
		n = c.client.Recv(c.send)
	}
	return 0
}

func (c *KCPConn) Close(hs *Handshake) {
	c.once.Do(func() {
		if hs == nil {
			hs = NewHandshakePacket(HANDSHAKE_FIN, c.hs.conv, c.hs.token, 1, 0x19419494)
		}
		if c.remote != nil {
			c.remote.Write(hs.Compose())
			c.remote.Close()
		}
		if c.writeLocal != nil {
			c.writeLocal(hs.Compose())
		}
		c.running = false
		close(c.cChan)
		close(c.sChan)
		c.recorder.Stop()
		c.client.Free()
		c.server.Free()
	})
}

func ConstructKCPConn(remote *net.UDPAddr, writeLocal WriteFunc, hs *Handshake, key *utils.PacketKey, keyID int) (*KCPConn, error) {
	colorlog.Info("handling new conn...")

	conn, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		return nil, err
	}

	hsBuf := hs.Compose()
	n, err := conn.Write(hsBuf)
	if err != nil {
		return nil, err
	}
	if n != len(hsBuf) {
		return nil, errors.New("write handshake failed")
	}

	buf := make([]byte, 128)
	n, err = conn.Read(buf)
	if err != nil {
		return nil, err
	}

	handshake, err := ParseHandshakePacket(buf[:n])
	if err != nil {
		return nil, err
	}
	if handshake.m1 != HANDSHAKE_ACK {
		return nil, errors.New("server not ack the handshake")
	}

	writeLocal(buf[:n])

	client, err := kcp.NewKCPWithToken(handshake.conv, handshake.token, func(buf []byte, size int) {
		// colorlog.Debug("send to client, n: %d", size)
		if size >= kcp.IkcpOVERHEAD {
			n, err := writeLocal(buf[:size])
			if err != nil {
				colorlog.Error("write udp to local failed, err: %+v", err)
			}
			if n != size {
				colorlog.Error("write udp to local failed, err: n!=size")
			}
		}
	})
	if err != nil {
		return nil, err
	}
	client.SetMtu(1200)
	client.WndSize(1024, 1024)
	client.NoDelay(1, 10, 2, 1)

	server, err := kcp.NewKCPWithToken(handshake.conv, handshake.token, func(buf []byte, size int) {
		// colorlog.Debug("send to server, n: %d", size)
		if size >= kcp.IkcpOVERHEAD {
			n, err := conn.Write(buf[:size])
			if err != nil {
				colorlog.Error("write udp to server failed, err: %+v", err)
			}
			if n != size {
				colorlog.Error("write udp to server failed, err: n!=size")
			}
		}
	})
	if err != nil {
		return nil, err
	}
	server.SetMtu(1200)
	server.WndSize(1024, 1024)
	server.NoDelay(1, 10, 2, 1)

	parser := utils.NewPacketHandler()
	parser.SetKey(key)

	kConn := &KCPConn{
		client:     client,
		cChan:      make(chan []byte, 8192),
		server:     server,
		sChan:      make(chan []byte, 8192),
		writeLocal: writeLocal,
		remote:     conn,
		key:        key,
		parser:     parser,
		recorder:   utils.NewRecorder(16384, parser),
		hs:         handshake,
		running:    true,
		keyID:      keyID,
		recv:       make([]byte, BUFFER_SIZE),
		send:       make([]byte, BUFFER_SIZE),
	}

	kConn.Start()

	colorlog.Info("conn constructed")

	return kConn, nil
}

type KCPSocket struct {
	local  *net.UDPConn
	remote *net.UDPAddr
	key    *utils.PacketKey
	keyID  int
	conns  *sync.Map
}

func (k *KCPSocket) Start() {
	k.conns = &sync.Map{}
	go func() {
		// recv from local
		buf := make([]byte, 4096)
		local, remote, key, keyID, conns := k.local, k.remote, k.key, k.keyID, k.conns
		for {
			n, addr, err := local.ReadFrom(buf)
			// colorlog.Debug("read from %+v, n: %d", addr, n)
			if err != nil {
				colorlog.Error("read udp from local failed, err: %+v", err)
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
			if IsHandshakePacket(buf[:n]) {
				handshake, err := ParseHandshakePacket(buf[:n])
				if err != nil {
					colorlog.Error("handle handshake failed, err: %+v", err)
					continue
				}
				switch handshake.m1 {
				case HANDSHAKE_SYN:
					go func() {
						conn, err := ConstructKCPConn(remote, func(b []byte) (int, error) {
							return local.WriteTo(b, addr)
						}, handshake, key.Duplicate(), keyID)
						if err != nil {
							colorlog.Error("construct kcp conn failed, err: %+v", err)
							return
						}
						conns.Store(conn.hs.lid, conn)
					}()
				case HANDSHAKE_FIN:
					if i, ok := conns.LoadAndDelete(handshake.lid); ok {
						i.(*KCPConn).Close(handshake)
					}
				}
				continue
			}
			lid := ToLID(le.Uint32(buf), le.Uint32(buf[4:]))
			if i, ok := conns.Load(lid); ok {
				res := i.(*KCPConn).Input(buf, n)
				if res != 0 {
					colorlog.Error("write kcp packet failed, lid: %d", lid)
				}
			} else {
				colorlog.Warn("not found session with %d", lid)
			}
		}
	}()
}

func (s *KCPSocket) Stop() {
	s.local.Close()
	s.conns.Range(func(key, value interface{}) bool {
		value.(*KCPConn).Close(nil)
		return true
	})
	s.conns = nil
}

type ProxyInterface interface {
	Start()
	Stop()
}

func NewKCPSocket(local *net.UDPConn, remote *net.UDPAddr, dispatchKey *utils.PacketKey, keyID int) ProxyInterface {
	return &KCPSocket{
		local:  local,
		remote: remote,
		key:    dispatchKey,
		keyID:  keyID,
		conns:  nil,
	}
}
