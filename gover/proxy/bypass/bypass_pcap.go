//go:build bypass
// +build bypass

package bypass

import (
	"encoding/binary"
	"net"
	"strings"
	"sync"

	"github.com/MoonlightPS/Iridium-gidra/gover/utils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/yezihack/colorlog"
)

var be = binary.BigEndian

func getAllDevicesHandlers() (handles []*pcap.Handle, err error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return
	}
	for _, dev := range devs {
		desc := strings.ToLower(dev.Description)
		if strings.Contains(desc, "loopback") ||
			strings.Contains(desc, "virtual") ||
			strings.Contains(desc, "miniport") {
			continue
		}
		handle, err := pcap.OpenLive(dev.Name, 1600, true, pcap.BlockForever)
		if err != nil {
			for _, h := range handles {
				h.Close()
			}
			return nil, err
		}
		if handle.LinkType() != layers.LinkTypeEthernet {
			handle.Close()
			continue
		}
		handle.SetBPFFilter("udp portrange 22101-22102")
		handles = append(handles, handle)
	}
	return
}

type notifyObj struct {
	cb     *CallbackDesc
	remove bool
}

type bypassListener struct {
	handle *pcap.Handle
	notify chan notifyObj
	quit   chan int
}

func (b *bypassListener) Start() {
	go func() {
		source := gopacket.NewPacketSource(b.handle, b.handle.LinkType())
		lstMap := map[uint64]func(data []byte, source int){}
		for {
			select {
			case pk := <-source.Packets():
				var src, dst net.IP
				if ipLayer := pk.Layer(layers.LayerTypeIPv4); ipLayer != nil {
					ip, _ := ipLayer.(*layers.IPv4)
					src, dst = ip.SrcIP, ip.DstIP
				}
				if len(src) < 4 || len(dst) < 4 {
					continue
				}
				if udpLayer := pk.Layer(layers.LayerTypeUDP); udpLayer != nil {
					udp, _ := udpLayer.(*layers.UDP)
					id1 := (uint64(be.Uint32(src)) << 32) | uint64(udp.SrcPort)
					id2 := (uint64(be.Uint32(dst)) << 32) | uint64(udp.DstPort)
					if f, ok := lstMap[id1]; ok {
						f(udp.Payload, utils.SOURCE_SERVER)
					} else if f, ok := lstMap[id2]; ok {
						f(udp.Payload, utils.SOURCE_CLIENT)
					}
				}
			case notify := <-b.notify:
				if len(notify.cb.IP) < 4 {
					continue
				}
				id := (uint64(be.Uint32(notify.cb.IP)) << 32) | uint64(notify.cb.Port)
				if notify.remove {
					delete(lstMap, id)
				} else if notify.cb.Func != nil {
					lstMap[id] = notify.cb.Func
					colorlog.Info("register func on %s:%d with %d", notify.cb.IP, notify.cb.Port, id)
				}
			case <-b.quit:
				return
			}
		}
	}()
}

func (b *bypassListener) Stop() {
	b.quit <- 1
}

var bypassObj = struct {
	handles []*bypassListener
	mu      sync.Mutex
}{}

func CheckBypassBuild() bool { return true }

func StartBypassService() error {
	bypassObj.mu.Lock()
	defer bypassObj.mu.Unlock()
	if len(bypassObj.handles) > 0 {
		return nil
	}
	handles, err := getAllDevicesHandlers()
	if err != nil {
		return err
	}
	for _, h := range handles {
		listener := &bypassListener{
			handle: h,
			notify: make(chan notifyObj, 1024),
			quit:   make(chan int),
		}
		listener.Start()
		bypassObj.handles = append(bypassObj.handles, listener)
	}
	return nil
}

func RegisterCallback(cb *CallbackDesc) {
	bypassObj.mu.Lock()
	defer bypassObj.mu.Unlock()
	for _, h := range bypassObj.handles {
		h.notify <- notifyObj{cb: cb}
	}
}

func RemoveCallback(cb *CallbackDesc) {
	bypassObj.mu.Lock()
	defer bypassObj.mu.Unlock()
	for _, h := range bypassObj.handles {
		h.notify <- notifyObj{cb: cb, remove: true}
	}
}

func StopBypassService() {
	bypassObj.mu.Lock()
	defer bypassObj.mu.Unlock()
	for _, h := range bypassObj.handles {
		h.Stop()
	}
	bypassObj.handles = nil
}
