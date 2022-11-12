package bypass

import "net"

type CallbackDesc struct {
	IP   net.IP
	Port uint16
	Func func(data []byte, source int)
}
