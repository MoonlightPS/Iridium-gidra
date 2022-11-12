package kcp

import (
	"fmt"
	"testing"
)

func TestKCP(t *testing.T) {
	kcp, err := NewKCPWithToken(1, 2, func(buf []byte, size int) { fmt.Println(buf, size) })
	fmt.Println(kcp, err)
	kcp.NoDelay(1, 10, 2, 1)
	kcp.Send([]byte("hello world"))
	kcp.Update(0)
	kcp.Input([]byte{1, 0, 0, 0, 2, 0, 0, 0, 81, 0, 32, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11, 0, 0, 0, 104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100})
	d := make([]byte, 1500)
	n := kcp.Recv(d)
	fmt.Println(n)
	if n > 0 {
		fmt.Println(string(d[:n]))
	}
}
