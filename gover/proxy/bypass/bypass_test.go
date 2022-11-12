package bypass

import (
	"fmt"
	"net"
	"testing"
)

func TestBypass(t *testing.T) {
	fmt.Println(net.Interfaces())
}
