package utils

import (
	"fmt"
	"testing"
)

func TestPrng(t *testing.T) {
	p := NewCompatPrng(1024)
	v := p.SafeUInt64()
	fmt.Println(v)
	if v != 12723918419362635776 {
		t.Fail()
	}
}
