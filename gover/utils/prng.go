package utils

import "math"

type CompatPrng struct {
	seedArray []int32
	inext     int32
	inextp    int32
}

func abs(x int32) int32 {
	if x < 0 {
		x = -x
	}
	return x
}

func (c *CompatPrng) SafeUInt64() uint64 {
	return uint64(c.Sample() * math.MaxUint64)
}

func (c *CompatPrng) Sample() float64 {
	return float64(c.sample()) * (1.0 / float64(math.MaxInt32))
}

func (c *CompatPrng) sample() int32 {
	locINext := c.inext + 1
	if locINext >= 56 {
		locINext = 1
	}

	locINextp := c.inextp + 1
	if locINextp >= 56 {
		locINextp = 1
	}

	seedArray := c.seedArray
	retVal := seedArray[locINext] - seedArray[locINextp]

	if retVal == math.MaxInt32 {
		retVal--
	}
	if retVal < 0 {
		retVal += math.MaxInt32
	}

	seedArray[locINext] = retVal
	c.inext = locINext
	c.inextp = locINextp

	return retVal
}

func NewCompatPrng(seed int32) *CompatPrng {
	seedArray := make([]int32, 56)

	var subtraction int32 = abs(seed)
	if seed == math.MinInt32 {
		subtraction = math.MaxInt32
	}
	mj := 161803398 - subtraction
	seedArray[55] = mj
	var mk int32 = 1

	var ii int32 = 0
	for i := int32(1); i < 55; i++ {
		// The range [1..55] is special (Knuth) and so we're wasting the 0'th position.
		ii += 21
		if (ii) >= 55 {
			ii -= 55
		}

		seedArray[ii] = mk
		mk = mj - mk
		if mk < 0 {
			mk += math.MaxInt32
		}

		mj = seedArray[ii]
	}

	for k := int32(1); k < 5; k++ {
		for i := int32(1); i < 56; i++ {
			n := i + 30
			if n >= 55 {
				n -= 55
			}

			seedArray[i] -= seedArray[1+n]
			if seedArray[i] < 0 {
				seedArray[i] += math.MaxInt32
			}
		}
	}

	return &CompatPrng{
		seedArray: seedArray,
		inext:     0,
		inextp:    21,
	}
}
