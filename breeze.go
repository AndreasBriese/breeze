// LICENSE
// MIT-TYPE with ADDITIONAL RESTRICTIVE CLAUSE about Breeze implementations in hardware
//
// Copyright (c) 2014 Andreas Briese <ab@edutoolbox.de>, 31157 Sarstedt, Gernmany
//
// ADDITIONAL RESTRICTIVE CLAUSE: Any use of this software, modifications of this software or modifications or extensions
// of the underlying principle of the Breeze RNG implemented IN HARDWARE needs to be explicitly licensed by the copyright holder
// Andreas Briese (contact: ab<at>edutoolbox.de).
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy,
// modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software
// is furnished to do so, subject to the following conditions:
// //
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
// OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
// IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// Note:
// The purpose of this modified MIT LICENSE with ADDITIONAL RESTRICTIVE CLAUSE shall allow a unrestricted use by developers on any
// software platform. In case of the implementation of Breeze or it's underlying logic in RNG hardware (for example but not limited
// to encryption chips or PIN number generators) the producer of such hardware needs to document the proper implementation to become
// licensed. This takes into account that improper or wrong implementation of Breeze in hardware might decrease the quality of the the
// resulting random number stream.
//
//
// Important Note 2014/10/30:
// Breeze had not been cryptoanalysed.
// It is definitly not recommended to use Breeze and it's ShortHash() or XOR() functions in particular in any security sensitive or
// cryptographic context.
//
// revision 2014/11/7:
//
// Breeze32 / Breeze72 removed.
// moved to Breeze128 (4 LMs) Breeze256 (8 LMs) to provide practice relevant length of keyspace: 128bit / 256bit.
//

package breeze

import (
	"errors"
	"sync"
	"unsafe"
)

var (
	initSeedErr          = errors.New("Seed type not supported")
	initSeedToShort      = errors.New("Seed to short")
	initSeedArrayToShort = errors.New("[]uint64 seed must have at least length of 2")
	mutex                = &sync.Mutex{}
)

// initr(s interface{}) (seed [2]uint64)
// processes the seed given by the user and returns
// two uint64 to seed up to four logistic map functions
// it takes various user seed formats:
// (u)int/8/16/32/84, float32/64, []uint64 processed directly here
// []byte, string are "folded+compressed" by sipHash compression function
// it is used by all below Breeze flavours
func initr(s interface{}) (seed [2]uint64, err error) {
	switch s := s.(type) {
	case int:
		if s < 0 {
			s = -s
		}
		seed = [2]uint64{uint64(s), uint64(0)}
	case int8:
		if s < 0 {
			s = -s
		}
		seed = [2]uint64{uint64(s), uint64(0)}
	case int16:
		if s < 0 {
			s = -s
		}
		seed = [2]uint64{uint64(s), uint64(0)}
	case int32:
		if s < 0 {
			s = -s
		}
		seed = [2]uint64{uint64(s), uint64(0)}
	case int64:
		if s < 0 {
			s = -s
		}
		seed = [2]uint64{uint64(s), uint64(0)}
	case uint8:
		seed = [2]uint64{uint64(s), uint64(0)}
	case uint16:
		seed = [2]uint64{uint64(s), uint64(0)}
	case uint32:
		seed = [2]uint64{uint64(s), uint64(0)}
	case uint64:
		seed = [2]uint64{s, 0}
	case []uint64:
		for len(s) > 2 {
			seed[0] ^= s[0]
			seed[1] ^= s[1]
			s = s[2:]
		}
		seed[0] ^= s[0]
		seed[1] ^= s[len(s)-1]
	case string:
		seed = foldAndCompress([]byte(s))
	case []byte:
		seed = foldAndCompress(s)
	case float32:
		seed = [2]uint64{uint64(*(*uint32)(unsafe.Pointer(&s)) << 9 >> 9), uint64(0)}
	case float64:
		seed = [2]uint64{*(*uint64)(unsafe.Pointer(&s)) << 11 >> 11, uint64(0)}
	default:
		return seed, initSeedErr
	}
	return seed, nil
}

// splittr(seed uint64) (s1, s2, startrounds uint64)
// processes two logistic map seeds (<2**32) and startrounds (>>38 overhead) from a given uint64
// returns seeds s1, s2, startrounds
func splittr(seed uint64) (s1, s2, s3 uint64) {
	s1 = 1<<22 - seed>>43
	s2 = 1<<23 - seed<<21>>42
	s3 = 1<<22 - seed<<43>>43
	return s1, s2, s3
}

//
// Breeze 128
//
// implements a cb-prng with four LM
// seeds with two 64bit (uint64) -> four seeds 2**32 + startrounds
// 128 Byte outputstate
type Breeze128 struct {
	state          [16]uint64
	state1, state2 float64
	state3, state4 float64
	state5, state6 float64
	bitshift       uint8
	idx            uint8
	strt           unsafe.Pointer
}

// Reset resets to the initial (empty) state
// before initializing.
func (l *Breeze128) Reset() {
	*l = Breeze128{}
}

// Init initializes from user input by calling initr() to process the input to become seeds (seedr(seed)) for the LMs.
// Init reseeds the LMs but it does NOT reset the prng:
//    it seeds based on the previous output states, internal bitshift and idx values
func (l *Breeze128) Init(s interface{}) (err error) {
	seed, err := initr(s)
	if err != nil {
		return err
	}
	l.seedr(seed)
	return err
}

// seedr calculates the startvalues of the LMs and
// calls for the initial 'startrounds' roundtrips to shift circle
// once or more times over the output states
func (l *Breeze128) seedr(seed [2]uint64) {
	s1, s2, s3 := splittr(seed[0])
	s4, s5, s6 := splittr(seed[1])
	startrounds := 17

	l.state1 = 1.0 / float64(s1)
	l.state2 = 1.0 - 1.0/float64(s2)
	l.state3 = 1.0 / float64(s3)
	l.state4 = 1.0 - 1.0/float64(s4)
	l.state5 = 1.0 / float64(s5)
	l.state6 = 1.0 - 1.0/float64(s6)

	for startrounds > 0 {
		l.roundTrip()
		startrounds--
	}
	l.strt = unsafe.Pointer(&l.state[0])

}

// roundTrip calculates the next LMs states
// tests the states to be != 0 (else reseeds from previous states)
// interchanges the states between LMs after 'mirroring them at 1'
// processes the output states from two or more LMs states
// mixin (xoring) in previous output states
// rotates all output states
func (l *Breeze128) roundTrip() {
	newstate1 := (1.0 - l.state1)
	newstate1 *= 4.0 * l.state1
	newstate2 := (1.0 - l.state2)
	newstate2 *= 3.999999999 * l.state2
	newstate3 := (1.0 - l.state3)
	newstate3 *= 3.99999998 * l.state3
	newstate4 := (1.0 - l.state4)
	newstate4 *= 3.99999997 * l.state4
	// ...
	// newstate_n := (1.0 - l.state_n)
	// newstate_n *= 3.83 * l.state_n

	switch newstate1 * newstate2 * newstate3 * newstate4 {
	case 0:
		s1 := (uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<11>>(12+l.bitshift%7)) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<11>>(12+l.bitshift%7))
		s1 += (uint64)((*(*uint64)(unsafe.Pointer(&l.state5))) << 11 >> (12 + l.bitshift%7))
		s2 := (uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<11>>(12+l.bitshift%7)) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state4)))<<11>>(12+l.bitshift%7))
		s2 += (uint64)((*(*uint64)(unsafe.Pointer(&l.state6))) << 11 >> (12 + l.bitshift%7))
		seed := [2]uint64{s1, s2}
		l.bitshift++
		l.seedr(seed)
	default:
		l.state1 = 1.0 - newstate2
		l.state2 = l.state6
		l.state3 = 1.0 - newstate4
		l.state4 = l.state5
		l.state5 = 1.0 - newstate1
		l.state6 = 1.0 - newstate3
	}

	l.bitshift = (l.bitshift + 1) % 21

	tmp := l.state[0]
	l.state[0] = l.state[1] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<11>>(12+l.bitshift)))
	l.state[1] = l.state[2] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<11>>(12+l.bitshift)))
	l.state[2] = l.state[3] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state4)))<<11>>(12+l.bitshift)))
	l.state[3] = l.state[4] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state4)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<11>>(12+l.bitshift)))

	l.bitshift++
	l.state[4] = (l.state[5] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<11>>(12+l.bitshift)))) ^ l.state[2]
	l.state[5] = (l.state[6] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<11>>(12+l.bitshift)))) ^ l.state[3]
	l.state[6] = (l.state[7] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state4)))<<11>>(12+l.bitshift)))) ^ l.state[0]

	l.bitshift++
	l.state[7] = (l.state[8] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<11>>(12+l.bitshift)))) ^ l.state[1]
	l.state[8] = (l.state[9] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<11>>(12+l.bitshift)))) ^ l.state[2]
	l.state[9] = (l.state[10] ^ (uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state4)))<<11>>(12+l.bitshift))) ^ l.state[3]

	l.bitshift++
	l.state[10] = (l.state[11] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<11>>(12+l.bitshift)))) ^ l.state[0]
	l.state[11] = (l.state[12] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state4)))<<11>>(12+l.bitshift)))) ^ l.state[1]
	l.state[12] = (l.state[13] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<11>>(12+l.bitshift)))) ^ l.state[2]

	l.bitshift++
	l.state[13] = (l.state[14] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state4)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<11>>(12+l.bitshift)))) ^ l.state[3]
	l.state[14] = (l.state[15] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state4)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<11>>(12+l.bitshift)))) ^ l.state[0]
	l.state[15] = (tmp ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state4)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<11>>(12+l.bitshift)))) ^ l.state[1]

}

// isSeeded checks if the prng had been seeded
// and returns bool
func (l *Breeze128) isSeeded() bool {
	for _, v := range l.state {
		if v > 0 {
			return true
		}
	}
	return false
}

// RandIntn returns an uint64 from the outputstate byte register
// calling ByteMP to become thread/multiprocessing safe
func (l *Breeze128) RandIntn() (ri uint64) {
	if !l.isSeeded() {
		return ri
	}
	var byt uint8
	for i := 0; i < 8; i++ {
		l.ByteMP(&byt)
		ri = ri<<8 + uint64(byt)
	}
	return ri
}

// RandDbl returns a positive float64 [0,1) (from an uint64 deriving from outputstate byte register)
// calls RandIntn to be thread/multiprocessing safe
// RandDbl returns are uniform distributed
func (l *Breeze128) RandDbl() float64 {
	if !l.isSeeded() {
		return float64(0)
	}
	rd := float64(l.RandIntn()) / float64(1<<64)
	switch rd {
	case 1:
		return float64(0)
	default:
		return rd
	}
}

// RandNorm returns a positive float64 [0,1) calculating the mean of 3 internal LM states
// and calls a roundTrip afterwards
// RandNorm returns are normal (gaussian) distributed
func (l *Breeze128) RandNorm() (rd float64) {
	if !l.isSeeded() {
		return rd
	}
	rd = (l.state1 + l.state2 + l.state3) / 3
	l.roundTrip()
	switch rd {
	case 1:
		return float64(0)
	default:
		return rd
	}
}

// Byte() sets byt to the next Byte from the prng output byte register
// refreshes by calling roundTrip if all registers on the stack had been called once
func (l *Breeze128) Byte(byt *uint8) {
	*byt = (uint8)(*(*uint8)(unsafe.Pointer(uintptr(l.strt) + uintptr(l.idx))))
	switch l.idx {
	case 127:
		l.roundTrip()
		l.idx = 0
	default:
		l.idx++
	}
}

// ByteMP() is the mutex.Locked variant of Byte(): it sets byt to the next Byte from the prng output byte register
// refreshes by calling roundTrip if all registers on the stack had been called once
// ByteMP is thread/multiprocessing safe
func (l *Breeze128) ByteMP(byt *uint8) {
	mutex.Lock()
	*byt = (uint8)(*(*uint8)(unsafe.Pointer(uintptr(l.strt) + uintptr(l.idx))))
	switch l.idx {
	case 127:
		l.roundTrip()
		l.idx = 0
	default:
		l.idx++
	}
	mutex.Unlock()
}

// XOR(out *[]byte, in *[]byte, key *[]byte)
// XOR (re)seeds the prng with key (via SHortHash function) and
// then XORes the bytes of *in with the *prng output register bytes to *out.
// calls roudTrip to refresh the output byte register if it becomes exhausted
// key must have at least 8 Byte length; keys longer than 1000 Bytes might slow down processing through long seeding calculation
func (l *Breeze128) XOR(out *[]byte, in *[]byte, key *[]byte) error {
	_, err := l.ShortHash(*key, 512/8)
	if err != nil {
		return err
	}
	idx := l.idx
	for i, v := range *in {
		(*out)[i] = v ^ (uint8)(*(*uint8)(unsafe.Pointer(uintptr(l.strt) + uintptr(idx))))
		switch idx {
		case 127:
			l.roundTrip()
			idx = 0
		default:
			idx++
		}
	}
	return nil
}

// ShortHash returns a hash from input of lenInBytes length
// input must have at least a length of 8; else returns an error
// (re)seeds the prng with input folded and compressed by sipHash2-4 forld&compress function
// input longer than 1000 Bytes might slow down processing through long seeding calculation
func (l *Breeze128) ShortHash(s interface{}, lenInBytes int) (hash []byte, err error) {
	hash = make([]byte, lenInBytes)
	var pad []byte
	var padLen int
	var seed [2]uint64

	switch s := s.(type) {
	case string:
		if len(s) < 8 {
			return hash, initSeedToShort
		}
		seed = foldAndCompress([]byte(s))
		padLen = 1 + len(s)/lenInBytes
		pad = make([]byte, padLen*lenInBytes)
		copy(pad[len(s)%lenInBytes:], []byte(s))
	case []byte:
		if len(s) < 8 {
			return hash, initSeedToShort
		}
		seed = foldAndCompress(s)
		padLen = 1 + len(s)/lenInBytes
		pad = make([]byte, padLen*lenInBytes)
		copy(pad[len(s)%lenInBytes:], s)
	default:
		return hash, initSeedErr
	}

	l.seedr(seed)

	copy(hash, pad)
	idx := uintptr(0)
	for i := 0; i < padLen; i++ {
		for ii := 0; ii < lenInBytes; ii++ {
			hash[ii] ^= (pad[i*lenInBytes+ii] ^ (uint8)(*(*uint8)(unsafe.Pointer(uintptr(l.strt) + idx))))
			switch idx {
			case 127:
				l.roundTrip()
				idx = 0
			default:
				idx++
			}
		}
	}

	return hash, nil
}

//
// Breeze 256
//
// implements a cb-prng with eight LM
// seeds with four 64bit (uint64) -> eight seeds 2**32 + startrounds
// 256 Byte outputstate
type Breeze256 struct {
	state                     [32]uint64
	state1, state2, state3    float64
	state4, state5, state6    float64
	state7, state8, state9    float64
	state10, state11, state12 float64
	bitshift                  uint8
	idx                       uint8
	strt                      unsafe.Pointer
}

// Reset resets to the initial (empty) state
// before initializing.
func (l *Breeze256) Reset() {
	*l = Breeze256{}
}

// Init initializes from user input by calling initr() to process the input to become seeds (seedr(seed)) for the LMs.
// Init reseeds the LMs but it does NOT reset the prng:
//    it seeds based on the previous output states, internal bitshift and idx values
func (l *Breeze256) Init(s interface{}) (err error) {
	var seed [4]uint64
	switch s := s.(type) {
	case string:
		if len(s) < 8 {
			return initSeedErr
		}
		if len(s) > 7 && len(s) < 17 {
			seed1 := foldAndCompress([]byte(s))
			seed = [4]uint64{seed1[0], seed1[1], seed1[0], seed1[1]}
		}
		if len(s) > 16 && len(s) < 32 {
			seed1 := foldAndCompress([]byte(s[0:16]))
			seed2 := foldAndCompress([]byte(s[len(s)-16:]))
			seed = [4]uint64{seed1[0], seed1[1], seed2[0], seed2[1]}
		}
		if len(s) > 31 {
			seed1 := foldAndCompress([]byte(s[0 : len(s)/2]))
			seed2 := foldAndCompress([]byte(s[len(s)/2:]))
			seed = [4]uint64{seed1[0], seed1[1], seed2[0], seed2[1]}
		}
	case []byte:
		if len(s) < 8 {
			return initSeedErr
		}
		if len(s) > 7 && len(s) < 17 {
			seed1 := foldAndCompress([]byte(s))
			seed = [4]uint64{seed1[0], seed1[1], seed1[0], seed1[1]}
		}
		if len(s) > 16 && len(s) < 32 {
			seed1 := foldAndCompress([]byte(s[0:16]))
			seed2 := foldAndCompress([]byte(s[len(s)-16:]))
			seed = [4]uint64{seed1[0], seed1[1], seed2[0], seed2[1]}
		}
		if len(s) > 31 {
			seed1 := foldAndCompress([]byte(s[0 : len(s)/2]))
			seed2 := foldAndCompress([]byte(s[len(s)/2:]))
			seed = [4]uint64{seed1[0], seed1[1], seed2[0], seed2[1]}
		}
	case []uint64:
		switch len(s) {
		case 1:
			seed1, err := initr([]uint64{s[0], s[0]})
			if err != nil {
				return initSeedErr
			}
			seed = [4]uint64{seed1[0], seed1[1], uint64(0), uint64(0)}
		case 2:
			seed1, err := initr([]uint64{s[0], s[1]})
			if err != nil {
				return initSeedErr
			}
			seed = [4]uint64{seed1[0], seed1[1], seed1[0], seed1[1]}
		case 3:
			seed1, err := initr([]uint64{s[0], s[1]})
			seed2, err := initr([]uint64{s[2], s[2]})
			if err != nil {
				return initSeedErr
			}
			seed = [4]uint64{seed1[0], seed1[1], seed2[0], seed2[1]}
		case 4:
			seed1, err := initr([]uint64{s[0], s[1]})
			seed2, err := initr([]uint64{s[2], s[3]})
			if err != nil {
				return initSeedErr
			}
			seed = [4]uint64{seed1[0], seed1[1], seed2[0], seed2[1]}
		default:
			return initSeedErr
		}
	default:
		seed1, err := initr(s)
		if err != nil {
			return initSeedErr
		}
		seed = [4]uint64{seed1[0], seed1[1], uint64(0), uint64(0)}
	}
	l.seedr(seed)
	return nil
}

// seedr calculates the startvalues of the LMs and
// calls for the initial 'startrounds' roundtrips to shift circle
// once or more times over the output states
func (l *Breeze256) seedr(seed [4]uint64) {
	s1, s2, s3 := splittr(seed[0])
	s4, s5, s6 := splittr(seed[1])
	s7, s8, s9 := splittr(seed[0])
	s10, s11, s12 := splittr(seed[1])
	startrounds := 37

	l.state1 = 1.0 / float64(s1)
	l.state2 = 1.0 - 1.0/float64(s2)
	l.state3 = 1.0 / float64(s3)
	l.state4 = 1.0 - 1.0/float64(s4)
	l.state5 = 1.0 / float64(s5)
	l.state6 = 1.0 - 1.0/float64(s6)
	l.state7 = 1.0 / float64(s7)
	l.state8 = 1.0 - 1.0/float64(s8)
	l.state9 = 1.0 / float64(s9)
	l.state10 = 1.0 - 1.0/float64(s10)
	l.state11 = 1.0 / float64(s11)
	l.state12 = 1.0 - 1.0/float64(s12)

	for startrounds > 0 {
		l.roundTrip()
		startrounds--
	}
	l.strt = unsafe.Pointer(&l.state[0])

}

// roundTrip calculates the next LMs states
// tests the states to be != 0 (else reseeds from previous states)
// interchanges the states between LMs after 'mirroring them at 1'
// processes the output states from two or more LMs states
// mixin (xoring) in previous output states
// rotates all output states
func (l *Breeze256) roundTrip() {
	newstate1 := (1.0 - l.state1)
	newstate1 *= 3.999999999 * l.state1
	newstate2 := (1.0 - l.state2)
	newstate2 *= 3.999999998 * l.state2
	newstate3 := (1.0 - l.state3)
	newstate3 *= 3.999999997 * l.state3
	newstate4 := (1.0 - l.state4)
	newstate4 *= 3.999999996 * l.state4
	newstate5 := (1.0 - l.state5)
	newstate5 *= 3.99999999 * l.state5
	newstate6 := (1.0 - l.state6)
	newstate6 *= 3.99999998 * l.state6
	newstate7 := (1.0 - l.state7)
	newstate7 *= 3.99999997 * l.state7
	newstate8 := (1.0 - l.state8)
	newstate8 *= 3.99999996 * l.state8
	// ...
	// newstate_n := (1.0 - l.state_n)
	// newstate_n *= 3.83 * l.state_n

	switch newstate1 * newstate2 * newstate3 * newstate4 * newstate5 * newstate6 * newstate7 * newstate8 {
	case 0:
		s1 := (uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<11>>(12+l.bitshift%7)) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<11>>(12+l.bitshift%7))
		s1 += (uint64)((*(*uint64)(unsafe.Pointer(&l.state9))) << 11 >> (12 + l.bitshift%7))
		s2 := (uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<11>>(12+l.bitshift%7)) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state4)))<<11>>(12+l.bitshift%7))
		s2 += (uint64)((*(*uint64)(unsafe.Pointer(&l.state10))) << 11 >> (12 + l.bitshift%7))
		s3 := (uint64)((*(*uint64)(unsafe.Pointer(&l.state5)))<<11>>(12+l.bitshift%7)) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state6)))<<11>>(12+l.bitshift%7))
		s3 += (uint64)((*(*uint64)(unsafe.Pointer(&l.state11))) << 11 >> (12 + l.bitshift%7))
		s4 := (uint64)((*(*uint64)(unsafe.Pointer(&l.state7)))<<11>>(12+l.bitshift%7)) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state8)))<<11>>(12+l.bitshift%7))
		s4 += (uint64)((*(*uint64)(unsafe.Pointer(&l.state12))) << 11 >> (12 + l.bitshift%7))
		seed := [4]uint64{s1 ^ s4, s2 ^ s1, s3 ^ s2, s4 ^ s3}
		l.bitshift++
		l.seedr(seed)
	default:
		l.state1 = 1.0 - newstate2
		l.state2 = l.state12
		l.state3 = 1.0 - newstate4
		l.state4 = l.state11
		l.state5 = 1.0 - newstate6
		l.state6 = l.state10
		l.state7 = 1.0 - newstate8
		l.state8 = l.state9
		l.state9 = 1.0 - newstate1
		l.state10 = 1.0 - newstate7
		l.state11 = 1.0 - newstate5
		l.state12 = 1.0 - newstate3
	}

	l.bitshift = (l.bitshift + 1) % 21

	tmp := l.state[0]
	l.state[0] = l.state[1] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<11>>(12+l.bitshift)))
	l.state[1] = l.state[2] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<11>>(12+l.bitshift)))
	l.state[2] = l.state[3] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state4)))<<11>>(12+l.bitshift)))
	l.state[3] = l.state[4] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state4)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<11>>(12+l.bitshift)))

	l.bitshift++
	l.state[4] = (l.state[5] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<11>>(12+l.bitshift)))) ^ l.state[18]
	l.state[5] = (l.state[6] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<11>>(12+l.bitshift)))) ^ l.state[19]
	l.state[6] = (l.state[7] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state4)))<<11>>(12+l.bitshift)))) ^ l.state[16]

	l.bitshift++
	l.state[7] = (l.state[8] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<11>>(12+l.bitshift)))) ^ l.state[16]
	l.state[8] = (l.state[9] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<11>>(12+l.bitshift)))) ^ l.state[17]
	l.state[9] = (l.state[10] ^ (uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state4)))<<11>>(12+l.bitshift))) ^ l.state[18]

	l.bitshift++
	l.state[10] = (l.state[11] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<11>>(12+l.bitshift)))) ^ l.state[16]
	l.state[11] = (l.state[12] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state4)))<<11>>(12+l.bitshift)))) ^ l.state[17]
	l.state[12] = (l.state[13] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<11>>(12+l.bitshift)))) ^ l.state[18]

	l.bitshift++
	l.state[13] = (l.state[14] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state4)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<11>>(12+l.bitshift)))) ^ l.state[19]
	l.state[14] = (l.state[15] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state4)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<11>>(12+l.bitshift)))) ^ l.state[16]
	l.state[15] = (l.state[16] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state4)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<11>>(12+l.bitshift)))) ^ l.state[17]

	l.bitshift = (l.bitshift + 1) % 21

	l.state[16] = l.state[17] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<11>>(12+l.bitshift)))
	l.state[17] = l.state[18] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<11>>(12+l.bitshift)))
	l.state[18] = l.state[19] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state4)))<<11>>(12+l.bitshift)))
	l.state[19] = l.state[20] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state4)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<11>>(12+l.bitshift)))

	l.bitshift++
	l.state[20] = (l.state[21] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<11>>(12+l.bitshift)))) ^ l.state[2]
	l.state[21] = (l.state[22] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<11>>(12+l.bitshift)))) ^ l.state[3]
	l.state[22] = (l.state[23] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state4)))<<11>>(12+l.bitshift)))) ^ l.state[0]

	l.bitshift++
	l.state[23] = (l.state[24] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<11>>(12+l.bitshift)))) ^ l.state[1]
	l.state[24] = (l.state[25] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<11>>(12+l.bitshift)))) ^ l.state[2]
	l.state[25] = (l.state[26] ^ (uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state4)))<<11>>(12+l.bitshift))) ^ l.state[3]

	l.bitshift++
	l.state[26] = (l.state[27] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<11>>(12+l.bitshift)))) ^ l.state[0]
	l.state[27] = (l.state[28] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state4)))<<11>>(12+l.bitshift)))) ^ l.state[1]
	l.state[28] = (l.state[29] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<11>>(12+l.bitshift)))) ^ l.state[2]

	l.bitshift++
	l.state[29] = (l.state[30] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state4)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<11>>(12+l.bitshift)))) ^ l.state[3]
	l.state[30] = (l.state[31] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state4)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<11>>(12+l.bitshift)))) ^ l.state[0]
	l.state[31] = (tmp ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state4)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<11>>(12+l.bitshift)))) ^ l.state[1]

}

// isSeeded checks if the prng had been seeded
// and returns bool
func (l *Breeze256) isSeeded() bool {
	for _, v := range l.state {
		if v > 0 {
			return true
		}
	}
	return false
}

// RandIntn returns an uint64 from the outputstate byte register
// calling ByteMP to become thread/multiprocessing safe
func (l *Breeze256) RandIntn() (ri uint64) {
	if !l.isSeeded() {
		return ri
	}
	var byt uint8
	for i := 0; i < 8; i++ {
		l.ByteMP(&byt)
		ri = ri<<8 + uint64(byt)
	}
	return ri
}

// RandDbl returns a positive float64 [0,1) (from an uint64 deriving from outputstate byte register)
// calls RandIntn to be thread/multiprocessing safe
// RandDbl returns are uniform distributed
func (l *Breeze256) RandDbl() float64 {
	if !l.isSeeded() {
		return float64(0)
	}
	rd := float64(l.RandIntn()) / float64(1<<64)
	switch rd {
	case 1:
		return float64(0)
	default:
		return rd
	}
}

// RandNorm returns a positive float64 [0,1) calculating the mean of 3 internal LM states
// and calls a roundTrip afterwards
// RandNorm returns are normal (gaussian) distributed
func (l *Breeze256) RandNorm() (rd float64) {
	if !l.isSeeded() {
		return rd
	}
	rd = (l.state1 + l.state2 + l.state3) / 3
	l.roundTrip()
	switch rd {
	case 1:
		return float64(0)
	default:
		return rd
	}
}

// Byte() sets byt to the next Byte from the prng output byte register
// refreshes by calling roundTrip if all registers on the stack had been called once
func (l *Breeze256) Byte(byt *uint8) {
	*byt = (uint8)(*(*uint8)(unsafe.Pointer(uintptr(l.strt) + uintptr(l.idx))))
	switch l.idx {
	case 255:
		l.roundTrip()
		l.idx = 0
	default:
		l.idx++
	}
}

// ByteMP() is the mutex.Locked variant of Byte(): it sets byt to the next Byte from the prng output byte register
// refreshes by calling roundTrip if all registers on the stack had been called once
// ByteMP is thread/multiprocessing safe
func (l *Breeze256) ByteMP(byt *uint8) {
	mutex.Lock()
	*byt = (uint8)(*(*uint8)(unsafe.Pointer(uintptr(l.strt) + uintptr(l.idx))))
	switch l.idx {
	case 255:
		l.roundTrip()
		l.idx = 0
	default:
		l.idx++
	}
	mutex.Unlock()
}

// XOR(out *[]byte, in *[]byte, key *[]byte)
// XOR (re)seeds the prng with key (via SHortHash function) and
// then XORes the bytes of *in with the *prng output register bytes to *out.
// calls roudTrip to refresh the output byte register if it becomes exhausted
// key must have at least 8 Byte length; keys longer than 1000 Bytes might slow down processing through long seeding calculation
func (l *Breeze256) XOR(out *[]byte, in *[]byte, key *[]byte) error {
	_, err := l.ShortHash(*key, 512/8)
	if err != nil {
		return err
	}
	idx := l.idx
	for i, v := range *in {
		(*out)[i] = v ^ (uint8)(*(*uint8)(unsafe.Pointer(uintptr(l.strt) + uintptr(idx))))
		switch idx {
		case 255:
			l.roundTrip()
			idx = 0
		default:
			idx++
		}

	}
	return nil
}

// ShortHash returns a hash from input of lenInBytes length
// input must have at least a length of 8; else returns an error
// (re)seeds the prng with input folded and compressed by sipHash2-4 forld&compress function
// input longer than 1000 Bytes might slow down processing through long seeding calculation
func (l *Breeze256) ShortHash(s interface{}, lenInBytes int) (hash []byte, err error) {
	hash = make([]byte, lenInBytes)
	var pad []byte
	var padLen int
	var seed [4]uint64

	switch s := s.(type) {
	case string:
		if len(s) < 8 {
			return hash, initSeedToShort
		}
		if len(s) > 7 && len(s) < 17 {
			seed1 := foldAndCompress([]byte(s))
			seed = [4]uint64{seed1[0], seed1[1], seed1[0], seed1[1]}
		}
		if len(s) > 16 && len(s) < 32 {
			seed1 := foldAndCompress([]byte(s[0:16]))
			seed2 := foldAndCompress([]byte(s[len(s)-16:]))
			seed = [4]uint64{seed1[0], seed1[1], seed2[0], seed2[1]}
		}
		if len(s) > 31 {
			seed1 := foldAndCompress([]byte(s[0 : len(s)/2]))
			seed2 := foldAndCompress([]byte(s[len(s)/2:]))
			seed = [4]uint64{seed1[0], seed1[1], seed2[0], seed2[1]}
		}
		padLen = 1 + len(s)/lenInBytes
		pad = make([]byte, padLen*lenInBytes)
		copy(pad[len(s)%lenInBytes:], []byte(s))
	case []byte:
		if len(s) < 8 {
			return hash, initSeedToShort
		}
		if len(s) > 7 && len(s) < 17 {
			seed1 := foldAndCompress(s)
			seed = [4]uint64{seed1[0], seed1[1], seed1[0], seed1[1]}
		}
		if len(s) > 16 && len(s) < 32 {
			seed1 := foldAndCompress(s[0:16])
			seed2 := foldAndCompress(s[len(s)-16:])
			seed = [4]uint64{seed1[0], seed1[1], seed2[0], seed2[1]}
		}
		if len(s) > 31 {
			seed1 := foldAndCompress(s[0 : len(s)/2])
			seed2 := foldAndCompress(s[len(s)/2:])
			seed = [4]uint64{seed1[0], seed1[1], seed2[0], seed2[1]}
		}
		padLen = 1 + len(s)/lenInBytes
		pad = make([]byte, padLen*lenInBytes)
		copy(pad[len(s)%lenInBytes:], s)
	default:
		return hash, initSeedErr
	}

	l.seedr(seed)

	copy(hash, pad)
	idx := uintptr(0)
	for i := 0; i < padLen; i++ {
		for ii := 0; ii < lenInBytes; ii++ {
			hash[ii] ^= (pad[i*lenInBytes+ii] ^ (uint8)(*(*uint8)(unsafe.Pointer(uintptr(l.strt) + idx))))
			switch idx {
			case 255:
				l.roundTrip()
				idx = 0
			default:
				idx++
			}
		}
	}

	return hash, nil
}
