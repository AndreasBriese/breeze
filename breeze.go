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
// revision 2014/11/9:
//
// added Breeze512 (16 LMs) to provide length of keyspace: 512bit.
// parenthesis in roundTrip() ()all functions corr; Statenumbers corrected to fit the new scheme
//
// 2014/11/10:
// added BreezeCS128 (4LMs) to provide fast CSPRNG from go/golangs crypto/rand (dev/urandom)
// // Breeze had not been cryptoanalysed.
// // It is definitly not recommended to use Breeze and it's ShortHash() or XOR() functions in particular in any security sensitive or
// // cryptographic context.
//

package breeze

//Version 1.1.1 as of 2014/11/10

import (
	"errors"
	"sync"
	"unsafe"
)

var (
	initSeedErr          = errors.New("Seed type not supported")
	initSeedToShort      = errors.New("Seed string to short")
	initSeedArrayToShort = errors.New("[]uint64 seed must have at least length of 2 (Breeze256) / 4 (Breeze512)")
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
		seed = [2]uint64{uint64(s), 0}
	case int8:
		if s < 0 {
			s = -s
		}
		seed = [2]uint64{uint64(s), 0}
	case int16:
		if s < 0 {
			s = -s
		}
		seed = [2]uint64{uint64(s), 0}
	case int32:
		if s < 0 {
			s = -s
		}
		seed = [2]uint64{uint64(s), 0}
	case int64:
		if s < 0 {
			s = -s
		}
		seed = [2]uint64{uint64(s), 0}
	case uint8:
		seed = [2]uint64{uint64(s), 0}
	case uint16:
		seed = [2]uint64{uint64(s), 0}
	case uint32:
		seed = [2]uint64{uint64(s), 0}
	case uint64:
		seed = [2]uint64{s, 0}
	case []uint64:
		for len(s) > 2 {
			seed[0] ^= s[0]
			seed[1] ^= s[1]
			s = s[2:]
		}
		seed[0] ^= s[0]
		if len(s) == 2 {
			seed[1] ^= s[1]
		}
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
	s1 = (1 << 22) - seed>>43
	s2 = (1 << 23) - seed<<21>>42
	s3 = (1 << 22) - seed<<43>>43
	return s1, s2, s3
}

//
// Breeze 128
//
// implements a cb-prng with four LM
// seeds with two 64bit (uint64) -> four seeds 2**32 + startrounds
// 128 Byte outputState
type Breeze128 struct {
	State          [16]uint64
	State1, State2 float64
	State3, State4 float64
	State5, State6 float64
	bitshift       uint8
	idx            uint8
	strt           unsafe.Pointer
}

// Reset resets to the initial (empty) State
// before initializing.
func (l *Breeze128) Reset() {
	*l = Breeze128{}
}

// Init initializes from user input by calling initr() to process the input to become seeds (seedr(seed)) for the LMs.
// Init reseeds the LMs but it does NOT reset the prng:
//    it seeds based on the previous output States, internal bitshift and idx values
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
// once or more times over the output States
func (l *Breeze128) seedr(seed [2]uint64) {
	s1, s2, s3 := splittr(seed[0])
	s4, s5, s6 := splittr(seed[1])
	startrounds := 17

	l.State1 = 1.0 / float64(s1)
	l.State2 = 1.0 - 1.0/float64(s2)
	l.State3 = 1.0 / float64(s3)
	l.State4 = 1.0 - 1.0/float64(s4)
	l.State5 = 1.0 / float64(s5)
	l.State6 = 1.0 - 1.0/float64(s6)

	for startrounds > 0 {
		l.roundTrip()
		startrounds--
	}
	l.strt = unsafe.Pointer(&l.State[0])

}

// roundTrip calculates the next LMs States
// tests the States to be != 0 (else reseeds from previous States)
// interchanges the States between LMs after 'mirroring them at 1'
// processes the output States from two or more LMs States
// mixin (xoring) in previous output States
// rotates all output States
func (l *Breeze128) roundTrip() {
	newState1 := (1.0 - l.State1)
	newState1 *= 4.0 * l.State1
	newState2 := (1.0 - l.State2)
	newState2 *= 3.999999999 * l.State2
	newState3 := (1.0 - l.State3)
	newState3 *= 3.99999998 * l.State3
	newState4 := (1.0 - l.State4)
	newState4 *= 3.99999997 * l.State4
	// ...
	// newState_n := (1.0 - l.State_n)
	// newState_n *= 3.83 * l.State_n

	switch newState1 * newState2 * newState3 * newState4 {
	case 0:
		s1 := (uint64)((*(*uint64)(unsafe.Pointer(&l.State1)))<<11>>(12+l.bitshift%7)) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State2)))<<11>>(12+l.bitshift%7))
		s1 += (uint64)((*(*uint64)(unsafe.Pointer(&l.State5))) << 11 >> (12 + l.bitshift%7))
		s2 := (uint64)((*(*uint64)(unsafe.Pointer(&l.State3)))<<11>>(12+l.bitshift%7)) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State4)))<<11>>(12+l.bitshift%7))
		s2 += (uint64)((*(*uint64)(unsafe.Pointer(&l.State6))) << 11 >> (12 + l.bitshift%7))
		seed := [2]uint64{s1, s2}
		l.bitshift++
		l.seedr(seed)
	default:
		l.State1 = 1.0 - newState2
		l.State2 = l.State6
		l.State3 = 1.0 - newState4
		l.State4 = l.State5
		l.State5 = 1.0 - newState1
		l.State6 = 1.0 - newState3
	}

	l.bitshift = (l.bitshift + 1) % 21

	tmp := l.State[0]
	l.State[0] = l.State[1] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State1)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State2)))<<11>>(12+l.bitshift)))
	l.State[1] = l.State[2] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State2)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State3)))<<11>>(12+l.bitshift)))
	l.State[2] = l.State[3] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State3)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State4)))<<11>>(12+l.bitshift)))
	l.State[3] = l.State[4] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State4)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State1)))<<11>>(12+l.bitshift)))

	l.bitshift++
	l.State[4] = (l.State[5] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State1)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State2)))<<11>>(12+l.bitshift)))) ^ l.State[2]
	l.State[5] = (l.State[6] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State1)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State3)))<<11>>(12+l.bitshift)))) ^ l.State[3]
	l.State[6] = (l.State[7] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State1)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State4)))<<11>>(12+l.bitshift)))) ^ l.State[0]

	l.bitshift++
	l.State[7] = (l.State[8] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State2)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State1)))<<11>>(12+l.bitshift)))) ^ l.State[1]
	l.State[8] = (l.State[9] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State2)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State3)))<<11>>(12+l.bitshift)))) ^ l.State[2]
	l.State[9] = (l.State[10] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State2)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State4)))<<11>>(12+l.bitshift)))) ^ l.State[3]

	l.bitshift++
	l.State[10] = (l.State[11] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State3)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State2)))<<11>>(12+l.bitshift)))) ^ l.State[0]
	l.State[11] = (l.State[12] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State3)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State4)))<<11>>(12+l.bitshift)))) ^ l.State[1]
	l.State[12] = (l.State[13] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State3)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State1)))<<11>>(12+l.bitshift)))) ^ l.State[2]

	l.bitshift++
	l.State[13] = (l.State[14] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State4)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State1)))<<11>>(12+l.bitshift)))) ^ l.State[3]
	l.State[14] = (l.State[15] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State4)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State2)))<<11>>(12+l.bitshift)))) ^ l.State[0]
	l.State[15] = (tmp ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State4)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State3)))<<11>>(12+l.bitshift)))) ^ l.State[1]

	// obfuscate States 0..3
	tmp = l.State[0]
	l.State[0] ^= l.State[2]
	l.State[1] ^= l.State[3]
	l.State[2] ^= tmp
	l.State[3] ^= l.State[1]

}

// isSeeded checks if the prng had been seeded
// and returns bool
func (l *Breeze128) isSeeded() bool {
	for _, v := range l.State {
		if v > 0 {
			return true
		}
	}
	return false
}

// RandIntn returns an uint64 from the outputState byte register
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

// RandDbl returns a positive float64 [0,1) (from an uint64 deriving from outputState byte register)
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

// RandNorm returns a positive float64 [0,1) calculating the mean of 3 internal LM States
// and calls a roundTrip afterwards
// RandNorm returns are normal (gaussian) distributed
func (l *Breeze128) RandNorm() (rd float64) {
	if !l.isSeeded() {
		return rd
	}
	rd = (l.State1 + l.State2 + l.State3) / 3
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
			return hash, initSeedArrayToShort
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
// 256 Byte outputState
type Breeze256 struct {
	State                     [32]uint64
	State1, State2, State3    float64
	State4, State5, State6    float64
	State7, State8, State9    float64
	State10, State11, State12 float64
	bitshift                  uint8
	idx                       uint8
	strt                      unsafe.Pointer
}

// Reset resets to the initial (empty) State
// before initializing.
func (l *Breeze256) Reset() {
	*l = Breeze256{}
}

// Init initializes from user input by calling initr() to process the input to become seeds (seedr(seed)) for the LMs.
// Init reseeds the LMs but it does NOT reset the prng:
//    it seeds based on the previous output States, internal bitshift and idx values
// Make sure, you Init with at minimum [2]uint64
func (l *Breeze256) Init(s interface{}) (err error) {
	var seed [4]uint64
	switch s := s.(type) {
	case string:
		if len(s) < 8 {
			return initSeedToShort
		}
		if len(s) > 7 && len(s) < 17 {
			seed1 := foldAndCompress([]byte(s))
			seed = [4]uint64{seed1[0], seed1[1], uint64(0), uint64(0)}
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
			return initSeedArrayToShort
		}
		if len(s) > 7 && len(s) < 17 {
			seed1 := foldAndCompress(s)
			seed = [4]uint64{seed1[0], seed1[1], uint64(0), uint64(0)}
		}
		if len(s) > 16 && len(s) < 32 {
			seed1 := foldAndCompress(s[0:16])
			seed2 := foldAndCompress(s[len(s)-16:])
			seed = [4]uint64{seed1[0], seed1[1], seed2[0], seed2[1]}
		}
		if len(s) > 31 {
			seed1 := foldAndCompress([]byte(s[0 : len(s)/2]))
			seed2 := foldAndCompress([]byte(s[len(s)/2:]))
			seed = [4]uint64{seed1[0], seed1[1], seed2[0], seed2[1]}
		}
	case []uint64:
		if len(s) < 2 {
			return initSeedArrayToShort
		}
		copy(seed[0:], s[0:])
	default:
		return initSeedErr
	}
	l.seedr(seed)
	return nil
}

// seedr calculates the startvalues of the LMs and
// calls for the initial 'startrounds' roundtrips to shift circle
// once or more times over the output States
func (l *Breeze256) seedr(seed [4]uint64) {
	s1, s2, s3 := splittr(seed[0])
	s4, s5, s6 := splittr(seed[1])
	s7, s8, s9 := splittr(seed[2])
	s10, s11, s12 := splittr(seed[3])
	startrounds := 37

	l.State1 = 1.0 / float64(s1)
	l.State2 = 1.0 - 1.0/float64(s2)
	l.State3 = 1.0 / float64(s3)
	l.State4 = 1.0 - 1.0/float64(s4)
	l.State5 = 1.0 / float64(s5)
	l.State6 = 1.0 - 1.0/float64(s6)
	l.State7 = 1.0 / float64(s7)
	l.State8 = 1.0 - 1.0/float64(s8)
	l.State9 = 1.0 / float64(s9)
	l.State10 = 1.0 - 1.0/float64(s10)
	l.State11 = 1.0 / float64(s11)
	l.State12 = 1.0 - 1.0/float64(s12)

	for startrounds > 0 {
		l.roundTrip()
		startrounds--
	}
	l.strt = unsafe.Pointer(&l.State[0])

}

// roundTrip calculates the next LMs States
// tests the States to be != 0 (else reseeds from previous States)
// interchanges the States between LMs after 'mirroring them at 1'
// processes the output States from two or more LMs States
// mixin (xoring) in previous output States
// rotates all output States
func (l *Breeze256) roundTrip() {
	newState1 := (1.0 - l.State1)
	newState1 *= 3.999999999 * l.State1
	newState2 := (1.0 - l.State2)
	newState2 *= 3.999999998 * l.State2
	newState3 := (1.0 - l.State3)
	newState3 *= 3.999999997 * l.State3
	newState4 := (1.0 - l.State4)
	newState4 *= 3.999999996 * l.State4
	newState5 := (1.0 - l.State5)
	newState5 *= 3.99999999 * l.State5
	newState6 := (1.0 - l.State6)
	newState6 *= 3.99999998 * l.State6
	newState7 := (1.0 - l.State7)
	newState7 *= 3.99999997 * l.State7
	newState8 := (1.0 - l.State8)
	newState8 *= 3.99999996 * l.State8
	// ...
	// newState_n := (1.0 - l.State_n)
	// newState_n *= 3.83 * l.State_n

	switch newState1 * newState2 * newState3 * newState4 * newState5 * newState6 * newState7 * newState8 {
	case 0:
		s1 := (uint64)((*(*uint64)(unsafe.Pointer(&l.State1)))<<11>>(12+l.bitshift%7)) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State2)))<<11>>(12+l.bitshift%7))
		s1 += (uint64)((*(*uint64)(unsafe.Pointer(&l.State9))) << 11 >> (12 + l.bitshift%7))
		s2 := (uint64)((*(*uint64)(unsafe.Pointer(&l.State3)))<<11>>(12+l.bitshift%7)) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State4)))<<11>>(12+l.bitshift%7))
		s2 += (uint64)((*(*uint64)(unsafe.Pointer(&l.State10))) << 11 >> (12 + l.bitshift%7))
		s3 := (uint64)((*(*uint64)(unsafe.Pointer(&l.State5)))<<11>>(12+l.bitshift%7)) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State6)))<<11>>(12+l.bitshift%7))
		s3 += (uint64)((*(*uint64)(unsafe.Pointer(&l.State11))) << 11 >> (12 + l.bitshift%7))
		s4 := (uint64)((*(*uint64)(unsafe.Pointer(&l.State7)))<<11>>(12+l.bitshift%7)) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State8)))<<11>>(12+l.bitshift%7))
		s4 += (uint64)((*(*uint64)(unsafe.Pointer(&l.State12))) << 11 >> (12 + l.bitshift%7))
		seed := [4]uint64{s1 ^ s4, s2 ^ s1, s3 ^ s2, s4 ^ s3}
		l.bitshift++
		l.seedr(seed)
	default:
		l.State1 = 1.0 - newState2
		l.State2 = l.State12
		l.State3 = 1.0 - newState4
		l.State4 = l.State11
		l.State5 = 1.0 - newState6
		l.State6 = l.State10
		l.State7 = 1.0 - newState8
		l.State8 = l.State9
		l.State9 = 1.0 - newState1
		l.State10 = 1.0 - newState7
		l.State11 = 1.0 - newState5
		l.State12 = 1.0 - newState3
	}

	l.bitshift = (l.bitshift + 1) % 21

	tmp := l.State[0]
	l.State[0] = l.State[1] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State1)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State2)))<<11>>(12+l.bitshift)))
	l.State[1] = l.State[2] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State2)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State3)))<<11>>(12+l.bitshift)))
	l.State[2] = l.State[3] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State3)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State4)))<<11>>(12+l.bitshift)))
	l.State[3] = l.State[4] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State4)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State1)))<<11>>(12+l.bitshift)))

	l.State[16] = l.State[17] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State5)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State6)))<<11>>(12+l.bitshift)))
	l.State[17] = l.State[18] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State6)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State7)))<<11>>(12+l.bitshift)))
	l.State[18] = l.State[19] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State7)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State8)))<<11>>(12+l.bitshift)))
	l.State[19] = l.State[20] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State8)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State5)))<<11>>(12+l.bitshift)))

	l.bitshift++
	l.State[4] = (l.State[5] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State1)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State2)))<<11>>(12+l.bitshift)))) ^ l.State[18]
	l.State[5] = (l.State[6] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State1)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State3)))<<11>>(12+l.bitshift)))) ^ l.State[19]
	l.State[6] = (l.State[7] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State1)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State4)))<<11>>(12+l.bitshift)))) ^ l.State[16]

	l.bitshift++
	l.State[7] = (l.State[8] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State2)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State1)))<<11>>(12+l.bitshift)))) ^ l.State[16]
	l.State[8] = (l.State[9] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State2)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State3)))<<11>>(12+l.bitshift)))) ^ l.State[17]
	l.State[9] = (l.State[10] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State2)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State4)))<<11>>(12+l.bitshift)))) ^ l.State[18]

	l.bitshift++
	l.State[10] = (l.State[11] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State3)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State2)))<<11>>(12+l.bitshift)))) ^ l.State[16]
	l.State[11] = (l.State[12] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State3)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State4)))<<11>>(12+l.bitshift)))) ^ l.State[17]
	l.State[12] = (l.State[13] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State3)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State1)))<<11>>(12+l.bitshift)))) ^ l.State[18]

	l.bitshift++
	l.State[13] = (l.State[14] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State4)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State1)))<<11>>(12+l.bitshift)))) ^ l.State[19]
	l.State[14] = (l.State[15] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State4)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State2)))<<11>>(12+l.bitshift)))) ^ l.State[16]
	l.State[15] = (l.State[16] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State4)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State3)))<<11>>(12+l.bitshift)))) ^ l.State[17]

	l.bitshift = (l.bitshift + 1) % 21

	l.bitshift++
	l.State[20] = (l.State[21] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State5)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State6)))<<11>>(12+l.bitshift)))) ^ l.State[2]
	l.State[21] = (l.State[22] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State5)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State7)))<<11>>(12+l.bitshift)))) ^ l.State[3]
	l.State[22] = (l.State[23] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State5)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State8)))<<11>>(12+l.bitshift)))) ^ l.State[0]

	l.bitshift++
	l.State[23] = (l.State[24] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State6)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State5)))<<11>>(12+l.bitshift)))) ^ l.State[1]
	l.State[24] = (l.State[25] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State6)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State7)))<<11>>(12+l.bitshift)))) ^ l.State[2]
	l.State[25] = (l.State[26] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State6)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State8)))<<11>>(12+l.bitshift)))) ^ l.State[3]

	l.bitshift++
	l.State[26] = (l.State[27] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State7)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State6)))<<11>>(12+l.bitshift)))) ^ l.State[0]
	l.State[27] = (l.State[28] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State7)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State8)))<<11>>(12+l.bitshift)))) ^ l.State[1]
	l.State[28] = (l.State[29] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State7)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State5)))<<11>>(12+l.bitshift)))) ^ l.State[2]

	l.bitshift++
	l.State[29] = (l.State[30] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State8)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State5)))<<11>>(12+l.bitshift)))) ^ l.State[3]
	l.State[30] = (l.State[31] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State8)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State6)))<<11>>(12+l.bitshift)))) ^ l.State[0]
	l.State[31] = (tmp ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State8)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State7)))<<11>>(12+l.bitshift)))) ^ l.State[1]

	// obfuscate States 0..3 16..19
	tmp = l.State[0]
	l.State[0] ^= l.State[16]
	l.State[16] ^= l.State[1]
	l.State[1] ^= l.State[17]
	l.State[17] ^= l.State[2]
	l.State[2] ^= l.State[18]
	l.State[18] ^= l.State[3]
	l.State[3] ^= l.State[19]
	l.State[19] ^= tmp

}

// isSeeded checks if the prng had been seeded
// and returns bool
func (l *Breeze256) isSeeded() bool {
	for _, v := range l.State {
		if v > 0 {
			return true
		}
	}
	return false
}

// RandIntn returns an uint64 from the outputState byte register
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

// RandDbl returns a positive float64 [0,1) (from an uint64 deriving from outputState byte register)
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

// RandNorm returns a positive float64 [0,1) calculating the mean of 3 internal LM States
// and calls a roundTrip afterwards
// RandNorm returns are normal (gaussian) distributed
func (l *Breeze256) RandNorm() (rd float64) {
	if !l.isSeeded() {
		return rd
	}
	rd = (l.State1 + l.State2 + l.State3) / 3
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
			seed = [4]uint64{seed1[0], seed1[1], 0, 0}
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
			return hash, initSeedArrayToShort
		}
		if len(s) > 7 && len(s) < 17 {
			seed1 := foldAndCompress(s)
			seed = [4]uint64{seed1[0], seed1[1], 0, 0}
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

//
// Breeze 512
//
// implements a cb-prng with 16 LM
// seeds with eight 64bit (uint64) -> 24 seeds 22/23 bit
// 512 Byte outputState
type Breeze512 struct {
	State                     [64]uint64
	State1, State2, State3    float64
	State4, State5, State6    float64
	State7, State8, State9    float64
	State10, State11, State12 float64
	State13, State14, State15 float64
	State16, State17, State18 float64
	State19, State20, State21 float64
	State22, State23, State24 float64
	bitshift                  uint8
	idx                       uint16
	strt                      unsafe.Pointer
}

// Reset resets to the initial (empty) State
// before initializing.
func (l *Breeze512) Reset() {
	*l = Breeze512{}
}

// Init initializes from user input by calling initr() to process the input to become seeds (seedr(seed)) for the LMs.
// Init reseeds the LMs but it does NOT reset the prng:
//    it seeds based on the previous output States, internal bitshift and idx values
// Make sure, you Init with at minimum [4]uint64
func (l *Breeze512) Init(s interface{}) (err error) {
	var seed [8]uint64
	switch s := s.(type) {
	case string:
		if len(s) < 16 {
			return initSeedToShort
		}
		if len(s) > 16 && len(s) < 32 {
			seed1 := foldAndCompress([]byte(s[0:16]))
			seed2 := foldAndCompress([]byte(s[len(s)-16:]))
			seed = [8]uint64{seed1[0], seed1[1], seed2[0], seed2[1], 0, 0, 0, 0}
		}
		if len(s) > 31 && len(s) < 48 {
			seed1 := foldAndCompress([]byte(s[0:16]))
			seed2 := foldAndCompress([]byte(s[16:32]))
			seed3 := foldAndCompress([]byte(s[len(s)-16:]))
			seed = [8]uint64{seed1[0], seed1[1], seed2[0], seed2[1], seed3[0], seed3[1], 0, 0}
		}
		if len(s) > 47 && len(s) < 64 {
			seed1 := foldAndCompress([]byte(s[0:16]))
			seed2 := foldAndCompress([]byte(s[16:32]))
			seed3 := foldAndCompress([]byte(s[32:48]))
			seed4 := foldAndCompress([]byte(s[len(s)-16:]))
			seed = [8]uint64{seed1[0], seed1[1], seed2[0], seed2[1], seed3[0], seed3[1], seed4[0], seed4[1]}
		}
		if len(s) > 63 {
			l := len(s) / 4
			seed1 := foldAndCompress([]byte(s[0:l]))
			seed2 := foldAndCompress([]byte(s[l : 2*l]))
			seed3 := foldAndCompress([]byte(s[2*l : 3*l]))
			seed4 := foldAndCompress([]byte(s[3*l:]))
			seed = [8]uint64{seed1[0], seed1[1], seed2[0], seed2[1], seed3[0], seed3[1], seed4[0], seed4[1]}
		}
	case []byte:
		if len(s) < 16 {
			return initSeedArrayToShort
		}
		if len(s) > 16 && len(s) < 32 {
			seed1 := foldAndCompress(s[0:16])
			seed2 := foldAndCompress(s[len(s)-16:])
			seed = [8]uint64{seed1[0], seed1[1], seed2[0], seed2[1], 0, 0, 0, 0}
		}
		if len(s) > 31 && len(s) < 48 {
			seed1 := foldAndCompress(s[0:16])
			seed2 := foldAndCompress(s[16:32])
			seed3 := foldAndCompress(s[len(s)-16:])
			seed = [8]uint64{seed1[0], seed1[1], seed2[0], seed2[1], seed3[0], seed3[1], 0, 0}
		}
		if len(s) > 47 && len(s) < 64 {
			seed1 := foldAndCompress(s[0:16])
			seed2 := foldAndCompress(s[16:32])
			seed3 := foldAndCompress(s[32:48])
			seed4 := foldAndCompress(s[len(s)-16:])
			seed = [8]uint64{seed1[0], seed1[1], seed2[0], seed2[1], seed3[0], seed3[1], seed4[0], seed4[1]}
		}
		if len(s) > 63 {
			l := len(s) / 4
			seed1 := foldAndCompress(s[0:l])
			seed2 := foldAndCompress(s[l : 2*l])
			seed3 := foldAndCompress(s[2*l : 3*l])
			seed4 := foldAndCompress(s[3*l:])
			seed = [8]uint64{seed1[0], seed1[1], seed2[0], seed2[1], seed3[0], seed3[1], seed4[0], seed4[1]}
		}
	case []uint64:
		if len(s) < 4 {
			return initSeedArrayToShort
		}
		copy(seed[0:], s[0:])
	default:
		return initSeedErr
	}
	l.seedr(seed)
	return nil
}

// seedr calculates the startvalues of the LMs and
// calls for the initial 'startrounds' roundtrips to shift circle
// once or more times over the output States
func (l *Breeze512) seedr(seed [8]uint64) {
	s1, s2, s3 := splittr(seed[0])
	s4, s5, s6 := splittr(seed[1])
	s7, s8, s9 := splittr(seed[2])
	s10, s11, s12 := splittr(seed[3])
	s13, s14, s15 := splittr(seed[4])
	s16, s17, s18 := splittr(seed[5])
	s19, s20, s21 := splittr(seed[6])
	s22, s23, s24 := splittr(seed[7])
	startrounds := 67

	l.State1 = 1.0 / float64(s1)
	l.State2 = 1.0 - 1.0/float64(s2)
	l.State3 = 1.0 / float64(s3)
	l.State4 = 1.0 - 1.0/float64(s4)
	l.State5 = 1.0 / float64(s5)
	l.State6 = 1.0 - 1.0/float64(s6)
	l.State7 = 1.0 / float64(s7)
	l.State8 = 1.0 - 1.0/float64(s8)
	l.State9 = 1.0 / float64(s9)
	l.State10 = 1.0 - 1.0/float64(s10)
	l.State11 = 1.0 / float64(s11)
	l.State12 = 1.0 - 1.0/float64(s12)

	l.State13 = 1.0 / float64(s13)
	l.State14 = 1.0 - 1.0/float64(s14)
	l.State15 = 1.0 / float64(s15)
	l.State16 = 1.0 - 1.0/float64(s16)
	l.State17 = 1.0 / float64(s17)
	l.State18 = 1.0 - 1.0/float64(s18)
	l.State19 = 1.0 / float64(s19)
	l.State20 = 1.0 - 1.0/float64(s20)
	l.State21 = 1.0 / float64(s21)
	l.State22 = 1.0 - 1.0/float64(s22)
	l.State23 = 1.0 / float64(s23)
	l.State24 = 1.0 - 1.0/float64(s24)

	for startrounds > 0 {
		l.roundTrip()
		startrounds--
	}
	l.strt = unsafe.Pointer(&l.State[0])

}

// roundTrip calculates the next LMs States
// tests the States to be != 0 (else reseeds from previous States)
// interchanges the States between LMs after 'mirroring them at 1'
// processes the output States from two or more LMs States
// mixin (xoring) in previous output States
// rotates all output States
func (l *Breeze512) roundTrip() {
	newState1 := (1.0 - l.State1)
	newState1 *= 3.901 * l.State1
	newState2 := (1.0 - l.State2)
	newState2 *= 3.902 * l.State2
	newState3 := (1.0 - l.State3)
	newState3 *= 3.903 * l.State3
	newState4 := (1.0 - l.State4)
	newState4 *= 3.904 * l.State4
	newState5 := (1.0 - l.State5)
	newState5 *= 3.905 * l.State5
	newState6 := (1.0 - l.State6)
	newState6 *= 3.906 * l.State6
	newState7 := (1.0 - l.State7)
	newState7 *= 3.907 * l.State7
	newState8 := (1.0 - l.State8)
	newState8 *= 3.908 * l.State8
	newState9 := (1.0 - l.State9)
	newState9 *= 3.909 * l.State9
	newState10 := (1.0 - l.State10)
	newState10 *= 3.918 * l.State10
	newState11 := (1.0 - l.State11)
	newState11 *= 3.917 * l.State11
	newState12 := (1.0 - l.State12)
	newState12 *= 3.916 * l.State12
	newState13 := (1.0 - l.State13)
	newState13 *= 3.939 * l.State13
	newState14 := (1.0 - l.State14)
	newState14 *= 3.948 * l.State14
	newState15 := (1.0 - l.State15)
	newState15 *= 3.958 * l.State15
	newState16 := (1.0 - l.State16)
	newState16 *= 3.967 * l.State16
	// ...
	// newState_n := (1.0 - l.State_n)
	// newState_n *= 3.83 * l.State_n

	switch newState1 * newState2 * newState3 * newState4 * newState5 * newState6 * newState7 * newState8 * newState9 * newState10 * newState11 * newState12 * newState13 * newState14 * newState15 * newState16 {
	case 0:
		s1 := (uint64)((*(*uint64)(unsafe.Pointer(&l.State1)))<<11>>(12+l.bitshift%7)) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State2)))<<11>>(12+l.bitshift%7))
		s1 += (uint64)((*(*uint64)(unsafe.Pointer(&l.State9))) << 11 >> (12 + l.bitshift%7))
		s2 := (uint64)((*(*uint64)(unsafe.Pointer(&l.State3)))<<11>>(12+l.bitshift%7)) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State4)))<<11>>(12+l.bitshift%7))
		s2 += (uint64)((*(*uint64)(unsafe.Pointer(&l.State10))) << 11 >> (12 + l.bitshift%7))
		s3 := (uint64)((*(*uint64)(unsafe.Pointer(&l.State5)))<<11>>(12+l.bitshift%7)) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State6)))<<11>>(12+l.bitshift%7))
		s3 += (uint64)((*(*uint64)(unsafe.Pointer(&l.State11))) << 11 >> (12 + l.bitshift%7))
		s4 := (uint64)((*(*uint64)(unsafe.Pointer(&l.State7)))<<11>>(12+l.bitshift%7)) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State8)))<<11>>(12+l.bitshift%7))
		s4 += (uint64)((*(*uint64)(unsafe.Pointer(&l.State12))) << 11 >> (12 + l.bitshift%7))

		s5 := (uint64)((*(*uint64)(unsafe.Pointer(&l.State13)))<<11>>(12+l.bitshift%7)) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State14)))<<11>>(12+l.bitshift%7))
		s5 += (uint64)((*(*uint64)(unsafe.Pointer(&l.State21))) << 11 >> (12 + l.bitshift%7))
		s6 := (uint64)((*(*uint64)(unsafe.Pointer(&l.State15)))<<11>>(12+l.bitshift%7)) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State16)))<<11>>(12+l.bitshift%7))
		s6 += (uint64)((*(*uint64)(unsafe.Pointer(&l.State22))) << 11 >> (12 + l.bitshift%7))
		s7 := (uint64)((*(*uint64)(unsafe.Pointer(&l.State17)))<<11>>(12+l.bitshift%7)) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State18)))<<11>>(12+l.bitshift%7))
		s7 += (uint64)((*(*uint64)(unsafe.Pointer(&l.State23))) << 11 >> (12 + l.bitshift%7))
		s8 := (uint64)((*(*uint64)(unsafe.Pointer(&l.State19)))<<11>>(12+l.bitshift%7)) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State20)))<<11>>(12+l.bitshift%7))
		s8 += (uint64)((*(*uint64)(unsafe.Pointer(&l.State24))) << 11 >> (12 + l.bitshift%7))
		seed := [8]uint64{s1 ^ s4, s2 ^ s1, s3 ^ s2, s4 ^ s3, s5 ^ s8, s6 ^ s5, s7 ^ s6, s8 ^ s7}
		l.bitshift++
		l.seedr(seed)
	default:
		l.State1 = 1.0 - newState2
		l.State2 = l.State24
		l.State3 = 1.0 - newState4
		l.State4 = l.State23
		l.State5 = 1.0 - newState6
		l.State6 = l.State22
		l.State7 = 1.0 - newState8
		l.State8 = l.State21
		l.State9 = 1.0 - newState10
		l.State10 = l.State20
		l.State11 = 1.0 - newState12
		l.State12 = l.State19
		l.State13 = 1.0 - newState14
		l.State14 = l.State18
		l.State15 = 1.0 - newState16
		l.State16 = l.State17

		l.State17 = 1.0 - newState1
		l.State18 = 1.0 - newState15
		l.State19 = 1.0 - newState13
		l.State20 = 1.0 - newState11
		l.State21 = 1.0 - newState9
		l.State22 = 1.0 - newState7
		l.State23 = 1.0 - newState5
		l.State24 = 1.0 - newState3
	}

	l.bitshift = (l.bitshift + 1) % 21

	tmp := l.State[0]
	l.State[0] = l.State[1] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State1)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State2)))<<11>>(12+l.bitshift)))
	l.State[1] = l.State[2] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State2)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State3)))<<11>>(12+l.bitshift)))
	l.State[2] = l.State[3] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State3)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State4)))<<11>>(12+l.bitshift)))
	l.State[3] = l.State[4] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State4)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State1)))<<11>>(12+l.bitshift)))

	l.State[16] = l.State[17] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State5)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State6)))<<11>>(12+l.bitshift)))
	l.State[17] = l.State[18] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State6)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State7)))<<11>>(12+l.bitshift)))
	l.State[18] = l.State[19] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State7)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State8)))<<11>>(12+l.bitshift)))
	l.State[19] = l.State[20] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State8)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State5)))<<11>>(12+l.bitshift)))

	l.bitshift++
	l.State[4] = (l.State[5] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State1)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State2)))<<11>>(12+l.bitshift)))) ^ l.State[18]
	l.State[5] = (l.State[6] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State1)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State3)))<<11>>(12+l.bitshift)))) ^ l.State[19]
	l.State[6] = (l.State[7] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State1)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State4)))<<11>>(12+l.bitshift)))) ^ l.State[16]

	l.bitshift++
	l.State[7] = (l.State[8] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State2)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State1)))<<11>>(12+l.bitshift)))) ^ l.State[16]
	l.State[8] = (l.State[9] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State2)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State3)))<<11>>(12+l.bitshift)))) ^ l.State[17]
	l.State[9] = (l.State[10] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State2)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State4)))<<11>>(12+l.bitshift)))) ^ l.State[18]

	l.bitshift++
	l.State[10] = (l.State[11] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State3)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State2)))<<11>>(12+l.bitshift)))) ^ l.State[16]
	l.State[11] = (l.State[12] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State3)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State4)))<<11>>(12+l.bitshift)))) ^ l.State[17]
	l.State[12] = (l.State[13] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State3)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State1)))<<11>>(12+l.bitshift)))) ^ l.State[18]

	l.bitshift++
	l.State[13] = (l.State[14] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State4)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State1)))<<11>>(12+l.bitshift)))) ^ l.State[19]
	l.State[14] = (l.State[15] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State4)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State2)))<<11>>(12+l.bitshift)))) ^ l.State[16]
	l.State[15] = (l.State[16] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State4)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State3)))<<11>>(12+l.bitshift)))) ^ l.State[17]

	l.bitshift = (l.bitshift + 1) % 21

	l.bitshift++
	l.State[20] = (l.State[21] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State5)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State6)))<<11>>(12+l.bitshift)))) ^ l.State[2]
	l.State[21] = (l.State[22] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State5)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State7)))<<11>>(12+l.bitshift)))) ^ l.State[3]
	l.State[22] = (l.State[23] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State5)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State8)))<<11>>(12+l.bitshift)))) ^ l.State[0]

	l.bitshift++
	l.State[23] = (l.State[24] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State6)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State5)))<<11>>(12+l.bitshift)))) ^ l.State[1]
	l.State[24] = (l.State[25] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State6)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State7)))<<11>>(12+l.bitshift)))) ^ l.State[2]
	l.State[25] = (l.State[26] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State6)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State8)))<<11>>(12+l.bitshift)))) ^ l.State[3]

	l.bitshift++
	l.State[26] = (l.State[27] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State7)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State6)))<<11>>(12+l.bitshift)))) ^ l.State[0]
	l.State[27] = (l.State[28] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State7)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State8)))<<11>>(12+l.bitshift)))) ^ l.State[1]
	l.State[28] = (l.State[29] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State7)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State5)))<<11>>(12+l.bitshift)))) ^ l.State[2]

	l.bitshift++
	l.State[29] = (l.State[30] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State8)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State5)))<<11>>(12+l.bitshift)))) ^ l.State[3]
	l.State[30] = (l.State[31] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State8)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State6)))<<11>>(12+l.bitshift)))) ^ l.State[0]
	l.State[31] = (tmp ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State8)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State7)))<<11>>(12+l.bitshift)))) ^ l.State[1]

	// obfuscate States 0..3 16..19
	tmp = l.State[0]
	l.State[0] ^= l.State[16]
	l.State[16] ^= l.State[1]
	l.State[1] ^= l.State[17]
	l.State[17] ^= l.State[2]
	l.State[2] ^= l.State[18]
	l.State[18] ^= l.State[3]
	l.State[3] ^= l.State[19]
	l.State[19] ^= tmp

	l.bitshift = (l.bitshift + 1) % 21

	tmp = l.State[32]
	l.State[32] = l.State[33] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State9)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State10)))<<11>>(12+l.bitshift)))
	l.State[33] = l.State[34] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State10)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State11)))<<11>>(12+l.bitshift)))
	l.State[34] = l.State[35] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State11)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State12)))<<11>>(12+l.bitshift)))
	l.State[35] = l.State[36] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State12)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State9)))<<11>>(12+l.bitshift)))

	l.State[48] = l.State[49] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State13)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State14)))<<11>>(12+l.bitshift)))
	l.State[49] = l.State[50] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State14)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State15)))<<11>>(12+l.bitshift)))
	l.State[50] = l.State[51] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State15)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State16)))<<11>>(12+l.bitshift)))
	l.State[51] = l.State[52] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State16)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State13)))<<11>>(12+l.bitshift)))

	l.bitshift++
	l.State[36] = (l.State[37] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State9)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State10)))<<11>>(12+l.bitshift)))) ^ l.State[50]
	l.State[37] = (l.State[38] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State9)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State11)))<<11>>(12+l.bitshift)))) ^ l.State[51]
	l.State[38] = (l.State[39] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State9)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State12)))<<11>>(12+l.bitshift)))) ^ l.State[48]

	l.bitshift++
	l.State[39] = (l.State[40] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State10)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State9)))<<11>>(12+l.bitshift)))) ^ l.State[49]
	l.State[40] = (l.State[41] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State10)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State11)))<<11>>(12+l.bitshift)))) ^ l.State[50]
	l.State[41] = (l.State[42] ^ (uint64)((*(*uint64)(unsafe.Pointer(&l.State10)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State12)))<<11>>(12+l.bitshift))) ^ l.State[51]

	l.bitshift++
	l.State[42] = (l.State[43] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State11)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State10)))<<11>>(12+l.bitshift)))) ^ l.State[48]
	l.State[43] = (l.State[44] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State11)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State12)))<<11>>(12+l.bitshift)))) ^ l.State[49]
	l.State[44] = (l.State[45] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State11)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State9)))<<11>>(12+l.bitshift)))) ^ l.State[50]

	l.bitshift++
	l.State[45] = (l.State[46] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State12)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State9)))<<11>>(12+l.bitshift)))) ^ l.State[51]
	l.State[46] = (l.State[47] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State12)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State10)))<<11>>(12+l.bitshift)))) ^ l.State[48]
	l.State[47] = (l.State[48] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State12)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State11)))<<11>>(12+l.bitshift)))) ^ l.State[49]

	l.bitshift = (l.bitshift + 1) % 21

	l.bitshift++
	l.State[52] = (l.State[53] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State13)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State14)))<<11>>(12+l.bitshift)))) ^ l.State[34]
	l.State[53] = (l.State[54] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State13)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State15)))<<11>>(12+l.bitshift)))) ^ l.State[35]
	l.State[54] = (l.State[55] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State13)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State16)))<<11>>(12+l.bitshift)))) ^ l.State[32]

	l.bitshift++
	l.State[55] = (l.State[56] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State14)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State13)))<<11>>(12+l.bitshift)))) ^ l.State[33]
	l.State[56] = (l.State[57] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State14)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State15)))<<11>>(12+l.bitshift)))) ^ l.State[34]
	l.State[57] = (l.State[58] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State14)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State16)))<<11>>(12+l.bitshift)))) ^ l.State[35]

	l.bitshift++
	l.State[58] = (l.State[59] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State15)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State14)))<<11>>(12+l.bitshift)))) ^ l.State[32]
	l.State[59] = (l.State[60] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State15)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State16)))<<11>>(12+l.bitshift)))) ^ l.State[33]
	l.State[60] = (l.State[61] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State15)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State13)))<<11>>(12+l.bitshift)))) ^ l.State[34]

	l.bitshift++
	l.State[61] = (l.State[62] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State16)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State13)))<<11>>(12+l.bitshift)))) ^ l.State[35]
	l.State[62] = (l.State[63] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State16)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State14)))<<11>>(12+l.bitshift)))) ^ l.State[32]
	l.State[63] = (tmp ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State16)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State15)))<<11>>(12+l.bitshift)))) ^ l.State[33]

	// obfuscate States 32..35 48..51
	tmp = l.State[32]
	l.State[32] ^= l.State[48]
	l.State[48] ^= l.State[33]
	l.State[33] ^= l.State[49]
	l.State[49] ^= l.State[34]
	l.State[34] ^= l.State[50]
	l.State[50] ^= l.State[35]
	l.State[35] ^= l.State[51]
	l.State[51] ^= tmp

}

// isSeeded checks if the prng had been seeded
// and returns bool
func (l *Breeze512) isSeeded() bool {
	for _, v := range l.State {
		if v > 0 {
			return true
		}
	}
	return false
}

// RandIntn returns an uint64 from the outputState byte register
// calling ByteMP to become thread/multiprocessing safe
func (l *Breeze512) RandIntn() (ri uint64) {
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

// RandDbl returns a positive float64 [0,1) (from an uint64 deriving from outputState byte register)
// calls RandIntn to be thread/multiprocessing safe
// RandDbl returns are uniform distributed
func (l *Breeze512) RandDbl() float64 {
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

// RandNorm returns a positive float64 [0,1) calculating the mean of 3 internal LM States
// and calls a roundTrip afterwards
// RandNorm returns are normal (gaussian) distributed
func (l *Breeze512) RandNorm() (rd float64) {
	if !l.isSeeded() {
		return rd
	}
	rd = (l.State1 + l.State2 + l.State3) / 3
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
func (l *Breeze512) Byte(byt *uint8) {
	*byt = (uint8)(*(*uint8)(unsafe.Pointer(uintptr(l.strt) + uintptr(l.idx))))
	switch l.idx {
	case 511:
		l.roundTrip()
		l.idx = 0
	default:
		l.idx++
	}
}

// ByteMP() is the mutex.Locked variant of Byte(): it sets byt to the next Byte from the prng output byte register
// refreshes by calling roundTrip if all registers on the stack had been called once
// ByteMP is thread/multiprocessing safe
func (l *Breeze512) ByteMP(byt *uint8) {
	mutex.Lock()
	*byt = (uint8)(*(*uint8)(unsafe.Pointer(uintptr(l.strt) + uintptr(l.idx))))
	switch l.idx {
	case 511:
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
func (l *Breeze512) XOR(out *[]byte, in *[]byte, key *[]byte) error {
	_, err := l.ShortHash(*key, 512/8)
	if err != nil {
		return err
	}
	idx := l.idx
	for i, v := range *in {
		(*out)[i] = v ^ (uint8)(*(*uint8)(unsafe.Pointer(uintptr(l.strt) + uintptr(idx))))
		switch idx {
		case 511:
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
func (l *Breeze512) ShortHash(s interface{}, lenInBytes int) (hash []byte, err error) {
	hash = make([]byte, lenInBytes)
	var pad []byte
	var padLen int
	var seed [8]uint64

	switch s := s.(type) {
	case string:
		if len(s) < 8 {
			return hash, initSeedToShort
		}
		if len(s) > 7 && len(s) < 17 {
			seed1 := foldAndCompress([]byte(s))
			seed = [8]uint64{seed1[0], seed1[1], uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)}
		}
		if len(s) > 16 && len(s) < 32 {
			seed1 := foldAndCompress([]byte(s[0:16]))
			seed2 := foldAndCompress([]byte(s[len(s)-16:]))
			seed = [8]uint64{seed1[0], seed1[1], seed2[0], seed2[1], uint64(0), uint64(0), uint64(0), uint64(0)}
		}
		if len(s) > 31 && len(s) < 48 {
			seed1 := foldAndCompress([]byte(s[0:16]))
			seed2 := foldAndCompress([]byte(s[16:32]))
			seed3 := foldAndCompress([]byte(s[len(s)-16:]))
			seed = [8]uint64{seed1[0], seed1[1], seed2[0], seed2[1], seed3[0], seed3[1], uint64(0), uint64(0)}
		}
		if len(s) > 47 && len(s) < 64 {
			seed1 := foldAndCompress([]byte(s[0:16]))
			seed2 := foldAndCompress([]byte(s[16:32]))
			seed3 := foldAndCompress([]byte(s[32:48]))
			seed4 := foldAndCompress([]byte(s[len(s)-16:]))
			seed = [8]uint64{seed1[0], seed1[1], seed2[0], seed2[1], seed3[0], seed3[1], seed4[0], seed4[1]}
		}
		if len(s) > 63 {
			l := len(s) / 4
			seed1 := foldAndCompress([]byte(s[0:l]))
			seed2 := foldAndCompress([]byte(s[l : 2*l]))
			seed3 := foldAndCompress([]byte(s[2*l : 3*l]))
			seed4 := foldAndCompress([]byte(s[3*l:]))
			seed = [8]uint64{seed1[0], seed1[1], seed2[0], seed2[1], seed3[0], seed3[1], seed4[0], seed4[1]}
		}
		padLen = 1 + len(s)/lenInBytes
		pad = make([]byte, padLen*lenInBytes)
		copy(pad[len(s)%lenInBytes:], []byte(s))
	case []byte:
		if len(s) < 8 {
			return hash, initSeedArrayToShort
		}
		if len(s) > 7 && len(s) < 17 {
			seed1 := foldAndCompress(s)
			seed = [8]uint64{seed1[0], seed1[1], uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)}
		}
		if len(s) > 16 && len(s) < 32 {
			seed1 := foldAndCompress(s[0:16])
			seed2 := foldAndCompress(s[len(s)-16:])
			seed = [8]uint64{seed1[0], seed1[1], seed2[0], seed2[1], uint64(0), uint64(0), uint64(0), uint64(0)}
		}
		if len(s) > 31 && len(s) < 48 {
			seed1 := foldAndCompress(s[0:16])
			seed2 := foldAndCompress(s[16:32])
			seed3 := foldAndCompress(s[len(s)-16:])
			seed = [8]uint64{seed1[0], seed1[1], seed2[0], seed2[1], seed3[0], seed3[1], uint64(0), uint64(0)}
		}
		if len(s) > 47 && len(s) < 64 {
			seed1 := foldAndCompress(s[0:16])
			seed2 := foldAndCompress(s[16:32])
			seed3 := foldAndCompress(s[32:48])
			seed4 := foldAndCompress(s[len(s)-16:])
			seed = [8]uint64{seed1[0], seed1[1], seed2[0], seed2[1], seed3[0], seed3[1], seed4[0], seed4[1]}
		}
		if len(s) > 63 {
			l := len(s) / 4
			seed1 := foldAndCompress(s[0:l])
			seed2 := foldAndCompress(s[l : 2*l])
			seed3 := foldAndCompress(s[2*l : 3*l])
			seed4 := foldAndCompress(s[3*l:])
			seed = [8]uint64{seed1[0], seed1[1], seed2[0], seed2[1], seed3[0], seed3[1], seed4[0], seed4[1]}
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
			case 511:
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
// Breeze CS128
//
// implements a cb-prng with four LM
// seeds with urandom & time.Nanoseconds
// 128 Byte outputState
type BreezeCS128 struct {
	State          [16]uint64
	State1, State2 float64
	State3, State4 float64
	State5, State6 float64
	bitshift       uint8
	idx            uint8
	strt           unsafe.Pointer
}

// Reset resets to the initial (empty) State
// before initializing.
func (l *BreezeCS128) Reset() error {
	*l = BreezeCS128{}
	err := l.Init()
	if err != nil {
		return err
	}
	return nil
}

// Init initializes from user input by calling initr() to process the input to become seeds (seedr(seed)) for the LMs.
// Init reseeds the LMs but it does NOT reset the prng:
//    it seeds based on the previous output States, internal bitshift and idx values
func (l *BreezeCS128) Init() (err error) {
	crand, err := csrand()
	if err != nil {
		return err
	}
	l.seedr(crand)
	return err
}

// seedr calculates the startvalues of the LMs and
// calls for the initial 'startrounds' roundtrips to shift circle
// once or more times over the output States
func (l *BreezeCS128) seedr(seed [2]uint64) {
	s1, s2, s3 := splittr(seed[0])
	s4, s5, s6 := splittr(seed[1])
	startrounds := 17

	l.State1 = 1.0 / float64(s1)
	l.State2 = 1.0 - 1.0/float64(s2)
	l.State3 = 1.0 / float64(s3)
	l.State4 = 1.0 - 1.0/float64(s4)
	l.State5 = 1.0 / float64(s5)
	l.State6 = 1.0 - 1.0/float64(s6)

	for startrounds > 0 {
		l.roundTrip()
		startrounds--
	}
	l.strt = unsafe.Pointer(&l.State[0])

}

// roundTrip calculates the next LMs States
// tests the States to be != 0 (else reseeds from crypto/rand ^ time.Now().Nanosecond())
// interchanges the States between LMs after 'mirroring them at 1'
// processes the output States from two or more LMs States
// mixin (xoring) in previous output States
// rotates all output States
func (l *BreezeCS128) roundTrip() {
	newState1 := (1.0 - l.State1)
	newState1 *= 4.0 * l.State1
	newState2 := (1.0 - l.State2)
	newState2 *= 3.999999999 * l.State2
	newState3 := (1.0 - l.State3)
	newState3 *= 3.99999998 * l.State3
	newState4 := (1.0 - l.State4)
	newState4 *= 3.99999997 * l.State4
	// ...
	// newState_n := (1.0 - l.State_n)
	// newState_n *= 3.83 * l.State_n

	switch newState1 * newState2 * newState3 * newState4 {
	case 0:
		crand, err := csrand()
		if err != nil {
			panic(1)
		}
		l.bitshift++
		l.seedr(crand)
	default:
		l.State1 = 1.0 - newState2
		l.State2 = l.State6
		l.State3 = 1.0 - newState4
		l.State4 = l.State5
		l.State5 = 1.0 - newState1
		l.State6 = 1.0 - newState3
	}

	l.bitshift = (l.bitshift + 1) % 21

	tmp := l.State[0]
	l.State[0] = l.State[1] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State1)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State2)))<<11>>(12+l.bitshift)))
	l.State[1] = l.State[2] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State2)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State3)))<<11>>(12+l.bitshift)))
	l.State[2] = l.State[3] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State3)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State4)))<<11>>(12+l.bitshift)))
	l.State[3] = l.State[4] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State4)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State1)))<<11>>(12+l.bitshift)))

	l.bitshift++
	l.State[4] = (l.State[5] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State1)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State2)))<<11>>(12+l.bitshift)))) ^ l.State[2]
	l.State[5] = (l.State[6] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State1)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State3)))<<11>>(12+l.bitshift)))) ^ l.State[3]
	l.State[6] = (l.State[7] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State1)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State4)))<<11>>(12+l.bitshift)))) ^ l.State[0]

	l.bitshift++
	l.State[7] = (l.State[8] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State2)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State1)))<<11>>(12+l.bitshift)))) ^ l.State[1]
	l.State[8] = (l.State[9] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State2)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State3)))<<11>>(12+l.bitshift)))) ^ l.State[2]
	l.State[9] = (l.State[10] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State2)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State4)))<<11>>(12+l.bitshift)))) ^ l.State[3]

	l.bitshift++
	l.State[10] = (l.State[11] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State3)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State2)))<<11>>(12+l.bitshift)))) ^ l.State[0]
	l.State[11] = (l.State[12] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State3)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State4)))<<11>>(12+l.bitshift)))) ^ l.State[1]
	l.State[12] = (l.State[13] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State3)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State1)))<<11>>(12+l.bitshift)))) ^ l.State[2]

	l.bitshift++
	l.State[13] = (l.State[14] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State4)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State1)))<<11>>(12+l.bitshift)))) ^ l.State[3]
	l.State[14] = (l.State[15] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State4)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State2)))<<11>>(12+l.bitshift)))) ^ l.State[0]
	l.State[15] = (tmp ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.State4)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.State3)))<<11>>(12+l.bitshift)))) ^ l.State[1]

	// obfuscate States 0..3
	tmp = l.State[0]
	l.State[0] ^= l.State[2]
	l.State[1] ^= l.State[3]
	l.State[2] ^= tmp
	l.State[3] ^= l.State[1]

}

// isSeeded checks if the prng had been seeded
// and returns bool
func (l *BreezeCS128) isSeeded() bool {
	for _, v := range l.State {
		if v > 0 {
			return true
		}
	}
	return false
}

// RandIntn returns an uint64 from the outputState byte register
// calling ByteMP to become thread/multiprocessing safe
func (l *BreezeCS128) RandIntn() (ri uint64) {
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

// RandDbl returns a positive float64 [0,1) (from an uint64 deriving from outputState byte register)
// calls RandIntn to be thread/multiprocessing safe
// RandDbl returns are uniform distributed
func (l *BreezeCS128) RandDbl() float64 {
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

// RandNorm returns a positive float64 [0,1) calculating the mean of 3 internal LM States
// and calls a roundTrip afterwards
// RandNorm returns are normal (gaussian) distributed
func (l *BreezeCS128) RandNorm() (rd float64) {
	if !l.isSeeded() {
		return rd
	}
	rd = (l.State1 + l.State2 + l.State3) / 3
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
func (l *BreezeCS128) Byte(byt *uint8) {
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
func (l *BreezeCS128) ByteMP(byt *uint8) {
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
func (l *BreezeCS128) XOR(out *[]byte, in *[]byte, key *[]byte) error {
	err := l.Init()
	if err != nil {
		return err
	}
	_, err = l.ShortHash(*key, 64)
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
func (l *BreezeCS128) ShortHash(s interface{}, lenInBytes int) (hash []byte, err error) {
	err = l.Init()
	if err != nil {
		return hash, err
	}
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
			return hash, initSeedArrayToShort
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
