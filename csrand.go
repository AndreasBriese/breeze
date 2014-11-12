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
// parenthesis in roundTrip() ()all functions corr; statenumbers corrected to fit the new scheme
//
// revision 2014/11/10:
// any inner state has ist's own LM now: Breeze128: 6 LMs; Breeze 256: 12 LMs;  Breeze 512: 24 LMs;
// added BreezeCS128 (6LMs) to provide fast CSPRNG from go/golangs crypto/rand (dev/urandom) -> csrand.go
//
// // Breeze had not been cryptoanalysed.
// // It is definitly not recommended to use Breeze and it's ShortHash() or XOR() functions in particular in any security sensitive or
// // cryptographic context.
//

package breeze

//Version 1.1.1 as of 2014/11/10

import (
	"bytes"
	"crypto/rand"
	"errors"
	"time"
	"unsafe"
)

func csrand() (csseed [2]uint64, err error) {
	var urand = make([]byte, 16)
	_, err = rand.Read(urand)
	if err != nil {
		return csseed, err
	}
	if bytes.Equal(urand, make([]byte, 16)) {
		return csseed, errors.New("urandom failed: returned zeroes")
	}
	for i, v := range urand {
		csseed[i/8] = csseed[i/8]<<8 + uint64((v ^ byte(time.Now().Nanosecond())))
	}
	return csseed, err
}

//
// Breeze CS128
//
// implements a cb-prng with four LM
// seeds with urandom & time.Nanoseconds
// 128 Byte outputstate
type BreezeCS128 struct {
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
//    it seeds based on the previous output states, internal bitshift and idx values
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
// once or more times over the output states
func (l *BreezeCS128) seedr(seed [2]uint64) {
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
// tests the states to be != 0 (else reseeds from crypto/rand ^ time.Now().Nanosecond())
// interchanges the states between LMs after 'mirroring them at 1'
// processes the output states from two or more LMs states
// mixin (xoring) in previous output states
// rotates all output states
func (l *BreezeCS128) roundTrip() {
	newstate1 := (1.0 - l.state1)
	newstate1 *= 4.0 * l.state1
	newstate2 := (1.0 - l.state2)
	newstate2 *= 3.999999999 * l.state2
	newstate3 := (1.0 - l.state3)
	newstate3 *= 3.99999998 * l.state3
	newstate4 := (1.0 - l.state4)
	newstate4 *= 3.99999997 * l.state4
	newstate5 := (1.0 - l.state5)
	newstate5 *= 3.999999 * l.state5
	newstate6 := (1.0 - l.state6)
	newstate6 *= 3.999997 * l.state6
	// ...
	// newstate_n := (1.0 - l.state_n)
	// newstate_n *= 3.83 * l.state_n

	switch newstate1 * newstate2 * newstate3 * newstate4 {
	case 0:
		crand, err := csrand()
		if err != nil {
			panic(1)
		}
		l.bitshift++
		l.seedr(crand)
	default:
		l.state1 = 1.0 - newstate2
		l.state2 = 1.0 - newstate3
		l.state3 = 1.0 - newstate4
		l.state4 = 1.0 - newstate5
		l.state5 = 1.0 - newstate6
		l.state6 = 1.0 - newstate1
	}

	l.bitshift = (l.bitshift + 1) % 20

	tmp := l.state[0]
	l.state[0] = l.state[1] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<12>>(13+l.bitshift)))
	l.state[1] = l.state[2] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<12>>(13+l.bitshift)))
	l.state[2] = l.state[3] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state4)))<<12>>(13+l.bitshift)))
	l.state[3] = l.state[4] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state4)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<12>>(13+l.bitshift)))
	hop := ((uint64)((*(*uint64)(unsafe.Pointer(&l.state5)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state6)))<<12>>(13+l.bitshift)))

	l.bitshift++
	l.state[4] = (l.state[5] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<12>>(13+l.bitshift)))) ^ l.state[2]
	l.state[5] = (l.state[6] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<12>>(13+l.bitshift)))) ^ hop
	l.state[6] = (l.state[7] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state4)))<<12>>(13+l.bitshift)))) ^ l.state[1]

	l.state[7] = (l.state[8] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<12>>(13+l.bitshift)))) ^ hop
	l.state[8] = (l.state[9] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<12>>(13+l.bitshift)))) ^ l.state[3]
	l.state[9] = (l.state[10] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state4)))<<12>>(13+l.bitshift)))) ^ hop

	l.bitshift++
	l.state[10] = (l.state[11] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<12>>(13+l.bitshift)))) ^ l.state[3]
	l.state[11] = (l.state[12] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state4)))<<12>>(13+l.bitshift)))) ^ l.state[1]
	l.state[12] = (l.state[13] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<12>>(13+l.bitshift)))) ^ hop

	l.state[13] = (l.state[14] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state4)))<<12) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<12>>(13+l.bitshift)))) ^ l.state[2]
	l.state[14] = (l.state[15] ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state4)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<12>>(13+l.bitshift)))) ^ hop
	l.state[15] = (tmp ^ ((uint64)((*(*uint64)(unsafe.Pointer(&l.state4)))<<30) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<12>>(13+l.bitshift)))) ^ l.state[0]

	// obfuscate states 0..3
	tmp = l.state[0]
	l.state[0] ^= l.state[2]
	l.state[1] ^= l.state[3]
	l.state[2] ^= tmp
	l.state[3] ^= l.state[1]

}

// isSeeded checks if the prng had been seeded
// and returns bool
func (l *BreezeCS128) isSeeded() bool {
	for _, v := range l.state {
		if v > 0 {
			return true
		}
	}
	return false
}

// RandIntn returns an uint64 from the outputstate byte register
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

// RandDbl returns a positive float64 [0,1) (from an uint64 deriving from outputstate byte register)
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

// RandNorm returns a positive float64 [0,1) calculating the mean of 3 internal LM states
// and calls a roundTrip afterwards
// RandNorm returns are normal (gaussian) distributed
func (l *BreezeCS128) RandNorm() (rd float64) {
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
		seed, err = initr(s)
		if err != nil {
			return hash, err
		}
		padLen = 1 + len(s)/lenInBytes
		pad = make([]byte, padLen*lenInBytes)
		copy(pad[len(s)%lenInBytes:], []byte(s))
	case []byte:
		seed, err = initr(s)
		if err != nil {
			return hash, err
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
