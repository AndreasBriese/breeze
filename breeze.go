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
// It is definitly not recommended to use Breeze and it's Hash() or XOR() functions in particular in any security sensitive or
// cryptographic context.
//
//

package breeze

// breeze v. 1.0 14/11/1

import (
	"sync"
	"unsafe"
)

var mutex = &sync.Mutex{}

func initr(s interface{}) (seed [2]uint64) {
	switch s := s.(type) {
	case int:
		if s < 0 {
			s = -s
		}
		seed = [2]uint64{uint64(s), uint64(s)}
	case int8:
		if s < 0 {
			s = -s
		}
		seed = [2]uint64{uint64(s), uint64(s)}
	case int16:
		if s < 0 {
			s = -s
		}
		seed = [2]uint64{uint64(s), uint64(s)}
	case int32:
		if s < 0 {
			s = -s
		}
		seed = [2]uint64{uint64(s), uint64(s)}
	case int64:
		if s < 0 {
			s = -s
		}
		seed = [2]uint64{uint64(s), uint64(s)}
	case uint8:
		seed = [2]uint64{uint64(s), uint64(s)}
	case uint16:
		seed = [2]uint64{uint64(s), uint64(s)}
	case uint32:
		seed = [2]uint64{uint64(s), uint64(s)}
	case uint64:
		seed = [2]uint64{s, s}
	case []uint64:
		seed = [2]uint64{s[0], s[len(s)-1]}
	case string:
		seed = foldAndCompress([]byte(s))
	case []byte:
		seed = foldAndCompress(s)
	case float32:
		seed = [2]uint64{uint64(*(*uint32)(unsafe.Pointer(&s)) << 9 >> 9), uint64(*(*uint32)(unsafe.Pointer(&s)) << 9 >> 9)}
	case float64:
		seed = [2]uint64{*(*uint64)(unsafe.Pointer(&s)) << 11 >> 11, *(*uint64)(unsafe.Pointer(&s)) << 11 >> 11}
	default:
		panic(1)
	}
	return seed
}

//
// Breeze 32 byte
//

type Breeze32 struct {
	state    [4]uint64
	state1   float64
	state2   float64
	bitshift uint8
	idx      uint8
	strt     unsafe.Pointer
}

func (l *Breeze32) Reset() {
	*l = Breeze32{}
}

func (l *Breeze32) Init(s interface{}) {
	l.seedr(initr(s))
}

func (l *Breeze32) seedr(seed [2]uint64) {
	var s1, s2, startrounds uint64
	for seed[0]&1 == 0 {
		seed[0] >>= 1
	}
	done := false
	for !done {
		for i := uint(63); i > 0; i-- {
			if seed[0]>>i == 1 {
				s1 = (seed[0] >> (i >> 1))
				s2 = (seed[0] << (63 - (i >> 1)) >> (63 - (i >> 1)))
				startrounds = 4 + (s1>>38 | s2>>38)
				s1 = s1 << 38 >> 38
				s2 = s2 << 38 >> 38
				if s1 != 0 && s2 != 0 {
					done = true
					break
				}
			}
		}
		seed[0] = seed[0] << 1 >> 1
		if seed[0] == 0 {
			seed[0] = s1
		}
	}

	switch s1 {
	case 0, 1, 2, 4:
		s1 = 1<<27 - 20*s1
	}

	switch s2 {
	case 0:
		s2 = 1<<27 - 20*s1
	}

	l.state1 = 1.0 / float64(s1)
	l.state2 = 1.0 / float64(s2)
	for startrounds > 0 {
		l.roundTrip()
		startrounds--
	}
	l.strt = unsafe.Pointer(&l.state[0])

}

func (l *Breeze32) roundTrip() {
	newstate1 := (1.0 - l.state1)
	newstate1 *= 4.0 * l.state1
	newstate2 := (1.0 - l.state2)
	newstate2 *= 3.999999999 * l.state2
	switch newstate1 * newstate2 {
	case 0:
		seed := [2]uint64{(uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<11>>(12+l.bitshift%7)) | (uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<11>>(12+l.bitshift%7))}
		l.bitshift++
		l.seedr(seed)
	default:
		l.state1 = 1.0 - newstate2
		l.state2 = 1.0 - newstate1
	}

	l.bitshift = (l.bitshift + 1) % 22

	l.state[0] ^= (uint64)((*(*uint64)(unsafe.Pointer(&l.state1))) << 32)
	l.state[0] ^= ((uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<11>>(12+l.bitshift)) ^ (uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<11>>(13+l.bitshift)))

	l.bitshift++

	l.state[1] ^= (uint64)((*(*uint64)(unsafe.Pointer(&l.state2))) << 32)
	l.state[1] ^= ((uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<11>>(12+l.bitshift)) ^ (uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<11>>(13+l.bitshift)))

	l.state[2] ^= l.state[0]
	l.state[2] ^= (uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<11) + (*(*uint64)(unsafe.Pointer(&l.state1)))<<11>>(12+l.bitshift)

	l.state[3] ^= l.state[1]
	l.state[3] ^= (uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<11) + (*(*uint64)(unsafe.Pointer(&l.state2)))<<11>>(12+l.bitshift) ^ l.state[2]

	l.state[2] ^= l.state[3]

	tmp := l.state[0]
	for i := uint8(1); i < 4; i++ {
		l.state[i-1] = l.state[i]
	}
	l.state[3] = tmp

}

func (l *Breeze32) Byte(byt *uint8) {
	*byt = (uint8)(*(*uint8)(unsafe.Pointer(uintptr(l.strt) + uintptr(l.idx))))
	l.idx++
	if l.idx == 32 {
		l.roundTrip()
		l.idx = 0
	}
}

func (l *Breeze32) ByteMP(byt *uint8) {
	mutex.Lock()
	*byt = (uint8)(*(*uint8)(unsafe.Pointer(uintptr(l.strt) + uintptr(l.idx))))
	l.idx++
	if l.idx == 32 {
		l.roundTrip()
		l.idx = 0
	}
	mutex.Unlock()
}

func (l *Breeze32) XOR(out *[]byte, in *[]byte, key *[]byte) {
	_ = l.ShortHash(*key, 512/8)
	idx := l.idx
	for i, v := range *in {
		(*out)[i] = v ^ (uint8)(*(*uint8)(unsafe.Pointer(uintptr(l.strt) + uintptr(idx))))
		idx++
		if idx == 32 {
			l.roundTrip()
			idx = 0
		}
	}
}

func (l *Breeze32) ShortHash(s interface{}, lenInBytes int) (hash []byte) {
	if lenInBytes%2 == 1 {
		panic(1)
	}

	hash = make([]byte, lenInBytes)
	var pad []byte
	var padLen int
	var seed [2]uint64

	switch s := s.(type) {
	case string:
		seed = foldAndCompress([]byte(s))
		padLen = 1 + len(s)/lenInBytes
		pad = make([]byte, padLen*lenInBytes)
		copy(pad[len(s)%lenInBytes:], []byte(s))
	case []byte:
		seed = foldAndCompress(s)
		padLen = 1 + len(s)/lenInBytes
		pad = make([]byte, padLen*lenInBytes)
		copy(pad[len(s)%lenInBytes:], s)
	default:
		panic(1)
	}

	seed[0] = seed[0] ^ seed[1]
	l.seedr(seed)

	copy(hash, pad)
	idx := l.idx
	for i := 0; i < padLen; i++ {
		for ii := 0; ii < lenInBytes; ii++ {
			hash[ii] ^= (pad[i*lenInBytes+ii] ^ (uint8)(*(*uint8)(unsafe.Pointer(uintptr(l.strt) + uintptr(idx)))))
			idx++
			if idx == 32 {
				l.roundTrip()
				idx = 0
			}
		}

	}

	return hash
}

//
// Breeze 72 byte
//

type Breeze72 struct {
	state          [9]uint64
	state1, state2 float64
	state3, state4 float64
	bitshift       uint8
	idx            uint8
	strt           unsafe.Pointer
}

func (l *Breeze72) Reset() {
	*l = Breeze72{}
}

func (l *Breeze72) Init(s interface{}) {
	l.seedr(initr(s))
}

func (l *Breeze72) seedr(seed [2]uint64) {
	var s1, s2, startrounds uint64
	for seed[0]&1 == 0 {
		seed[0] >>= 1
	}
	done := false
	for !done {
		for i := uint(63); i > 0; i-- {
			if seed[0]>>i == 1 {
				s1 = (seed[0] >> (i >> 1))
				s2 = (seed[0] << (63 - (i >> 1)) >> (63 - (i >> 1)))
				startrounds = 9 + ((s1>>38 | s2>>38) & seed[1] >> 38)
				s1 = s1 << 38 >> 38
				s2 = s2 << 38 >> 38
				if s2 != 0 && s1 != 0 {
					done = true
					break
				}
			}
		}
		seed[0] = seed[0] << 1 >> 1
		if seed[0] == 0 {
			seed[0] = s1
		}
	}

	switch s1 {
	case 0, 1, 2, 4:
		s1 = 1<<27 - 20*s1
	}

	switch s2 {
	case 0:
		s2 = 1<<27 - 20*s1
	}

	l.state1 = 1.0 / float64(s1)
	l.state2 = 1.0 / float64(s2)
	l.state3 = 1.0 / float64(seed[1]<<38>>38)
	for startrounds > 0 {
		l.roundTrip()
		startrounds--
	}
	l.strt = unsafe.Pointer(&l.state[0])

}

func (l *Breeze72) roundTrip() {
	newstate1 := (1.0 - l.state1)
	newstate1 *= 4.0 * l.state1
	newstate2 := (1.0 - l.state2)
	newstate2 *= 3.999999999 * l.state2
	newstate3 := (1.0 - l.state3)
	newstate3 *= 3.999999998 * l.state3
	// newstate4 := (1.0 - l.state4)
	// newstate4 *= 3.999999997 * l.state4
	// ...
	// newstate4 := (1.0 - l.state4)
	// newstate4 *= 3.83 * l.state4

	switch newstate1 * newstate2 * newstate3 {
	case 0:
		s := (uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<11>>(12+l.bitshift%7)) | (uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<11>>(12+l.bitshift%7)) | (uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<11>>(12+l.bitshift%7))
		seed := [2]uint64{s, s | s + s}
		l.bitshift++
		l.seedr(seed)
	default:
		l.state1 = 1.0 - newstate2
		l.state2 = 1.0 - newstate3
		l.state3 = 1.0 - newstate1
	}

	l.bitshift = (l.bitshift + 1) % 21

	l.state[0] ^= (uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<32) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<11>>11)
	l.state[0] ^= (uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<11>>(12+l.bitshift)) ^ (uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<11>>(12+l.bitshift))

	l.state[1] ^= (uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<32) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<11>>11)
	l.state[1] ^= (uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<11>>(12+l.bitshift)) ^ (uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<11>>(12+l.bitshift))

	l.state[2] ^= (uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<32) + (uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<11>>11)
	l.state[2] ^= (uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<11>>(12+l.bitshift)) ^ (*(*uint64)(unsafe.Pointer(&l.state2)))<<11>>(12+l.bitshift)

	l.bitshift++

	l.state[3] ^= l.state[0] + l.state[1]
	l.state[3] ^= (uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<11) ^ (uint64)(*(*uint64)(unsafe.Pointer(&l.state2)))<<11>>(12+l.bitshift) ^ (uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<11)

	l.state[4] ^= l.state[1] + l.state[2]
	l.state[4] ^= (uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<11) ^ (uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<11>>(12+l.bitshift)) ^ (uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<11)

	l.state[5] ^= l.state[2] + l.state[0]
	l.state[5] ^= (uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<11) ^ (uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<11>>(12+l.bitshift)) ^ (uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<11)

	l.bitshift++

	l.state[6] ^= l.state[3] + l.state[4]
	l.state[6] ^= (uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<11) ^ (uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<11>>(12+l.bitshift)|(uint64)(*(*uint64)(unsafe.Pointer(&l.state3))<<11>>(12+l.bitshift)))

	l.state[7] ^= l.state[4] + l.state[5]
	l.state[7] ^= (uint64)((*(*uint64)(unsafe.Pointer(&l.state2)))<<11) ^ (uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<11>>(12+l.bitshift)|(uint64)(*(*uint64)(unsafe.Pointer(&l.state1))<<11>>(12+l.bitshift)))

	l.state[8] ^= l.state[5] + l.state[3]
	l.state[8] ^= (uint64)((*(*uint64)(unsafe.Pointer(&l.state3)))<<11) ^ (uint64)((*(*uint64)(unsafe.Pointer(&l.state1)))<<11>>(12+l.bitshift)|(uint64)(*(*uint64)(unsafe.Pointer(&l.state2))<<11>>(12+l.bitshift)))

	tmp := l.state[0]
	for i := uint8(1); i < 9; i++ {
		l.state[i-1] = l.state[i]
	}
	l.state[8] = tmp
}

func (l *Breeze72) Byte(byt *uint8) {
	*byt = (uint8)(*(*uint8)(unsafe.Pointer(uintptr(l.strt) + uintptr(l.idx))))
	l.idx++
	if l.idx == 72 {
		l.roundTrip()
		l.idx = 0
	}
}

func (l *Breeze72) ByteMP(byt *uint8) {
	mutex.Lock()
	*byt = (uint8)(*(*uint8)(unsafe.Pointer(uintptr(l.strt) + uintptr(l.idx))))
	l.idx++
	if l.idx == 72 {
		l.roundTrip()
		l.idx = 0
	}
	mutex.Unlock()
}

func (l *Breeze72) XOR(out *[]byte, in *[]byte, key *[]byte) {
	_ = l.ShortHash(*key, 512/8)
	idx := uintptr(0)
	for i, v := range *in {
		(*out)[i] = v ^ (uint8)(*(*uint8)(unsafe.Pointer(uintptr(l.strt) + uintptr(idx))))
		idx++
		if idx == 72 {
			l.roundTrip()
			idx = 0
		}
	}
}

func (l *Breeze72) ShortHash(s interface{}, lenInBytes int) (hash []byte) {
	if lenInBytes%2 == 1 {
		panic(1)
	}

	hash = make([]byte, lenInBytes)
	var pad []byte
	var padLen int
	var seed [2]uint64

	switch s := s.(type) {
	case string:
		seed = foldAndCompress([]byte(s))
		padLen = 1 + len(s)/lenInBytes
		pad = make([]byte, padLen*lenInBytes)
		copy(pad[len(s)%lenInBytes:], []byte(s))
	case []byte:
		seed = foldAndCompress(s)
		padLen = 1 + len(s)/lenInBytes
		pad = make([]byte, padLen*lenInBytes)
		copy(pad[len(s)%lenInBytes:], s)
	default:
		panic(1)
	}

	l.seedr(seed)

	copy(hash, pad)

	idx := uintptr(0)
	for i := 0; i < padLen; i++ {
		for ii := 0; ii < lenInBytes; ii++ {
			hash[ii] ^= (pad[i*lenInBytes+ii] ^ (uint8)(*(*uint8)(unsafe.Pointer(uintptr(l.strt) + uintptr(idx)))))
			idx++
			if idx == 72 {
				l.roundTrip()
				idx = 0
			}
		}
	}

	return hash
}
