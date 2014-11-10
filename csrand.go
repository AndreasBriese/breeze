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
	"bytes"
	"crypto/rand"
	"errors"
	"time"
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
