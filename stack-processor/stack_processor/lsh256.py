#-*- coding: utf-8 -*-

'''
 Copyright (c) 2016 NSR (National Security Research Institute)
 
 Permission is hereby granted, free of charge, to any person obtaining a copy 
 of this software and associated documentation files (the "Software"), to deal 
 in the Software without restriction, including without limitation the rights 
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
 copies of the Software, and to permit persons to whom the Software is 
 furnished to do so, subject to the following conditions:
 
 The above copyright notice and this permission notice shall be included in 
 all copies or substantial portions of the Software.
 
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN 
 THE SOFTWARE.
'''

import struct

## LSH 추상 클래스
class LSHTemplate:

    _MASK = None
    _WORDBITLEN = None
    _NUMSTEP = None
    _BLOCKSIZE = 0
    _FORMAT_IN = None
    _FORMAT_OUT = None
    
    _outlenbits = 0
    _boff = None
    _cv = None
    _tcv = None
    _msg = None
    _buf = None
    
    _STEP = None
    _ALPHA_EVEN = None
    _ALPHA_ODD = None    
    _BETA_EVEN = None
    _BETA_ODD = None
    _GAMMA = None
    
    ## 생성자
    #  @param [in] self 객체 포인터
    #  @param [in] outlenbits 출력 길이 (비트)
    def __init__(self, outlenbits):
        self._init(outlenbits)
    
    
    ## HMAC 계산에 사용하기 위해서 내부 블록 길이 리턴
    #  @param [in] self 객체 포인터
    #  @return 내부 블록 길이
    def get_blocksize(self):
        return self._BLOCKSIZE
    
        
    ## 메시지 확장 함수
    #  @param [in] self 객체 포인터
    #  @param [in] data 입력 데이터
    #  @param [in] offset 데이터 시작 인덱스
    def _msg_expansion(self, data, offset):
        block = bytearray(data[offset:offset + self._BLOCKSIZE])
        self._msg[0:32] = struct.unpack(self._FORMAT_IN, block[0:self._BLOCKSIZE]) # noqa
        
        for i in range(2, self._NUMSTEP + 1): # noqa
            idx = 16 * i
            self._msg[idx     ] = (self._msg[idx - 16] + self._msg[idx - 29]) & self._MASK
            self._msg[idx +  1] = (self._msg[idx - 15] + self._msg[idx - 30]) & self._MASK
            self._msg[idx +  2] = (self._msg[idx - 14] + self._msg[idx - 32]) & self._MASK
            self._msg[idx +  3] = (self._msg[idx - 13] + self._msg[idx - 31]) & self._MASK
            self._msg[idx +  4] = (self._msg[idx - 12] + self._msg[idx - 25]) & self._MASK
            self._msg[idx +  5] = (self._msg[idx - 11] + self._msg[idx - 28]) & self._MASK
            self._msg[idx +  6] = (self._msg[idx - 10] + self._msg[idx - 27]) & self._MASK
            self._msg[idx +  7] = (self._msg[idx -  9] + self._msg[idx - 26]) & self._MASK
            self._msg[idx +  8] = (self._msg[idx -  8] + self._msg[idx - 21]) & self._MASK
            self._msg[idx +  9] = (self._msg[idx -  7] + self._msg[idx - 22]) & self._MASK
            self._msg[idx + 10] = (self._msg[idx -  6] + self._msg[idx - 24]) & self._MASK
            self._msg[idx + 11] = (self._msg[idx -  5] + self._msg[idx - 23]) & self._MASK
            self._msg[idx + 12] = (self._msg[idx -  4] + self._msg[idx - 17]) & self._MASK
            self._msg[idx + 13] = (self._msg[idx -  3] + self._msg[idx - 20]) & self._MASK
            self._msg[idx + 14] = (self._msg[idx -  2] + self._msg[idx - 19]) & self._MASK
            self._msg[idx + 15] = (self._msg[idx -  1] + self._msg[idx - 18]) & self._MASK
            
    ## 워드 단위 순환 함수
    #  @param [in] self 객체 포인터
    def _word_permutation(self):
        self._cv[ 0] = self._tcv[ 6]
        self._cv[ 1] = self._tcv[ 4]
        self._cv[ 2] = self._tcv[ 5]
        self._cv[ 3] = self._tcv[ 7]
        self._cv[ 4] = self._tcv[12]
        self._cv[ 5] = self._tcv[15]
        self._cv[ 6] = self._tcv[14]
        self._cv[ 7] = self._tcv[13]
        self._cv[ 8] = self._tcv[ 2]
        self._cv[ 9] = self._tcv[ 0]
        self._cv[10] = self._tcv[ 1]
        self._cv[11] = self._tcv[ 3]
        self._cv[12] = self._tcv[ 8]
        self._cv[13] = self._tcv[11]
        self._cv[14] = self._tcv[10]
        self._cv[15] = self._tcv[ 9]
        
    ## 스텝 함수 - LSH를 상속받는 클래스에서 별도로 구현해야 함
    #  @param [in] self 객체 포인터
    #  @param [in] idx 스텝 인덱스
    #  @param [in] alpha 회전값 알파
    #  @param [in] beta 회전값 베타
    def _step(self, idx, alpha, beta):
        raise NotImplementedError("Implement this method")
    
    ## 압축 함수
    #  @param [in] self 객체 포인터
    #  @param [in] data 입력 데이터
    #  @param [in] offset 데이터 시작 인덱스
    def _compress(self, data, offset = 0):    
        
        self._msg_expansion(data, offset)
        
        for idx in range(int(self._NUMSTEP / 2)):
            self._step(2 * idx, self._ALPHA_EVEN, self._BETA_EVEN)
            self._step(2 * idx + 1, self._ALPHA_ODD, self._BETA_ODD)
        
        for idx in range(16):
            self._cv[idx] ^= self._msg[16 * self._NUMSTEP + idx]

    
    ## IV 생성 함수 - LSH를 상속받는 클래스에서 별도로 구현해야 함
    #  @param [in] self 객체 포인터
    #  @param [in] outlenbits 출력 길이 (비트)
    def _init_iv(self, outlenbits):
        raise NotImplementedError("Implement this method")
    
    def _init(self, outlenbits):
        self._boff = 0
        self._tcv = [0] * 16
        self._msg = [0] * (16 * (self._NUMSTEP + 1))
        self._buf = [0] * self._BLOCKSIZE
        self._init_iv(outlenbits)
    
    ## 리셋 함수 - 키 입력 직후의 상태로 되돌린다
    #  @param self 객체 포인터
    def reset(self):
        self._init(self._outlenbits)
    
    
    ## 업데이트 함수
    #  @param [in] self 객체 포인터
    #  @param [in] data 입력 데이터
    #  @param [in] offset 데이터 시작 오프셋 (바이트)
    #  @param [in] length 데이터 길이 (비트)
    def update(self, data, offset = 0, length = -1):
        if data is None or len(data) == 0 or length == 0:
            return
        
        if length == -1:
            length = (len(data) - offset) << 3
        
        len_bytes = length >> 3
        len_bits = length & 0x7
        
        buf_idx = self._boff >> 3
        
        if (self._boff & 0x7) > 0:
            raise AssertionError("bit level update is not allowed")
        
        gap = self._BLOCKSIZE - (self._boff >> 3)
        
        if len_bytes >= gap:
            self._buf[buf_idx:self._BLOCKSIZE] = data[offset:offset + gap]
            self._compress(self._buf)
            self._boff = 0
            offset += gap
            len_bytes -= gap
        
        while len_bytes >= self._BLOCKSIZE:
            self._compress(data, offset)            
            offset += self._BLOCKSIZE
            len_bytes -= self._BLOCKSIZE
        
        if len_bytes > 0:
            buf_idx = self._boff >> 3
            self._buf[buf_idx:buf_idx + len_bytes] = data[offset:offset + len_bytes]
            self._boff += len_bytes << 3
            offset += len_bytes
        
        if len_bits > 0:
            buf_idx = self._boff >> 3
            self._buf[buf_idx] = data[offset] & ((0xff >> len_bits) ^ 0xff)
            self._boff += len_bits
    
    ## 종료 함수 - 최종 해쉬 값을 계산하여 리턴한다
    #  @param [in] self 객체 포인터
    #  @param [in] data 입력 데이터
    #  @param [in] offset 데이터 시작 오프셋 (바이트)
    #  @param [in] length 데이터 길이 (비트)
    #  @return 계산된 해쉬값
    def final(self, data = None, offset = 0, length = -1):
        if data is not None:
            self.update(data, offset, length)
        
        rbytes = self._boff >> 3
        rbits = self._boff & 0x7
        
        if rbits > 0:
            self._buf[rbytes] |= (0x1 << (7 - rbits))
        else:
            self._buf[rbytes] = 0x80
        
        pos = rbytes + 1
        if (pos < self._BLOCKSIZE):
            self._buf[pos:] = [0] * (self._BLOCKSIZE - pos)
            
        self._compress(self._buf)
        
        temp = [0] * 8
        for idx in range(8):
            temp[idx] = (self._cv[idx] ^ self._cv[idx + 8]) & self._MASK
        
        self._init(self._outlenbits)
        
        rbytes = self._outlenbits >> 3
        rbits = self._outlenbits & 0x7
        if rbits > 0:
            rbytes += 1
        
        result = bytearray(struct.pack(self._FORMAT_OUT, temp[0], temp[1], temp[2], temp[3], temp[4], temp[5], temp[6], temp[7]))
        result = result[0:rbytes]
        if rbits > 0:
            result[rbytes - 1] &= (0xff << (8 - rbits))
        
        return result

MASK_U32 = 0xffffffff 

## LSH256 구현 클래스
class LSH256(LSHTemplate):
    
    _MASK = MASK_U32
    _BLOCKSIZE = 128
    _NUMSTEP = 26
    _FORMAT_IN = '<LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL'
    _FORMAT_OUT = '<LLLLLLLL'
    
    ## 사전 계산된 224비트 출력용 IV
    __IV224 = [
        0x068608D3, 0x62D8F7A7, 0xD76652AB, 0x4C600A43, 0xBDC40AA8, 0x1ECA0B68, 0xDA1A89BE, 0x3147D354,
        0x707EB4F9, 0xF65B3862, 0x6B0B2ABE, 0x56B8EC0A, 0xCF237286, 0xEE0D1727, 0x33636595, 0x8BB8D05F,
    ]
    
    ## 사전 계산된 256비트 출력용 IV
    __IV256 = [
        0x46a10f1f, 0xfddce486, 0xb41443a8, 0x198e6b9d,    0x3304388d, 0xb0f5a3c7, 0xb36061c4, 0x7adbd553,
        0x105d5378, 0x2f74de54, 0x5c2f2d95, 0xf2553fbe,    0x8051357a, 0x138668c8, 0x47aa4484, 0xe01afb41
    ]
    
    ## STEP 상수
    _STEP = [
        0x917caf90, 0x6c1b10a2, 0x6f352943, 0xcf778243, 0x2ceb7472, 0x29e96ff2, 0x8a9ba428, 0x2eeb2642, 
        0x0e2c4021, 0x872bb30e, 0xa45e6cb2, 0x46f9c612, 0x185fe69e, 0x1359621b, 0x263fccb2, 0x1a116870, 
        0x3a6c612f, 0xb2dec195, 0x02cb1f56, 0x40bfd858, 0x784684b6, 0x6cbb7d2e, 0x660c7ed8, 0x2b79d88a, 
        0xa6cd9069, 0x91a05747, 0xcdea7558, 0x00983098, 0xbecb3b2e, 0x2838ab9a, 0x728b573e, 0xa55262b5, 
        0x745dfa0f, 0x31f79ed8, 0xb85fce25, 0x98c8c898, 0x8a0669ec, 0x60e445c2, 0xfde295b0, 0xf7b5185a, 
        0xd2580983, 0x29967709, 0x182df3dd, 0x61916130, 0x90705676, 0x452a0822, 0xe07846ad, 0xaccd7351, 
        0x2a618d55, 0xc00d8032, 0x4621d0f5, 0xf2f29191, 0x00c6cd06, 0x6f322a67, 0x58bef48d, 0x7a40c4fd, 
        0x8beee27f, 0xcd8db2f2, 0x67f2c63b, 0xe5842383, 0xc793d306, 0xa15c91d6, 0x17b381e5, 0xbb05c277, 
        0x7ad1620a, 0x5b40a5bf, 0x5ab901a2, 0x69a7a768, 0x5b66d9cd, 0xfdee6877, 0xcb3566fc, 0xc0c83a32, 
        0x4c336c84, 0x9be6651a, 0x13baa3fc, 0x114f0fd1, 0xc240a728, 0xec56e074, 0x009c63c7, 0x89026cf2, 
        0x7f9ff0d0, 0x824b7fb5, 0xce5ea00f, 0x605ee0e2, 0x02e7cfea, 0x43375560, 0x9d002ac7, 0x8b6f5f7b, 
        0x1f90c14f, 0xcdcb3537, 0x2cfeafdd, 0xbf3fc342, 0xeab7b9ec, 0x7a8cb5a3, 0x9d2af264, 0xfacedb06, 
        0xb052106e, 0x99006d04, 0x2bae8d09, 0xff030601, 0xa271a6d6, 0x0742591d, 0xc81d5701, 0xc9a9e200, 
        0x02627f1e, 0x996d719d, 0xda3b9634, 0x02090800, 0x14187d78, 0x499b7624, 0xe57458c9, 0x738be2c9, 
        0x64e19d20, 0x06df0f36, 0x15d1cb0e, 0x0b110802, 0x2c95f58c, 0xe5119a6d, 0x59cd22ae, 0xff6eac3c, 
        0x467ebd84, 0xe5ee453c, 0xe79cd923, 0x1c190a0d, 0xc28b81b8, 0xf6ac0852, 0x26efd107, 0x6e1ae93b, 
        0xc53c41ca, 0xd4338221, 0x8475fd0a, 0x35231729, 0x4e0d3a7a, 0xa2b45b48, 0x16c0d82d, 0x890424a9, 
        0x017e0c8f, 0x07b5a3f5, 0xfa73078e, 0x583a405e, 0x5b47b4c8, 0x570fa3ea, 0xd7990543, 0x8d28ce32, 
        0x7f8a9b90, 0xbd5998fc, 0x6d7a9688, 0x927a9eb6, 0xa2fc7d23, 0x66b38e41, 0x709e491a, 0xb5f700bf, 
        0x0a262c0f, 0x16f295b9, 0xe8111ef5, 0x0d195548, 0x9f79a0c5, 0x1a41cfa7, 0x0ee7638a, 0xacf7c074, 
        0x30523b19, 0x09884ecf, 0xf93014dd, 0x266e9d55, 0x191a6664, 0x5c1176c1, 0xf64aed98, 0xa4b83520, 
        0x828d5449, 0x91d71dd8, 0x2944f2d6, 0x950bf27b, 0x3380ca7d, 0x6d88381d, 0x4138868e, 0x5ced55c4, 
        0x0fe19dcb, 0x68f4f669, 0x6e37c8ff, 0xa0fe6e10, 0xb44b47b0, 0xf5c0558a, 0x79bf14cf, 0x4a431a20, 
        0xf17f68da, 0x5deb5fd1, 0xa600c86d, 0x9f6c7eb0, 0xff92f864, 0xb615e07f, 0x38d3e448, 0x8d5d3a6a, 
        0x70e843cb, 0x494b312e, 0xa6c93613, 0x0beb2f4f, 0x928b5d63, 0xcbf66035, 0x0cb82c80, 0xea97a4f7, 
        0x592c0f3b, 0x947c5f77, 0x6fff49b9, 0xf71a7e5a, 0x1de8c0f5, 0xc2569600, 0xc4e4ac8c, 0x823c9ce1,
    ]
    
    _ALPHA_EVEN = 29
    _ALPHA_ODD = 5
    
    _BETA_EVEN = 1
    _BETA_ODD = 17
    
    _GAMMA = [0, 8, 16, 24, 24, 16, 8, 0]
    
    ## 생성자
    #  @param [in] self 객체 포인터
    #  @param [in] outlenbits 출력 길이 (비트)
    def __init__(self, outlenbits = 256):
        self._init(outlenbits)
    
    
    ## IV 생성 함수 - 224, 256비트의 출력을 위해서는 사전 계산된 값을 사용하고, 그 외의 출력에 대해서는 IV 생성
    #  @param [in] self 객체 포인터
    #  @param [in] outlenbits 출력 길이 (비트)
    def _init_iv(self, outlenbits):
        def generate_iv():
            self._cv  = [32, self._outlenbits] + [0] * 14
            self._compress(self._buf)
        
        if outlenbits <= 0 or outlenbits > 256:
            raise ValueError("outlenbits should be 0 ~ 256")
        
        self._outlenbits = outlenbits
        if self._outlenbits == 224:
            self._cv = self.__IV224[:]
        elif self._outlenbits == 256:
            self._cv = self.__IV256[:]
        else:
            generate_iv()
    
    
    ## 32비트 회전 연산
    #  @param [in] value 회전하고자 하는 값
    #  @param [in] rot 회전량 (비트)
    @staticmethod
    def __rol32(value, rot):
        return ((value << rot) | (value >> (32 - rot))) & MASK_U32
   
          
    ## 스텝 함수
    #  @param [in] idx 스텝 인덱스
    #  @param [in] alpha 회전값 알파
    #  @param [in] beta 회전값 베타
    def _step(self, idx, alpha, beta):
        vl = 0
        vr = 0
        for colidx in range(8):
            vl = (self._cv[colidx    ] ^ self._msg[16 * idx + colidx    ]) & MASK_U32
            vr = (self._cv[colidx + 8] ^ self._msg[16 * idx + colidx + 8]) & MASK_U32
            vl = LSH256.__rol32((vl + vr) & MASK_U32, alpha) ^ self._STEP[8 * idx + colidx]
            vr = LSH256.__rol32((vl + vr) & MASK_U32, beta)
            self._tcv[colidx    ] = (vl + vr) & MASK_U32
            self._tcv[colidx + 8] = LSH256.__rol32(vr, self._GAMMA[colidx])
        
        self._word_permutation()

## 해쉬 함수 wrapper 클래스
class LSHDigest:

    ## 파라미터에 맞는 LSH 알고리즘 객체 생성
    #  @param [in] wordlenbits 워드 길이 (비트) 256, 512만 가능함
    #  @param [in] outlenbits 출력 길이 (비트) 1 ~ 256 (LSH-256) 혹은 1 ~ 512 (LSH-512) 가 가능함
    #  @return LSH 객체
    @staticmethod
    def getInstance(wordlenbits, outlenbits = None):
        if outlenbits is None:
            outlenbits = wordlenbits
        
        if wordlenbits == 256:            
            return LSH256(outlenbits)
        
        else:
            raise ValueError("Unsupported algorithm parameter");


    ## digest 함수 - 최종 해쉬값을 계산하여 리턴한다.
    #  @param [in] wordlenbits 워드 길이 256, 512 중 하나여야 함
    #  @param [in] outlenbits 출력 해시 길이 1 ~ wordlenbits 사이의 값이어야 함
    #  @param [in] data 입력 데이터
    #  @param [in] offset 데이터 시작 오프셋 (바이트)
    #  @param [in] length 데이터 길이 (비트)
    #  @return 계산된 해쉬값
    @staticmethod
    def digest(wordlenbits=256, outlenbits=None, data=None, offset=0, length=-1):
        if outlenbits is None:
            outlenbits = wordlenbits
        
        lsh = LSHDigest.getInstance(wordlenbits, outlenbits)
        return lsh.final(data, offset, length)
