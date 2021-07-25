"""
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
"""

import struct

## LSH 추상 클래스
class LSHTemplate:

    _MASK = 0
    _WORDBITLEN = None
    _NUMSTEP = 0
    _BLOCKSIZE = 0
    _FORMAT_IN = ""
    _FORMAT_OUT = ""

    _outlenbits = 0
    _boff = 0
    _cv = []
    _tcv = []
    _msg = []
    _buf = []

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
        block = bytearray(data[offset : offset + self._BLOCKSIZE])
        self._msg[0:32] = struct.unpack(
            self._FORMAT_IN, block[0 : self._BLOCKSIZE]
        )  # noqa

        for i in range(2, self._NUMSTEP + 1):  # noqa
            idx = 16 * i
            self._msg[idx] = (self._msg[idx - 16] + self._msg[idx - 29]) & self._MASK
            self._msg[idx + 1] = (
                self._msg[idx - 15] + self._msg[idx - 30]
            ) & self._MASK
            self._msg[idx + 2] = (
                self._msg[idx - 14] + self._msg[idx - 32]
            ) & self._MASK
            self._msg[idx + 3] = (
                self._msg[idx - 13] + self._msg[idx - 31]
            ) & self._MASK
            self._msg[idx + 4] = (
                self._msg[idx - 12] + self._msg[idx - 25]
            ) & self._MASK
            self._msg[idx + 5] = (
                self._msg[idx - 11] + self._msg[idx - 28]
            ) & self._MASK
            self._msg[idx + 6] = (
                self._msg[idx - 10] + self._msg[idx - 27]
            ) & self._MASK
            self._msg[idx + 7] = (self._msg[idx - 9] + self._msg[idx - 26]) & self._MASK
            self._msg[idx + 8] = (self._msg[idx - 8] + self._msg[idx - 21]) & self._MASK
            self._msg[idx + 9] = (self._msg[idx - 7] + self._msg[idx - 22]) & self._MASK
            self._msg[idx + 10] = (
                self._msg[idx - 6] + self._msg[idx - 24]
            ) & self._MASK
            self._msg[idx + 11] = (
                self._msg[idx - 5] + self._msg[idx - 23]
            ) & self._MASK
            self._msg[idx + 12] = (
                self._msg[idx - 4] + self._msg[idx - 17]
            ) & self._MASK
            self._msg[idx + 13] = (
                self._msg[idx - 3] + self._msg[idx - 20]
            ) & self._MASK
            self._msg[idx + 14] = (
                self._msg[idx - 2] + self._msg[idx - 19]
            ) & self._MASK
            self._msg[idx + 15] = (
                self._msg[idx - 1] + self._msg[idx - 18]
            ) & self._MASK

    ## 워드 단위 순환 함수
    #  @param [in] self 객체 포인터
    def _word_permutation(self):
        self._cv[0] = self._tcv[6]
        self._cv[1] = self._tcv[4]
        self._cv[2] = self._tcv[5]
        self._cv[3] = self._tcv[7]
        self._cv[4] = self._tcv[12]
        self._cv[5] = self._tcv[15]
        self._cv[6] = self._tcv[14]
        self._cv[7] = self._tcv[13]
        self._cv[8] = self._tcv[2]
        self._cv[9] = self._tcv[0]
        self._cv[10] = self._tcv[1]
        self._cv[11] = self._tcv[3]
        self._cv[12] = self._tcv[8]
        self._cv[13] = self._tcv[11]
        self._cv[14] = self._tcv[10]
        self._cv[15] = self._tcv[9]

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
    def _compress(self, data, offset=0):
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
    def update(self, data, offset=0, length=-1):
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
            self._buf[buf_idx : self._BLOCKSIZE] = data[offset : offset + gap]
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
            self._buf[buf_idx : buf_idx + len_bytes] = data[offset : offset + len_bytes]
            self._boff += len_bytes << 3
            offset += len_bytes

        if len_bits > 0:
            buf_idx = self._boff >> 3
            self._buf[buf_idx] = data[offset] & ((0xFF >> len_bits) ^ 0xFF)
            self._boff += len_bits

    ## 종료 함수 - 최종 해쉬 값을 계산하여 리턴한다
    #  @param [in] self 객체 포인터
    #  @param [in] data 입력 데이터
    #  @param [in] offset 데이터 시작 오프셋 (바이트)
    #  @param [in] length 데이터 길이 (비트)
    #  @return 계산된 해쉬값
    def final(self, data=None, offset=0, length=-1):
        if data is not None:
            self.update(data, offset, length)

        rbytes = self._boff >> 3
        rbits = self._boff & 0x7

        if rbits > 0:
            self._buf[rbytes] |= 0x1 << (7 - rbits)
        else:
            self._buf[rbytes] = 0x80

        pos = rbytes + 1
        if pos < self._BLOCKSIZE:
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

        result = bytearray(
            struct.pack(
                self._FORMAT_OUT,
                temp[0],
                temp[1],
                temp[2],
                temp[3],
                temp[4],
                temp[5],
                temp[6],
                temp[7],
            )
        )
        result = result[0:rbytes]
        if rbits > 0:
            result[rbytes - 1] &= 0xFF << (8 - rbits)

        return result


MASK_U32 = 0xFFFFFFFF

## LSH256 구현 클래스
class LSH256(LSHTemplate):

    _MASK = MASK_U32
    _BLOCKSIZE = 128
    _NUMSTEP = 26
    _FORMAT_IN = "<LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL"
    _FORMAT_OUT = "<LLLLLLLL"

    ## 사전 계산된 224비트 출력용 IV
    __IV224 = [
        0x068608D3,
        0x62D8F7A7,
        0xD76652AB,
        0x4C600A43,
        0xBDC40AA8,
        0x1ECA0B68,
        0xDA1A89BE,
        0x3147D354,
        0x707EB4F9,
        0xF65B3862,
        0x6B0B2ABE,
        0x56B8EC0A,
        0xCF237286,
        0xEE0D1727,
        0x33636595,
        0x8BB8D05F,
    ]

    ## 사전 계산된 256비트 출력용 IV
    __IV256 = [
        0x46A10F1F,
        0xFDDCE486,
        0xB41443A8,
        0x198E6B9D,
        0x3304388D,
        0xB0F5A3C7,
        0xB36061C4,
        0x7ADBD553,
        0x105D5378,
        0x2F74DE54,
        0x5C2F2D95,
        0xF2553FBE,
        0x8051357A,
        0x138668C8,
        0x47AA4484,
        0xE01AFB41,
    ]

    ## STEP 상수
    _STEP = [
        0x917CAF90,
        0x6C1B10A2,
        0x6F352943,
        0xCF778243,
        0x2CEB7472,
        0x29E96FF2,
        0x8A9BA428,
        0x2EEB2642,
        0x0E2C4021,
        0x872BB30E,
        0xA45E6CB2,
        0x46F9C612,
        0x185FE69E,
        0x1359621B,
        0x263FCCB2,
        0x1A116870,
        0x3A6C612F,
        0xB2DEC195,
        0x02CB1F56,
        0x40BFD858,
        0x784684B6,
        0x6CBB7D2E,
        0x660C7ED8,
        0x2B79D88A,
        0xA6CD9069,
        0x91A05747,
        0xCDEA7558,
        0x00983098,
        0xBECB3B2E,
        0x2838AB9A,
        0x728B573E,
        0xA55262B5,
        0x745DFA0F,
        0x31F79ED8,
        0xB85FCE25,
        0x98C8C898,
        0x8A0669EC,
        0x60E445C2,
        0xFDE295B0,
        0xF7B5185A,
        0xD2580983,
        0x29967709,
        0x182DF3DD,
        0x61916130,
        0x90705676,
        0x452A0822,
        0xE07846AD,
        0xACCD7351,
        0x2A618D55,
        0xC00D8032,
        0x4621D0F5,
        0xF2F29191,
        0x00C6CD06,
        0x6F322A67,
        0x58BEF48D,
        0x7A40C4FD,
        0x8BEEE27F,
        0xCD8DB2F2,
        0x67F2C63B,
        0xE5842383,
        0xC793D306,
        0xA15C91D6,
        0x17B381E5,
        0xBB05C277,
        0x7AD1620A,
        0x5B40A5BF,
        0x5AB901A2,
        0x69A7A768,
        0x5B66D9CD,
        0xFDEE6877,
        0xCB3566FC,
        0xC0C83A32,
        0x4C336C84,
        0x9BE6651A,
        0x13BAA3FC,
        0x114F0FD1,
        0xC240A728,
        0xEC56E074,
        0x009C63C7,
        0x89026CF2,
        0x7F9FF0D0,
        0x824B7FB5,
        0xCE5EA00F,
        0x605EE0E2,
        0x02E7CFEA,
        0x43375560,
        0x9D002AC7,
        0x8B6F5F7B,
        0x1F90C14F,
        0xCDCB3537,
        0x2CFEAFDD,
        0xBF3FC342,
        0xEAB7B9EC,
        0x7A8CB5A3,
        0x9D2AF264,
        0xFACEDB06,
        0xB052106E,
        0x99006D04,
        0x2BAE8D09,
        0xFF030601,
        0xA271A6D6,
        0x0742591D,
        0xC81D5701,
        0xC9A9E200,
        0x02627F1E,
        0x996D719D,
        0xDA3B9634,
        0x02090800,
        0x14187D78,
        0x499B7624,
        0xE57458C9,
        0x738BE2C9,
        0x64E19D20,
        0x06DF0F36,
        0x15D1CB0E,
        0x0B110802,
        0x2C95F58C,
        0xE5119A6D,
        0x59CD22AE,
        0xFF6EAC3C,
        0x467EBD84,
        0xE5EE453C,
        0xE79CD923,
        0x1C190A0D,
        0xC28B81B8,
        0xF6AC0852,
        0x26EFD107,
        0x6E1AE93B,
        0xC53C41CA,
        0xD4338221,
        0x8475FD0A,
        0x35231729,
        0x4E0D3A7A,
        0xA2B45B48,
        0x16C0D82D,
        0x890424A9,
        0x017E0C8F,
        0x07B5A3F5,
        0xFA73078E,
        0x583A405E,
        0x5B47B4C8,
        0x570FA3EA,
        0xD7990543,
        0x8D28CE32,
        0x7F8A9B90,
        0xBD5998FC,
        0x6D7A9688,
        0x927A9EB6,
        0xA2FC7D23,
        0x66B38E41,
        0x709E491A,
        0xB5F700BF,
        0x0A262C0F,
        0x16F295B9,
        0xE8111EF5,
        0x0D195548,
        0x9F79A0C5,
        0x1A41CFA7,
        0x0EE7638A,
        0xACF7C074,
        0x30523B19,
        0x09884ECF,
        0xF93014DD,
        0x266E9D55,
        0x191A6664,
        0x5C1176C1,
        0xF64AED98,
        0xA4B83520,
        0x828D5449,
        0x91D71DD8,
        0x2944F2D6,
        0x950BF27B,
        0x3380CA7D,
        0x6D88381D,
        0x4138868E,
        0x5CED55C4,
        0x0FE19DCB,
        0x68F4F669,
        0x6E37C8FF,
        0xA0FE6E10,
        0xB44B47B0,
        0xF5C0558A,
        0x79BF14CF,
        0x4A431A20,
        0xF17F68DA,
        0x5DEB5FD1,
        0xA600C86D,
        0x9F6C7EB0,
        0xFF92F864,
        0xB615E07F,
        0x38D3E448,
        0x8D5D3A6A,
        0x70E843CB,
        0x494B312E,
        0xA6C93613,
        0x0BEB2F4F,
        0x928B5D63,
        0xCBF66035,
        0x0CB82C80,
        0xEA97A4F7,
        0x592C0F3B,
        0x947C5F77,
        0x6FFF49B9,
        0xF71A7E5A,
        0x1DE8C0F5,
        0xC2569600,
        0xC4E4AC8C,
        0x823C9CE1,
    ]

    _ALPHA_EVEN = 29
    _ALPHA_ODD = 5

    _BETA_EVEN = 1
    _BETA_ODD = 17

    _GAMMA = [0, 8, 16, 24, 24, 16, 8, 0]

    ## 생성자
    #  @param [in] self 객체 포인터
    #  @param [in] outlenbits 출력 길이 (비트)
    def __init__(self, outlenbits=256):
        self._init(outlenbits)

    ## IV 생성 함수 - 224, 256비트의 출력을 위해서는 사전 계산된 값을 사용하고, 그 외의 출력에 대해서는 IV 생성
    #  @param [in] self 객체 포인터
    #  @param [in] outlenbits 출력 길이 (비트)
    def _init_iv(self, outlenbits):
        def generate_iv():
            self._cv = [32, self._outlenbits] + [0] * 14
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
            vl = (self._cv[colidx] ^ self._msg[16 * idx + colidx]) & MASK_U32
            vr = (self._cv[colidx + 8] ^ self._msg[16 * idx + colidx + 8]) & MASK_U32
            vl = (
                LSH256.__rol32((vl + vr) & MASK_U32, alpha)
                ^ self._STEP[8 * idx + colidx]
            )
            vr = LSH256.__rol32((vl + vr) & MASK_U32, beta)
            self._tcv[colidx] = (vl + vr) & MASK_U32
            self._tcv[colidx + 8] = LSH256.__rol32(vr, self._GAMMA[colidx])

        self._word_permutation()


## 해쉬 함수 wrapper 클래스
class LSHDigest:

    ## 파라미터에 맞는 LSH 알고리즘 객체 생성
    #  @param [in] wordlenbits 워드 길이 (비트) 256, 512만 가능함
    #  @param [in] outlenbits 출력 길이 (비트) 1 ~ 256 (LSH-256) 혹은 1 ~ 512 (LSH-512) 가 가능함
    #  @return LSH 객체
    @staticmethod
    def getInstance(wordlenbits, outlenbits=None):
        if outlenbits is None:
            outlenbits = wordlenbits

        if wordlenbits == 256:
            return LSH256(outlenbits)

        else:
            raise ValueError("Unsupported algorithm parameter")

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
