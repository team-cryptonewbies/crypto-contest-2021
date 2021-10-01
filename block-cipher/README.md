# PRINCE 전수 조사

> 입력파일 엔디안 몰라서 몇주 날렸음

- `reduced_prince_cipher.py`: 4-round PRINCE 암호 파이썬 구현.
- `prince_integral_attack.py`: Integral cryptanalysis로 `k1 ^ k0'` 을 구함. 키 탐색 공간을 2<sup>128</sup>에서 2<sup>64</sup>로 줄임.
- `analysis.txt`: 키는 영문 소문자라고 했고, 이 때문에 각 바이트의 high 4-bit가 제한적. 쌩노가다로 그냥 구해보면 키의 반은 알수있음. 키 탐색 공간을 2<sup>64</sup>에서 2<sup>32</sup>로 줄임.
- `prince_ref.h`: [PRINCE 암호 레퍼런스 구현](https://github.com/sebastien-riou/prince-c-ref)에서 가져옴. 아파치 라이선스 2.0.
- `bruteforce.cc`: 2<sup>32</sup>의 키 탐색 공간에서 전수조사하는 코드. 몇시간 정도 돌아가고, 정답은 다음과 같음. (꿀팁: 0부터 15까지 입력해서 병렬화하면 좀 더 빠르게 구할거임)

> hzqzzlpsugsuhcpr
