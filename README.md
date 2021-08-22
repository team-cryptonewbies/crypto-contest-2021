# 2021 암호분석경진대회 답안 Repo

2021년에는 [@E01x001](https://github.com/E01x001)하고 같이 출전함.

## 1번 고전암호 문제

뭘 하라는건지 모르겠음 ㅇㅅㅇ

## 2번 블록암호 문제 (`block-cipher` 디렉토리)

경량 암호 PRINCE64/128 깨기

문제에서 주어진 데이터가 한 nibble씩 변하는 것을 보면, Integral Cryptanalysis를 활용하라는 것임을 알 수 있음.

## 3번 암호응용 문제 (`stack-processor` 디렉토리)

스택 프로세서 에뮬레이터를 구현하고 거기서 ECDSA까지 하기
