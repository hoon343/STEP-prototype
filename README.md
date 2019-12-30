# STEP-prototype

본 repository는 제 졸업논문의 prototype을 구현한 코드를 포함하고 있습니다. 코드는 C++ 14 기준으로 작성되었고, 다음과 같은 라이브러리를 필요로 합니다.

* boost : https://www.boost.org/
* cryptopp : https://www.cryptopp.com/
* libuv : https://libuv.org/

그리고 다음과 같은 wrapper를 요구합니다.

* uvw : https://github.com/skypjack/uvw


![Evaluation](./image/Evaluation.png)

본 repository는 단순한 성능 측정만을 목적으로 하며, 아래와 같은 세 파트로 구분되어 있습니다.
1. Random Transaction Generator
2. Hot node (Block Producer)
3. Cold node (Node-A, B, C, ...)

테스트를 위해서는 다음과 같은 최소조건을 만족하기 위해 최소 두 개 이상의 서버가 필요합니다.  

1. Random Transaction Generator : 1개
2. Hot node : 1개
3. Cold node : 2개 이상

1번과 2번, 그리고 3번 cold node 하나는 같은 서버에서 구동할 수 있습니다.

## 1. Random Transaction Generator

* 성능 측정을 위한 무작위 트랜잭션을 주기적으로 발생시키는 역할을 합니다.
* random_transaction_generator 디렉토리에 저장되어 있습니다.
* boost, libuv 라이브러리를 사용하고, uvw 파일들이 main.cpp와 같은 경로에 있어야 합니다.  
* compile.sh를 실행하여 컴파일 할 수 있습니다. 실행 이전에 compile.sh 파일 끝에 -I로 시작되는 argument에서 -I 이후의 부분을 libuv와 boost 소스코드가 있는 경로로 수정해야 합니다.
* setting.txt는 세 줄로 구성되어 있고 줄마다 각각 hot node의 ip 주소, port 번호, 트랜잭션 생성 주기 (ms 단위)가 기록되어 있습니다.

## 2. Hot node (Block Producer)

* 1.에서 발생한 트랜잭션을 모아 블록을 생성하고 퍼뜨리는 역할을 합니다.
* hotnode 디렉토리에 저장되어 있습니다.
* boost, cryptopp, libuv 라이브러리를 사용하고, uvw 파일들이 main.cpp와 같은 경로에 있어야 합니다.
* dcompile.sh를 실행하여 헤더를 컴파일 할 수 있습니다. 실행 이전에 dcompile.sh 파일 끝에 -I로 시작되는 argument에서 -I 이후의 부분을 cryptopp 소스코드가 있는 경로로 수정해야 합니다.
* 헤더 컴파일이 완료되면, compile.sh를 실행하여 main.cpp를 컴파일 할 수 있습니다. 실행 이전에 compile.sh 파일 끝에 -I로 시작되는 argument에서 -I 이후의 부분을 uvw와 cryptopp 소스코드가 있는 경로로 수정해야 합니다.
* setting.txt는 다음과 같은 구조로 되어 있습니다.

1. 자신의 ip 주소
2. Random transaction generator로부터 트랜잭션을 받을 port 번호
3. 블록을 전송할 cold node의 수
4. (3.에서 기록된 수 만큼 반복) cold node의 ip 주소, 블록을 전송할 port 번호

## 3. Cold node (Node-A, B, C, ...)

* 2.에서 발생한 블록을 검증하고 그 결과를 서로 공유하는 역할을 합니다.
* coldnode 디렉토리에 저장되어 있습니다.
* boost, cryptopp, libuv 라이브러리를 사용하고, uvw 파일들이 main.cpp와 같은 경로에 있어야 합니다.
* dcompile.sh를 실행하여 헤더를 컴파일 할 수 있습니다. (2. 와 같은 헤더를 사용합니다.) 실행 이전에 dcompile.sh 파일 끝에 -I로 시작되는 argument에서 -I 이후의 부분을 cryptopp 소스코드가 있는 경로로 수정해야 합니다.
* 헤더 컴파일이 완료되면, compile.sh를 실행하여 main.cpp를 컴파일 할 수 있습니다. 실행 이전에 compile.sh 파일 끝에 -I로 시작되는 argument에서 -I 이후의 부분을 uvw와 cryptopp 소스코드가 있는 경로로 수정해야 합니다.
* setting.txt는 다음과 같은 구조로 되어 있습니다.

1. 자신의 ip 주소
2. Hot node의 ip 주소
3. Hot node로부터 생성된 블록을 전송받을 port 번호
4. Hot node에게 자신의 검증 결과를 전송할 port 번호
5. 다른 cold node로부터 검증 결과를 전송받을 port 번호
6. 검증에 필요한 최소 node의 수 (아래 8.에서 기록된 수 이하)
7. 자신의 검증 결과를 hot node에게 보낼지 보내지 않을지 여부 (0: 보내지 않는다, 1: 보낸다, 하나의 cold node만 1로 세팅)
8. cold node peer의 수 (전체 cold node 수 - 1)
9. (3.에서 기록된 수 만큼 반복) cold node의 ip 주소, 검증 결과를 전송할 port 번호
