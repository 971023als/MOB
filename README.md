# README - 전자금융 인증 및 SMS/ARS 후킹 스크립트

## 개요

이 스크립트는 Frida를 활용하여 전자금융 거래 애플리케이션의 인증 메서드, SMS 인증, ARS 인증, 그리고 유효시간 검증 로직을 후킹합니다. 후킹된 메서드를 통해 테스트 및 디버깅 목적으로 인증 동작을 검증하거나, 다양한 시나리오에서 예상하지 못한 동작을 시뮬레이션할 수 있습니다.

## 주요 기능

### 1. **SMS 인증 후킹**
- **`sendSMS`**: 특정 번호나 메시지 조건에 따라 SMS 전송을 차단하거나 승인.
- **`validateSMSCode`**: 입력된 SMS 코드에 따라 인증 결과를 강제 성공/실패 처리.

### 2. **ARS 인증 후킹**
- **`initiateARSCall`**: 특정 전화번호에 대한 ARS 호출 차단.
- **`validateARSResponse`**: ARS 응답 코드 길이와 값에 따라 인증 성공/실패 처리.

### 3. **인증 유효시간 검증**
- **`isWithinValidTime`**: 입력된 시간과 현재 시간의 차이에 따라 유효/무효 상태를 반환.

### 4. **거래 관리 로깅**
- **`startTransaction`**: 거래 ID를 검증하여 잘못된 ID에 대한 실패 처리.
- **`completeTransaction`**: 특정 거래 ID를 성공적으로 처리.

### 5. **로그 기록**
- 모든 후킹된 메서드 호출 시 관련 정보를 로그로 출력하여 디버깅 및 검증 가능.

## 설치 및 실행

### 요구 사항
- **Frida**: 후킹 및 디버깅을 위한 필수 도구.
- **JavaScript 환경**: 스크립트를 작성하고 실행하기 위한 환경.
- **Root 권한**: 타겟 애플리케이션에 접근하기 위해 필요할 수 있음.

### 실행 방법
1. **Frida 설치**:
   ```bash
   pip install frida-tools
   ```

2. **스크립트 실행**:
   ```bash
   frida -U -n <target_app> -s <script.js>
   ```

3. **로그 확인**: 스크립트 실행 중 출력되는 로그를 통해 동작 확인.

## 코드 설명

### 주요 클래스 및 메서드

#### 1. 인증 클래스
- **`AuthManager`**:
  - `startTransaction(transactionId)`: 거래 시작 로직 후킹.
  - `completeTransaction(transactionId)`: 거래 완료 로직 후킹.

#### 2. SMS 클래스
- **`SMSManager`**:
  - `sendSMS(phoneNumber, message)`: SMS 전송 로직 후킹.
  - `validateSMSCode(smsCode)`: SMS 코드 검증 로직 후킹.

#### 3. ARS 클래스
- **`ARSManager`**:
  - `initiateARSCall(phoneNumber)`: ARS 호출 로직 후킹.
  - `validateARSResponse(responseCode)`: ARS 응답 코드 검증 로직 후킹.

#### 4. 유효시간 검증 클래스
- **`TimeUtils`**:
  - `isWithinValidTime(time)`: 인증 시간 검증 로직 후킹.

### 테스트 로직
- 특정 전화번호나 메시지 조건에 따라 동작을 분기 처리.
- 테스트용 코드나 잘못된 입력을 기반으로 예상 결과 확인 가능.

## 로그 출력 예시
```text
[*] 전자금융 인증수단 검증 및 SMS/ARS 후킹 시작...
[+] sendSMS 호출됨 - 대상 전화번호: 01012345678, 메시지 내용: 테스트 메시지
[+] 테스트: 테스트용 번호로 SMS 전송 차단
[+] validateSMSCode 호출됨 - 입력 SMS 코드: 000000
[+] 테스트: 폐기된 SMS 코드 입력 → 인증 강제 성공
[+] initiateARSCall 호출됨 - 대상 전화번호: 01098765432
[+] 테스트: 테스트용 번호로 ARS 호출 차단
[*] 전자금융 거래 인증 및 SMS/ARS 검증 후킹 완료.
```

## 참고 사항
- 이 스크립트는 교육 및 디버깅 목적으로만 사용해야 합니다.
- 실제 애플리케이션 환경에서 무단 사용은 법적 문제를 야기할 수 있습니다.
- 테스트 환경에서만 사용을 권장합니다.
