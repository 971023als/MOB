Java.perform(function () {
    console.log("[*] 전자금융 인증수단 검증 및 SMS/ARS 후킹 시작...");

    // ======================
    // 1. 인증 클래스와 메서드
    // ======================
    const AuthManager = Java.use("com.example.bank.AuthManager");  // 인증 관리 클래스
    const SMSManager = Java.use("com.example.bank.SMSManager");    // SMS 관리 클래스
    const ARSManager = Java.use("com.example.bank.ARSManager");    // ARS 관리 클래스
    const TimeUtils = Java.use("com.example.utils.TimeUtils");     // 유효시간 검증 클래스

    // ===========================================
    // 2. SMS 인증 후킹 및 분기 처리
    // ===========================================
    SMSManager.sendSMS.implementation = function (phoneNumber, message) {
        console.log(`[+] sendSMS 호출됨 - 대상 전화번호: ${phoneNumber}, 메시지 내용: ${message}`);

        if (phoneNumber === "01012345678") {
            console.log("[+] 테스트: 테스트용 번호로 SMS 전송 차단");
            return false; // 특정 번호로 SMS 전송을 차단
        } else if (message.includes("테스트")) {
            console.log("[+] 테스트: '테스트'가 포함된 메시지 전송 감지 → 승인 처리");
            return true; // 테스트 메시지는 항상 승인
        }

        // 원래 동작 수행
        const result = this.sendSMS(phoneNumber, message);
        console.log(`[+] 원래 SMS 전송 결과: ${result}`);
        return result;
    };

    SMSManager.validateSMSCode.implementation = function (smsCode) {
        console.log(`[+] validateSMSCode 호출됨 - 입력 SMS 코드: ${smsCode}`);

        if (smsCode === "000000") {
            console.log("[+] 테스트: 폐기된 SMS 코드 입력 → 인증 강제 성공");
            return true; // 폐기된 SMS 코드 성공 처리
        } else if (smsCode.length !== 6) {
            console.log("[+] 테스트: 잘못된 SMS 코드 길이 입력 → 인증 실패 처리");
            return false; // SMS 코드는 6자리여야 한다는 가정
        }

        // 원래 동작 수행
        const result = this.validateSMSCode(smsCode);
        console.log(`[+] 원래 SMS 코드 인증 결과: ${result}`);
        return result;
    };

    // ===========================================
    // 3. ARS 인증 후킹 및 분기 처리
    // ===========================================
    ARSManager.initiateARSCall.implementation = function (phoneNumber) {
        console.log(`[+] initiateARSCall 호출됨 - 대상 전화번호: ${phoneNumber}`);

        if (phoneNumber === "01098765432") {
            console.log("[+] 테스트: 테스트용 번호로 ARS 호출 차단");
            return false; // 특정 번호로 ARS 호출 차단
        } else {
            console.log("[+] 테스트: 정상 ARS 호출");
        }

        // 원래 동작 수행
        const result = this.initiateARSCall(phoneNumber);
        console.log(`[+] 원래 ARS 호출 결과: ${result}`);
        return result;
    };

    ARSManager.validateARSResponse.implementation = function (responseCode) {
        console.log(`[+] validateARSResponse 호출됨 - 입력 ARS 응답 코드: ${responseCode}`);

        if (responseCode === "1234") {
            console.log("[+] 테스트: 예상 가능한 ARS 응답 코드 입력 → 인증 강제 성공");
            return true;
        } else if (responseCode.length !== 4) {
            console.log("[+] 테스트: 잘못된 ARS 응답 코드 길이 입력 → 인증 실패 처리");
            return false; // ARS 응답 코드는 4자리여야 한다는 가정
        }

        // 원래 동작 수행
        const result = this.validateARSResponse(responseCode);
        console.log(`[+] 원래 ARS 응답 인증 결과: ${result}`);
        return result;
    };

    // ===========================================
    // 4. 인증 유효시간 확인 분기 처리
    // ===========================================
    TimeUtils.isWithinValidTime.implementation = function (time) {
        console.log("[*] isWithinValidTime 호출됨 - 입력 시간: " + time);

        const currentTime = Date.now();
        const timeDifference = currentTime - time;

        console.log(`[+] 현재 시간: ${currentTime}, 입력된 인증 시간: ${time}`);
        console.log(`[+] 시간 차이: ${timeDifference}ms`);

        if (timeDifference > 120000) { // 2분 초과
            console.log("[+] 테스트: 유효시간 초과 상태로 반환 (2분 이상 경과)");
            return false; // 시간 초과로 인증 실패
        } else if (timeDifference > 60000) { // 1~2분 사이
            console.log("[+] 테스트: 경고 - 유효시간이 곧 초과될 예정 (1~2분 경과)");
        } else {
            console.log("[+] 테스트: 유효시간 내 정상 처리");
        }

        // 원래 동작 수행
        const result = this.isWithinValidTime(time);
        console.log("[*] 원래 유효시간 확인 결과: " + result);
        return result;
    };

    // ========================
    // 5. 전체 인증 로깅
    // ========================
    AuthManager.startTransaction.implementation = function (transactionId) {
        console.log(`[+] startTransaction 호출됨 - 거래 ID: ${transactionId}`);

        if (!transactionId) {
            console.log("[+] 테스트: 잘못된 거래 ID (null) → 거래 실패 처리");
            return false;
        }

        // 원래 동작 수행
        const result = this.startTransaction(transactionId);
        console.log(`[+] 거래 시작 결과: ${result}`);
        return result;
    };

    AuthManager.completeTransaction.implementation = function (transactionId) {
        console.log(`[+] completeTransaction 호출됨 - 거래 ID: ${transactionId}`);

        if (transactionId === "test_txn_id") {
            console.log("[+] 테스트: 테스트 거래 ID로 완료 → 성공 처리");
            return true;
        }

        // 원래 동작 수행
        const result = this.completeTransaction(transactionId);
        console.log(`[+] 거래 완료 결과: ${result}`);
        return result;
    };

    console.log("[*] 전자금융 거래 인증 및 SMS/ARS 검증 후킹 완료.");
});
