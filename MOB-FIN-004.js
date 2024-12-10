Java.perform(function () {
    console.log("[*] 전자금융 거래정보 및 전자서명 무결성 검증 후킹 시작...");

    // ======================
    // 1. 거래정보 클래스 및 메서드
    // ======================
    const TransactionManager = Java.use("com.example.bank.TransactionManager"); // 거래 관리 클래스
    const SignatureManager = Java.use("com.example.bank.SignatureManager");    // 전자서명 관리 클래스

    // ===========================================
    // 2. 거래정보 무결성 검증 후킹 및 분기 처리
    // ===========================================
    TransactionManager.verifyTransactionInfo.implementation = function (transactionInfo, approvalInfo) {
        console.log("[*] verifyTransactionInfo 호출됨");
        console.log(`[+] 예비 거래정보: ${transactionInfo}`);
        console.log(`[+] 본 거래정보: ${approvalInfo}`);

        if (transactionInfo !== approvalInfo) {
            console.log("[+] 테스트: 예비 거래정보와 본 거래정보 불일치 → 오류 반환");
            return false; // 무결성 검증 실패
        }

        // 원래 동작 수행
        const result = this.verifyTransactionInfo(transactionInfo, approvalInfo);
        console.log(`[+] 원래 거래정보 검증 결과: ${result}`);
        return result;
    };

    TransactionManager.verifyFinalApproval.implementation = function (finalInfo, approvedInfo) {
        console.log("[*] verifyFinalApproval 호출됨");
        console.log(`[+] 본 거래정보: ${finalInfo}`);
        console.log(`[+] 최종 승인 정보: ${approvedInfo}`);

        if (finalInfo !== approvedInfo) {
            console.log("[+] 테스트: 본 거래정보와 최종 승인 정보 불일치 → 오류 반환");
            return false; // 최종 승인 정보 불일치 시 실패 처리
        }

        // 원래 동작 수행
        const result = this.verifyFinalApproval(finalInfo, approvedInfo);
        console.log(`[+] 원래 최종 승인 검증 결과: ${result}`);
        return result;
    };

    // ===========================================
    // 3. 전자서명 검증 후킹 및 분기 처리
    // ===========================================
    SignatureManager.verifySignature.implementation = function (signature, publicKey, data) {
        console.log("[*] verifySignature 호출됨");
        console.log(`[+] 서명 값: ${signature}`);
        console.log(`[+] 공개키: ${publicKey}`);
        console.log(`[+] 데이터: ${data}`);

        if (publicKey === "test_public_key") {
            console.log("[+] 테스트: 잘못된 공개키 사용 → 검증 실패 처리");
            return false; // 잘못된 공개키 검증 실패 처리
        }

        if (signature === "fake_signature") {
            console.log("[+] 테스트: 위조된 서명 값 감지 → 검증 실패 처리");
            return false; // 위조 서명 검증 실패 처리
        }

        // 원래 동작 수행
        const result = this.verifySignature(signature, publicKey, data);
        console.log(`[+] 원래 서명 검증 결과: ${result}`);
        return result;
    };

    SignatureManager.generateSignature.implementation = function (privateKey, data) {
        console.log("[*] generateSignature 호출됨");
        console.log(`[+] 개인키: ${privateKey}`);
        console.log(`[+] 데이터: ${data}`);

        // 테스트: 매번 동일한 서명값 반환 시 무결성 검증 실패 처리
        const fakeSignature = "static_signature";
        console.log("[+] 테스트: 동일한 서명값 반환 → 무결성 검증 실패 가능성 테스트");
        return fakeSignature; // 고정된 서명값 반환
    };

    // ===========================================
    // 4. 계좌 인증 및 이체 금액 변조 테스트
    // ===========================================
    TransactionManager.performAccountTransfer.implementation = function (accountNumber, transferAmount) {
        console.log("[*] performAccountTransfer 호출됨");
        console.log(`[+] 계좌번호: ${accountNumber}`);
        console.log(`[+] 이체 금액: ${transferAmount}`);

        if (transferAmount > 1000000) { // 금액 제한 테스트
            console.log("[+] 테스트: 이체 금액 변조 감지 (1,000,000 초과) → 거래 차단");
            return false; // 이체 금액 제한 초과 시 거래 차단
        }

        // 원래 동작 수행
        const result = this.performAccountTransfer(accountNumber, transferAmount);
        console.log(`[+] 원래 계좌 이체 결과: ${result}`);
        return result;
    };

    // ===========================================
    // 5. 인증서 발급 비용 변조 테스트
    // ===========================================
    SignatureManager.issueCertificate.implementation = function (userInfo, cost) {
        console.log("[*] issueCertificate 호출됨");
        console.log(`[+] 사용자 정보: ${userInfo}`);
        console.log(`[+] 인증서 발급 비용: ${cost}`);

        if (cost < 0) {
            console.log("[+] 테스트: 발급 비용 변조 감지 (음수 값) → 발급 차단");
            return false; // 잘못된 비용으로 발급 차단
        }

        // 원래 동작 수행
        const result = this.issueCertificate(userInfo, cost);
        console.log(`[+] 원래 인증서 발급 결과: ${result}`);
        return result;
    };

    console.log("[*] 전자금융 거래정보 및 전자서명 무결성 검증 후킹 완료.");
});
