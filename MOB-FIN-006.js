Java.perform(function () {
    console.log("[*] 전자금융 거래 소유주 확인 검증 후킹 시작...");

    // ======================
    // 1. 거래 관리 클래스 및 메서드
    // ======================
    const AccountManager = Java.use("com.example.bank.AccountManager"); // 계좌 관리 클래스
    const TransactionManager = Java.use("com.example.bank.TransactionManager"); // 거래 관리 클래스
    const AuthManager = Java.use("com.example.bank.AuthManager"); // 인증 관리 클래스

    // 현재 로그인된 사용자 정보 저장 (예: 세션 또는 인증 클래스에서 가져옴)
    const currentUser = AuthManager.getCurrentUser();
    console.log(`[+] 현재 로그인된 사용자: ${currentUser}`);

    // ===========================================
    // 2. 계좌 정보 조회 후킹
    // ===========================================
    AccountManager.getAccountDetails.implementation = function (accountNumber) {
        console.log(`[+] getAccountDetails 호출됨 - 계좌 번호: ${accountNumber}`);

        // 계좌 번호 소유주 확인
        const accountOwner = this.getAccountOwner(accountNumber); // 계좌 소유주를 가져오는 가상의 메서드

        if (accountOwner !== currentUser) {
            console.log(`[!] 경고: 계좌 번호 ${accountNumber}는 로그인 사용자와 일치하지 않음! 접근 차단.`);
            return null; // 계좌 정보 반환 차단
        }

        console.log("[+] 정상: 계좌 소유주와 로그인 사용자 일치 → 접근 허용");
        return this.getAccountDetails(accountNumber);
    };

    // ===========================================
    // 3. 거래 요청 시 계좌 번호 검증 후킹
    // ===========================================
    TransactionManager.initiateTransaction.implementation = function (transactionData) {
        console.log("[*] initiateTransaction 호출됨");
        console.log(`[+] 거래 데이터: ${JSON.stringify(transactionData)}`);

        const sourceAccount = transactionData.sourceAccount;
        const destinationAccount = transactionData.destinationAccount;

        // 송금 계좌 소유주 확인
        const sourceOwner = AccountManager.getAccountOwner(sourceAccount);
        if (sourceOwner !== currentUser) {
            console.log(`[!] 경고: 거래 요청에서 송금 계좌 ${sourceAccount}는 로그인 사용자 소유가 아님! 거래 차단.`);
            return false; // 거래 차단
        }

        console.log("[+] 정상: 송금 계좌 소유주 확인 완료 → 거래 진행 허용");

        // 원래 거래 요청 수행
        const result = this.initiateTransaction(transactionData);
        console.log(`[+] 거래 요청 처리 결과: ${result}`);
        return result;
    };

    // ===========================================
    // 4. 테스트용 계좌 번호 변조 시도 감지
    // ===========================================
    TransactionManager.simulateAccountTampering.implementation = function (transactionData) {
        console.log("[*] simulateAccountTampering 호출됨");
        console.log(`[+] 테스트 거래 데이터: ${JSON.stringify(transactionData)}`);

        const tamperedAccount = transactionData.sourceAccount;
        const actualOwner = AccountManager.getAccountOwner(tamperedAccount);

        if (actualOwner !== currentUser) {
            console.log(`[!] 테스트: 변조된 계좌 ${tamperedAccount} 소유주 확인 실패 → 거래 차단.`);
            return false;
        }

        console.log("[+] 테스트: 변조된 계좌 소유주 확인 성공 → 취약점 존재 가능");
        return true; // 테스트 목적으로 정상 처리
    };

    console.log("[*] 전자금융 거래 소유주 확인 검증 후킹 완료.");
});
