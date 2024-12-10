Java.perform(function () {
    console.log("[*] 전자금융 비밀번호 변경 본인확인 검증 후킹 시작...");

    // ======================
    // 1. 인증 및 비밀번호 관리 클래스
    // ======================
    const AuthManager = Java.use("com.example.bank.AuthManager"); // 인증 관리 클래스
    const PasswordManager = Java.use("com.example.bank.PasswordManager"); // 비밀번호 관리 클래스

    // ===========================================
    // 2. 비밀번호 변경 요청 후킹 및 본인확인 절차 검증
    // ===========================================
    PasswordManager.changePassword.implementation = function (oldPassword, newPassword, verificationCode) {
        console.log("[*] changePassword 호출됨");
        console.log(`[+] 기존 비밀번호: ${oldPassword}`);
        console.log(`[+] 새 비밀번호: ${newPassword}`);
        console.log(`[+] 본인확인 코드: ${verificationCode}`);

        // 본인확인 코드 유무 확인
        if (!verificationCode || verificationCode.length === 0) {
            console.log("[!] 경고: 본인확인 절차 없이 비밀번호 변경 요청 감지 → 차단 처리");
            return false; // 본인확인 절차가 없는 경우 변경 차단
        }

        // 본인확인 코드 유효성 검증
        const isCodeValid = AuthManager.validateVerificationCode(verificationCode);
        if (!isCodeValid) {
            console.log("[!] 경고: 잘못된 본인확인 코드 감지 → 비밀번호 변경 차단");
            return false; // 잘못된 본인확인 코드로 변경 차단
        }

        console.log("[+] 정상: 본인확인 절차 통과 → 비밀번호 변경 진행");

        // 원래 동작 수행
        const result = this.changePassword(oldPassword, newPassword, verificationCode);
        console.log(`[+] 비밀번호 변경 처리 결과: ${result}`);
        return result;
    };

    // ===========================================
    // 3. 본인확인 코드 검증 메서드 후킹
    // ===========================================
    AuthManager.validateVerificationCode.implementation = function (verificationCode) {
        console.log(`[+] validateVerificationCode 호출됨 - 본인확인 코드: ${verificationCode}`);

        // 테스트용으로 잘못된 코드 처리
        if (verificationCode === "000000") {
            console.log("[!] 테스트: 잘못된 본인확인 코드 '000000' 입력 → 검증 실패 처리");
            return false;
        }

        // 원래 동작 수행
        const result = this.validateVerificationCode(verificationCode);
        console.log(`[+] 원래 본인확인 코드 검증 결과: ${result}`);
        return result;
    };

    // ===========================================
    // 4. 테스트용 비밀번호 변경 시도
    // ===========================================
    PasswordManager.simulatePasswordChange.implementation = function (oldPassword, newPassword) {
        console.log(`[+] simulatePasswordChange 호출됨 - 기존 비밀번호: ${oldPassword}, 새 비밀번호: ${newPassword}`);

        // 본인확인 절차 없이 변경 시도
        const isVerified = AuthManager.validateVerificationCode(null);
        if (!isVerified) {
            console.log("[!] 테스트: 본인확인 절차 없이 비밀번호 변경 시도 → 차단 처리");
            return false;
        }

        console.log("[+] 테스트: 본인확인 절차가 누락되었음에도 변경이 정상 처리됨 → 보안 취약점 가능성");
        return true; // 테스트 목적으로 변경 처리
    };

    console.log("[*] 전자금융 비밀번호 변경 본인확인 검증 후킹 완료.");
});
