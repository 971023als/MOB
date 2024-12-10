Java.perform(function () {
    console.log("[*] 전자금융 비밀번호 변경 복잡도 검증 및 네트워크 요청 분석 시작...");

    // ======================
    // 1. 비밀번호 관리 클래스
    // ======================
    const PasswordManager = Java.use("com.example.bank.PasswordManager"); // 비밀번호 관리 클래스
    const NetworkManager = Java.use("com.example.network.NetworkManager"); // 네트워크 관리 클래스
    const UsedPasswords = []; // 과거에 사용된 비밀번호를 저장할 배열

    // ===========================================
    // 2. 비밀번호 복잡도 검증
    // ===========================================
    function isPasswordComplexEnough(password) {
        const minLength = 8;
        const hasUpperCase = /[A-Z]/.test(password);
        const hasLowerCase = /[a-z]/.test(password);
        const hasNumber = /\d/.test(password);
        const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

        if (password.length < minLength) {
            console.log("[!] 비밀번호 복잡도 검증 실패: 길이가 충분하지 않습니다 (최소 8자)");
            return false;
        }
        if (!hasUpperCase) {
            console.log("[!] 비밀번호 복잡도 검증 실패: 대문자가 포함되어 있지 않습니다");
            return false;
        }
        if (!hasLowerCase) {
            console.log("[!] 비밀번호 복잡도 검증 실패: 소문자가 포함되어 있지 않습니다");
            return false;
        }
        if (!hasNumber) {
            console.log("[!] 비밀번호 복잡도 검증 실패: 숫자가 포함되어 있지 않습니다");
            return false;
        }
        if (!hasSpecialChar) {
            console.log("[!] 비밀번호 복잡도 검증 실패: 특수 문자가 포함되어 있지 않습니다");
            return false;
        }

        console.log("[+] 비밀번호 복잡도 검증 통과");
        return true;
    }

    PasswordManager.changePassword.implementation = function (oldPassword, newPassword) {
        console.log("[*] changePassword 호출됨");
        console.log(`[+] 기존 비밀번호: ${oldPassword}`);
        console.log(`[+] 새 비밀번호: ${newPassword}`);

        // 비밀번호 복잡도 검증
        if (!isPasswordComplexEnough(newPassword)) {
            console.log("[!] 비밀번호 복잡도 요건 미충족 → 변경 차단");
            return false; // 복잡도 검증 실패로 변경 차단
        }

        // 이전 비밀번호와 비교하여 재사용 여부 확인
        if (UsedPasswords.includes(newPassword)) {
            console.log("[!] 경고: 새 비밀번호가 과거에 사용된 비밀번호와 동일합니다 → 변경 차단");
            return false; // 동일 비밀번호 재사용 차단
        }

        console.log("[+] 정상: 비밀번호 복잡도 및 재사용 검증 통과 → 변경 진행 허용");

        // 원래 동작 수행
        const result = this.changePassword(oldPassword, newPassword);
        console.log(`[+] 비밀번호 변경 처리 결과: ${result}`);

        // 비밀번호 변경 성공 시 새로운 비밀번호를 목록에 추가
        if (result) {
            UsedPasswords.push(newPassword);
            console.log(`[+] 새 비밀번호가 과거 비밀번호 목록에 추가됨: ${newPassword}`);
        }

        return result;
    };

    // ===========================================
    // 3. 네트워크 요청 분석 후킹
    // ===========================================
    NetworkManager.sendRequest.implementation = function (url, data) {
        console.log(`[+] sendRequest 호출됨 - URL: ${url}`);
        console.log(`[+] 요청 데이터: ${JSON.stringify(data)}`);

        // 비밀번호 변경 요청 탐지
        if (url.includes("/changePassword")) {
            console.log("[!] 비밀번호 변경 요청 탐지");
            const requestData = JSON.parse(data);
            console.log(`[+] 요청 데이터 분석: ${JSON.stringify(requestData)}`);

            // 요청 데이터 변조 테스트
            if (requestData.newPassword === "weakpassword") {
                console.log("[!] 경고: 약한 비밀번호가 네트워크 요청에 포함됨 → 변경 차단 가능성");
                return null; // 요청을 차단하거나 변조
            }
        }

        // 원래 동작 수행
        const response = this.sendRequest(url, data);
        console.log(`[+] 네트워크 요청 처리 결과: ${response}`);
        return response;
    };

    console.log("[*] 전자금융 비밀번호 변경 복잡도 검증 및 네트워크 요청 분석 완료.");
});
