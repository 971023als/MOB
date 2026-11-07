Java.perform(function () {
    console.log("[*] Starting Authentication Error Limit Detection Script");

    // 인증 로직을 처리하는 주요 클래스 및 메서드 확인

    // 민감정보 평문 로깅 방지: 값 대신 길이만 남긴다
    function mask(value) {
        if (value === null || value === undefined) return "(null)";
        return "***" + "(len=" + value.toString().length + ")";
    }

    var AuthClass = Java.use("com.example.auth.AuthManager"); // 인증 관련 클래스
    var AuthMethod = AuthClass.validateCredentials; // 예: 비밀번호 검증 메서드

    AuthMethod.implementation = function (username, password) {
        console.log("[*] Intercepted authentication attempt:");
        console.log("  Username: " + username);
        console.log("  Password: " + mask(password));

        // 호출 전 상태 확인
        var errorCount = this.getErrorCount(); // 가정: 인증 실패 횟수 확인 메서드
        console.log("[*] Current error count: " + errorCount);

        // 호출 후 상태 확인
        var result = this.validateCredentials(username, password);
        if (!result) {
            var newErrorCount = this.getErrorCount();
            console.log("[!] Authentication failed. Updated error count: " + newErrorCount);

            if (newErrorCount >= 5) {
                console.warn("[!] Error limit reached. Account should be locked.");
            }
        } else {
            console.log("[+] Authentication succeeded.");
        }

        return result;
    };

    console.log("[*] Authentication Error Limit Hook installed");
});
