Java.perform(function () {
    console.log("[*] 세션 타임아웃 감지 스크립트 시작");

    // 세션 매니저 클래스 후킹
    var SessionManagerClass = Java.use("com.example.session.SessionManager"); // 실제 세션 매니저 클래스 이름으로 변경

    // 세션 초기화 메서드 후킹
    SessionManagerClass.startSession.implementation = function (userId) {
        console.log(`[+] 세션이 시작되었습니다 - 사용자 ID: ${userId}`);

        // 세션 타임아웃 값 확인
        var timeout = this.getSessionTimeout();
        console.log(`[+] 세션 타임아웃 값: ${timeout}초`);

        // 권장 타임아웃 값 초과 시 경고
        if (timeout > 600) { // 600초 = 10분
            console.warn("[!] 세션 타임아웃이 너무 깁니다. 권장 값은 600초 이하입니다.");
        }

        return this.startSession(userId);
    };

    // 세션 만료 메서드 후킹
    SessionManagerClass.endSession.implementation = function () {
        try {
            console.log("[+] 세션 종료 프로세스가 시작되었습니다.");

            // 세션 만료 작업 수행
            var result = this.endSession();
            console.log("[+] 세션이 성공적으로 종료되었습니다.");

            return result;
        } catch (e) {
            console.error(`[!] 세션 종료 중 오류 발생: ${e.message}`);
            throw e; // 오류 재발생
        }
    };

    console.log("[*] 세션 타임아웃 감지 후킹 설치 완료");
});
