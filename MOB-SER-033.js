Java.perform(function () {
    console.log("[*] Starting Session Timeout Detection Script");

    // 세션 매니저 클래스를 후킹
    var SessionManagerClass = Java.use("com.example.session.SessionManager"); // 실제 세션 매니저 클래스 이름으로 변경

    // 세션 초기화 메서드 확인
    SessionManagerClass.startSession.implementation = function (userId) {
        console.log("[*] Session started for user: " + userId);

        var timeout = this.getSessionTimeout(); // 세션 타임아웃 값을 가져오는 가정 메서드
        console.log("[*] Session timeout value: " + timeout + " seconds");

        if (timeout > 600) { // 10분(600초)을 초과하는 경우 경고
            console.warn("[!] Session timeout is too long. Recommended value is 600 seconds or less.");
        }

        return this.startSession(userId);
    };

    // 세션 만료 메서드 확인
    SessionManagerClass.endSession.implementation = function () {
        console.log("[*] Session is being terminated.");
        var result = this.endSession();
        console.log("[*] Session successfully ended.");
        return result;
    };

    console.log("[*] Session Timeout Detection Hook installed");
});
