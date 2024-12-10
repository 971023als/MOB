Java.perform(function () {
    console.log("[*] 불충분한 이용자 인증 탐지 및 방지 스크립트 시작");

    // 대상 클래스 및 메서드 설정 (가상 예시)
    const HttpRequest = Java.use("okhttp3.Request"); // HTTP 요청 관련 클래스
    const SharedPreferences = Java.use("android.content.SharedPreferences"); // 인증 토큰 저장소

    // =========================================================
    // 1. HTTP 요청 후킹: 인증 헤더 체크
    // =========================================================
    HttpRequest$Builder.build.implementation = function () {
        console.log("[+] HTTP 요청 감지");

        const request = this.build();
        const headers = request.headers().toString();
        const url = request.url().toString();

        console.log("[-] 요청 URL: " + url);
        console.log("[-] 요청 헤더: " + headers);

        if (!headers.includes("Authorization") || isTokenWeak(headers)) {
            console.warn("[!] 인증 헤더 누락 또는 약한 인증 토큰 탐지");
            alertUser(`인증 헤더가 없거나 약한 인증 토큰이 탐지되었습니다. URL: ${url}`);
            throw new Error("인증 절차 누락 또는 토큰 오류로 요청 차단");
        }

        return request;
    };

    // =========================================================
    // 2. SharedPreferences 접근 감지: 인증 토큰 조작 탐지
    // =========================================================
    SharedPreferences.getString.overload("java.lang.String", "java.lang.String").implementation = function (key, defValue) {
        const value = this.getString(key, defValue);

        console.log("[+] SharedPreferences 접근 감지");
        console.log("[-] Key: " + key + ", Value: " + value);

        if (key === "auth_token" && isTokenWeak(value)) {
            console.warn("[!] 약한 인증 토큰이 저장됨");
            alertUser("저장된 인증 토큰이 약합니다. 보안 점검 필요");
        }

        return value;
    };

    // =========================================================
    // 3. 인증 절차 확인 로직
    // =========================================================
    function isTokenWeak(token) {
        // 약한 토큰 패턴 예시: "12345", "abcdef", 단순 문자 반복 등
        const weakPatterns = ["12345", "abcdef", "test", "0000", "1111"];
        return weakPatterns.some(pattern => token.includes(pattern));
    }

    // =========================================================
    // 4. 사용자 경고 함수
    // =========================================================
    function alertUser(message) {
        Java.scheduleOnMainThread(function () {
            const context = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
            const AlertDialog = Java.use("android.app.AlertDialog");
            const Builder = AlertDialog.Builder;

            const builder = Builder.$new(context);
            builder.setTitle("보안 경고");
            builder.setMessage(message);
            builder.setPositiveButton("확인", null);
            builder.show();
        });
    }

    console.log("[*] 불충분한 이용자 인증 탐지 및 방지 스크립트 완료");
});
