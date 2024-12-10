Java.perform(function () {
    console.log("[*] 관리자 페이지 접근 모니터링 시작");

    // OkHttpClient 및 관련 클래스 로드
    var OkHttpClientClass = Java.use("okhttp3.OkHttpClient");

    // HTTP 요청 후킹
    OkHttpClientClass.newCall.overload('okhttp3.Request').implementation = function (request) {
        var url = request.url().toString();
        console.log(`[+] HTTP 요청 감지됨 - URL: ${url}`);

        // 관리자 페이지 경로 리스트
        var adminPaths = [
            "/admin", "/administrator", "/admin/login", "/admin-panel", "/manage",
            "/control", "/dashboard", "/adminarea", "/adminconsole", "/superuser"
        ];

        // URL에서 관리자 페이지 접근 탐지
        adminPaths.forEach(function (path) {
            if (url.includes(path)) {
                console.warn(`[!] 관리자 페이지 접근 탐지됨: ${url}`);
                console.warn(`[!] 문제 경로: ${path}`);
            }
        });

        return this.newCall(request);
    };

    console.log("[*] 관리자 페이지 접근 모니터링 후킹 설치 완료");
});
