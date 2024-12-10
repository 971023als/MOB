Java.perform(function () {
    console.log("[*] 불필요한 파일 노출 모니터링 시작");

    // OkHttpClient 및 관련 클래스 로드
    var OkHttpClientClass = Java.use("okhttp3.OkHttpClient");
    var RequestClass = Java.use("okhttp3.Request");

    // HTTP 요청 후킹 및 검사
    OkHttpClientClass.newCall.overload('okhttp3.Request').implementation = function (request) {
        var url = request.url().toString();
        console.log(`[+] HTTP 요청 감지 - URL: ${url}`);

        // 점검 대상 파일 및 경로 리스트
        var unnecessaryPaths = [
            "/test", "/backup", "/sample", "/debug",
            "/temp", "/old", "/dev", "/admin/test",
            "/admin/debug", "/.git", "/.svn", "/backup.zip"
        ];

        // URL에서 불필요한 파일 및 경로 탐지
        unnecessaryPaths.forEach(function (path) {
            if (url.includes(path)) {
                console.warn(`[!] 불필요한 파일/경로 탐지됨: ${url}`);
                console.warn(`[!] 문제 경로: ${path}`);
            }
        });

        return this.newCall(request);
    };

    console.log("[*] 불필요한 파일 노출 모니터링 후킹 설치 완료");
});
