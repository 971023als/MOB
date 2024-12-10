Java.perform(function () {
    console.log("[*] Starting Unnecessary File Exposure Monitoring");

    // OkHttpClient 및 관련 클래스 후킹
    var OkHttpClientClass = Java.use("okhttp3.OkHttpClient");
    var RequestClass = Java.use("okhttp3.Request");

    // HTTP 요청 감지 및 검사
    OkHttpClientClass.newCall.overload('okhttp3.Request').implementation = function (request) {
        var url = request.url().toString();
        console.log("[*] HTTP Request Sent: " + url);

        // 점검 대상 파일 및 경로 리스트
        var unnecessaryPaths = [
            "/test", "/backup", "/sample", "/debug",
            "/temp", "/old", "/dev", "/admin/test",
            "/admin/debug", "/.git", "/.svn", "/backup.zip"
        ];

        for (var i = 0; i < unnecessaryPaths.length; i++) {
            if (url.includes(unnecessaryPaths[i])) {
                console.warn("[!] Unnecessary File/Path Detected: " + url);
            }
        }

        return this.newCall(request);
    };

    console.log("[*] Unnecessary File Exposure Monitoring Hooks Installed");
});
