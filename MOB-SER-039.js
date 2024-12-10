Java.perform(function () {
    console.log("[*] Starting Admin Page Access Monitoring");

    // OkHttpClient 클래스 후킹
    var OkHttpClientClass = Java.use("okhttp3.OkHttpClient");
    var RequestClass = Java.use("okhttp3.Request");
    var HttpUrlClass = Java.use("okhttp3.HttpUrl");

    // HTTP Request 확인
    OkHttpClientClass.newCall.overload('okhttp3.Request').implementation = function (request) {
        var url = request.url().toString();
        console.log("[*] HTTP Request Sent: " + url);

        // 관리자 페이지 URL 패턴 탐지
        var adminPaths = ["/admin", "/administrator", "/admin/login", "/admin-panel", "/manage"];
        for (var i = 0; i < adminPaths.length; i++) {
            if (url.includes(adminPaths[i])) {
                console.warn("[!] Potential Admin Page Access Detected: " + url);
            }
        }

        return this.newCall(request);
    };

    console.log("[*] Admin Page Access Monitoring Hooks Installed");
});
