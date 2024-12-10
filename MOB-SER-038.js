Java.perform(function () {
    console.log("[*] Starting HTTP Method Monitoring");

    // OkHttpClient 클래스 후킹
    var OkHttpClientClass = Java.use("okhttp3.OkHttpClient");
    var RequestClass = Java.use("okhttp3.Request");
    var RequestBuilderClass = Java.use("okhttp3.Request$Builder");

    // HTTP Request를 생성하는 과정 후킹
    RequestBuilderClass.method.overload('java.lang.String', 'okhttp3.RequestBody').implementation = function (method, body) {
        console.log("[*] HTTP Method Detected: " + method);

        // 불필요한 메서드 탐지
        var disallowedMethods = ["PUT", "DELETE", "TRACE"];
        if (disallowedMethods.indexOf(method.toUpperCase()) !== -1) {
            console.warn("[!] Disallowed HTTP Method Used: " + method);
        }

        return this.method(method, body);
    };

    // OkHttpClient의 네트워크 요청 확인
    OkHttpClientClass.newCall.overload('okhttp3.Request').implementation = function (request) {
        console.log("[*] HTTP Request Sent: " + request.method());
        console.log("    URL: " + request.url());

        return this.newCall(request);
    };

    console.log("[*] HTTP Method Monitoring Hooks Installed");
});
