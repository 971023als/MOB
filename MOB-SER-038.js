Java.perform(function () {
    console.log("[*] HTTP 메서드 모니터링 시작");

    // OkHttpClient 및 관련 클래스 로드
    var OkHttpClientClass = Java.use("okhttp3.OkHttpClient");
    var RequestBuilderClass = Java.use("okhttp3.Request$Builder");

    // HTTP 요청 생성 과정 후킹
    RequestBuilderClass.method.overload('java.lang.String', 'okhttp3.RequestBody').implementation = function (method, body) {
        console.log(`[+] HTTP 메서드 감지됨: ${method}`);

        // 허용되지 않는 메서드 탐지
        var disallowedMethods = ["PUT", "DELETE", "TRACE"];
        if (disallowedMethods.includes(method.toUpperCase())) {
            console.warn(`[!] 허용되지 않은 HTTP 메서드 사용됨: ${method}`);
        }

        return this.method(method, body);
    };

    // HTTP 요청 확인
    OkHttpClientClass.newCall.overload('okhttp3.Request').implementation = function (request) {
        var method = request.method();
        var url = request.url().toString();
        console.log(`[+] HTTP 요청 감지됨 - 메서드: ${method}, URL: ${url}`);

        // 추가 점검 가능: 특정 조건 만족 시 경고 출력
        if (url.includes("/sensitive") || method === "TRACE") {
            console.warn(`[!] 민감한 요청 감지 - 메서드: ${method}, URL: ${url}`);
        }

        return this.newCall(request);
    };

    console.log("[*] HTTP 메서드 모니터링 후킹 완료");
});
