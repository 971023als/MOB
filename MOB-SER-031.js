Java.perform(function () {
    console.log("[*] Starting System Operational Information Leak Detection Script");

    // HTTP 응답 처리 후킹
    var OkHttpResponse = Java.use("okhttp3.Response");
    var ResponseBody = Java.use("okhttp3.ResponseBody");

    OkHttpResponse.body.implementation = function () {
        var body = this.body();
        var content = body.string(); // 응답 본문 추출

        // 민감 정보 패턴 탐지
        var sensitivePatterns = [
            /(?<=<title>).+?Exception.+?(?=<\/title>)/g, // 예외 정보
            /\/var\/www\/html/g,                          // 절대 경로
            /Apache\/\d+\.\d+\.\d+/g,                     // Apache 서버 버전
            /nginx\/\d+\.\d+/g,                           // Nginx 서버 버전
            /root@localhost/g                             // 시스템 계정 정보
        ];

        for (var i = 0; i < sensitivePatterns.length; i++) {
            var matches = content.match(sensitivePatterns[i]);
            if (matches) {
                console.warn("[!] Sensitive information detected: " + matches.join(", "));
            }
        }

        return body; // 원래 응답 반환
    };

    // Logcat에서 시스템 정보 로그 확인
    var LogClass = Java.use("android.util.Log");
    LogClass.d.overload("java.lang.String", "java.lang.String").implementation = function (tag, msg) {
        // 특정 키워드가 포함된 로그 메시지 출력
        var sensitiveKeywords = ["Exception", "StackTrace", "SystemError"];
        for (var j = 0; j < sensitiveKeywords.length; j++) {
            if (msg.includes(sensitiveKeywords[j])) {
                console.warn("[!] Sensitive log message detected: " + msg);
            }
        }

        return this.d(tag, msg);
    };

    console.log("[*] Operational Info Leak Detection Hook installed");
});
