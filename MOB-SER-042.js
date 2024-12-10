Java.perform(function () {
    console.log("[*] Starting Debug Log Monitoring");

    // Android Log 클래스 로드
    var Log = Java.use("android.util.Log");

    // 중요 정보 키워드 목록 정의
    var sensitiveKeywords = [
        "password", "card number", "otp", "security code", "social security number",
        "personal info", "authentication", "token", "key", "credential",
        "session", "private", "confidential", "bank account", "pin"
    ];

    // Log.d, Log.e, Log.i, Log.v, Log.w 메서드 후킹
    ["d", "e", "i", "v", "w"].forEach(function (method) {
        Log[method].overload("java.lang.String", "java.lang.String").implementation = function (tag, msg) {
            console.log("[*] Log." + method.toUpperCase() + " - Tag: " + tag + ", Message: " + msg);

            // 메시지에서 중요 정보 키워드 검색
            for (var i = 0; i < sensitiveKeywords.length; i++) {
                if (msg.toLowerCase().includes(sensitiveKeywords[i])) {
                    console.warn("[!] Potential Sensitive Data Exposure Detected in Log!");
                    console.warn("[!] Keyword: " + sensitiveKeywords[i]);
                    console.warn("[!] Message: " + msg);
                }
            }

            // 원래의 Log 메서드 호출
            return this[method](tag, msg);
        };
    });

    console.log("[*] Debug Log Monitoring Hooks Installed");
});
