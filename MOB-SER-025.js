Java.perform(function () {
    console.log("[*] Frida Script for Detecting Sensitive Information in App Source Code Started");

    // 민감한 키워드 목록 정의
    var sensitiveKeywords = ["password", "secret", "apikey", "admin", "encrypt", "key", "credential"];

    // Java String 클래스를 후킹하여 하드코딩된 민감 데이터 탐지
    var String = Java.use("java.lang.String");

    String.$init.overload('java.lang.String').implementation = function (str) {
        if (str !== null) {
            sensitiveKeywords.forEach(function (keyword) {
                if (str.toLowerCase().includes(keyword)) {
                    console.warn(`[!] 민감 정보 노출 감지! 문자열: ${str}`);
                }
            });
        }
        return this.$init(str);
    };

    // SharedPreferences 탐지: 민감 정보 저장 여부 점검
    var SharedPreferences = Java.use("android.content.SharedPreferences");
    var SharedPreferencesEditor = Java.use("android.content.SharedPreferences$Editor");

    SharedPreferencesEditor.putString.overload('java.lang.String', 'java.lang.String').implementation = function (key, value) {
        console.log("[*] SharedPreferences.putString() 호출 감지");
        console.log("    Key: " + key + ", Value: " + value);

        sensitiveKeywords.forEach(function (keyword) {
            if (key.toLowerCase().includes(keyword) || value.toLowerCase().includes(keyword)) {
                console.error(`[!] 민감 키워드 (${keyword}) 발견! Key: ${key}, Value: ${value}`);
            }
        });

        return this.putString(key, value);
    };

    // 네트워크 요청 데이터 점검 (OkHttp 예제)
    var OkHttpClient = Java.use("okhttp3.Request");
    OkHttpClient.body.overload().implementation = function () {
        var body = this.body();
        console.log("[*] HTTP 요청 Body 데이터 점검");

        if (body) {
            var bodyContent = body.toString();
            sensitiveKeywords.forEach(function (keyword) {
                if (bodyContent.toLowerCase().includes(keyword)) {
                    console.error(`[!] HTTP Body에 민감 키워드 (${keyword}) 포함됨: ${bodyContent}`);
                }
            });
        }
        return body;
    };

    // Native Code (JNI) 및 리소스 파일 점검
    Java.perform(function () {
        var AssetManager = Java.use("android.content.res.AssetManager");

        AssetManager.open.overload('java.lang.String').implementation = function (fileName) {
            console.log("[*] Asset 파일 접근 감지: " + fileName);

            if (fileName.endsWith(".so") || fileName.endsWith(".dex") || fileName.endsWith(".txt")) {
                console.log("[*] 민감 파일 의심됨: " + fileName);
            }

            return this.open(fileName);
        };
    });
});
