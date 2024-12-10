Java.perform(function () {
    console.log("[*] 확장된 HttpURLConnection 후킹 스크립트 시작");

    // HttpURLConnection 클래스 및 관련 메서드
    var HttpURLConnection = Java.use("java.net.HttpURLConnection");
    var BufferedReader = Java.use("java.io.BufferedReader");
    var InputStreamReader = Java.use("java.io.InputStreamReader");
    var PrintWriter = Java.use("java.io.PrintWriter");
    var OutputStreamWriter = Java.use("java.io.OutputStreamWriter");
    var ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");

    var sensitiveKeys = ["sessionId", "token", "authToken", "JSESSIONID", "Bearer", "cookie"];

    // URL.openConnection 후킹
    Java.use("java.net.URL").openConnection.overload().implementation = function () {
        var url = this.toString();
        console.log("[+] URL.openConnection 호출됨: " + url);
        return this.openConnection();
    };

    // HttpURLConnection.getRequestMethod 후킹 (요청 메서드 확인)
    HttpURLConnection.getRequestMethod.implementation = function () {
        var method = this.getRequestMethod();
        console.log("[+] HTTP 요청 메서드: " + method);
        if (method === "POST" || method === "PUT") {
            console.log("[!] 데이터 업로드 요청 탐지됨: " + method);
        }
        return method;
    };

    // HttpURLConnection.setRequestProperty 후킹 (헤더 설정 확인)
    HttpURLConnection.setRequestProperty.overload('java.lang.String', 'java.lang.String').implementation = function (key, value) {
        console.log("[+] 요청 헤더 설정됨: " + key + " = " + value);
        for (var i = 0; i < sensitiveKeys.length; i++) {
            if (value.includes(sensitiveKeys[i])) {
                console.warn("[!] 헤더 값에 민감한 키 탐지됨: " + key + " = " + value);
            }
        }
        if (key.toLowerCase() === "authorization" && !value.startsWith("Bearer ")) {
            console.warn("[!] 권한 헤더에 비정상 값 감지됨: " + value);
        }
        return this.setRequestProperty(key, value);
    };

    // HttpURLConnection.getInputStream 후킹 (응답 본문 읽기)
    HttpURLConnection.getInputStream.implementation = function () {
        console.log("[*] HttpURLConnection.getInputStream 후킹...");
        var inputStream = this.getInputStream();
        var reader = BufferedReader.$new(InputStreamReader.$new(inputStream));
        var line;
        console.log("[*] HTTP 응답 본문 읽는 중:");
        while ((line = reader.readLine()) !== null) {
            console.log("    " + line);
            for (var i = 0; i < sensitiveKeys.length; i++) {
                if (line.includes(sensitiveKeys[i])) {
                    console.warn("[!] 응답 본문에 민감한 데이터 탐지됨: " + line);
                }
            }
            if (line.toLowerCase().includes("error") || line.toLowerCase().includes("exception")) {
                console.warn("[!] 응답 본문에 에러 메시지 탐지됨: " + line);
            }
        }
        return inputStream;
    };

    // HttpURLConnection.getOutputStream 후킹 (요청 본문 쓰기)
    HttpURLConnection.getOutputStream.implementation = function () {
        console.log("[*] HttpURLConnection.getOutputStream 후킹...");
        var outputStream = this.getOutputStream();
        var byteStream = ByteArrayOutputStream.$new();
        var writer = PrintWriter.$new(OutputStreamWriter.$new(byteStream));

        writer.write = function (str) {
            console.log("[+] 요청 본문 가로채기: " + str);
            for (var i = 0; i < sensitiveKeys.length; i++) {
                if (str.includes(sensitiveKeys[i])) {
                    console.warn("[!] 요청 본문에 민감한 데이터 탐지됨: " + str);
                }
            }
            if (str.includes("password") || str.includes("passwd")) {
                console.warn("[!] 요청 본문에 비밀번호 관련 데이터 탐지됨: " + str);
            }
            this.write(str);
        };
        writer.close();
        return outputStream;
    };

    // HttpURLConnection.disconnect 후킹
    HttpURLConnection.disconnect.implementation = function () {
        console.log("[*] HttpURLConnection.disconnect 호출됨...");
        this.disconnect();
        console.log("[*] 연결 종료됨");
    };

    console.log("[*] 확장된 HttpURLConnection 후킹 스크립트 설치 완료");
});
