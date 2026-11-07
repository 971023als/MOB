Java.perform(function () {
    console.log("[*] 확장된 HttpURLConnection 후킹 스크립트 시작");

    // HttpURLConnection 클래스 및 관련 메서드
    var HttpURLConnection = Java.use("java.net.HttpURLConnection");
    var BufferedReader = Java.use("java.io.BufferedReader");
    var InputStreamReader = Java.use("java.io.InputStreamReader");
    var PrintWriter = Java.use("java.io.PrintWriter");
    var OutputStreamWriter = Java.use("java.io.OutputStreamWriter");
    var ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");
    var ByteArrayInputStream = Java.use("java.io.ByteArrayInputStream");

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

        // 스트림을 소비하면 앱이 EOF를 받으므로, 바이트로 모두 읽어 보관하고
        // 분석 후 동일 내용의 새 ByteArrayInputStream을 반환한다.
        var baos = ByteArrayOutputStream.$new();
        var buffer = Java.array("byte", new Array(4096).fill(0));
        var read;
        while ((read = inputStream.read(buffer)) !== -1) {
            baos.write(buffer, 0, read);
        }
        var bodyBytes = baos.toByteArray();

        var reader = BufferedReader.$new(InputStreamReader.$new(ByteArrayInputStream.$new(bodyBytes)));
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
        return ByteArrayInputStream.$new(bodyBytes);
    };

    // HttpURLConnection.getOutputStream 후킹 (요청 본문 쓰기)
    // 기존 코드는 JS에서 Java 객체의 write를 덮어써서 실제로는 가로채기가 동작하지 않았고,
    // 즉시 close()까지 호출해 앱의 전송을 깼다. 요청 본문 감시는 OutputStream.write 후킹이 필요하므로
    // 여기서는 호출 사실만 기록하고 원래 스트림을 그대로 반환한다.
    HttpURLConnection.getOutputStream.implementation = function () {
        console.log("[*] HttpURLConnection.getOutputStream 호출됨 (요청 본문 전송 예정)");
        return this.getOutputStream();
    };

    // HttpURLConnection.disconnect 후킹
    HttpURLConnection.disconnect.implementation = function () {
        console.log("[*] HttpURLConnection.disconnect 호출됨...");
        this.disconnect();
        console.log("[*] 연결 종료됨");
    };

    console.log("[*] 확장된 HttpURLConnection 후킹 스크립트 설치 완료");
});
