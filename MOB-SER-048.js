Java.perform(function () {
    console.log("[*] Starting Extended HttpURLConnection Hook Script");

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
        console.log("[+] Intercepted URL.openConnection: " + url);
        return this.openConnection();
    };

    // HttpURLConnection.getRequestMethod 후킹 (요청 메서드 확인)
    HttpURLConnection.getRequestMethod.implementation = function () {
        var method = this.getRequestMethod();
        console.log("[+] HTTP Request Method: " + method);
        return method;
    };

    // HttpURLConnection.setRequestProperty 후킹 (헤더 설정 확인)
    HttpURLConnection.setRequestProperty.overload('java.lang.String', 'java.lang.String').implementation = function (key, value) {
        console.log("[+] Set Request Header: " + key + " = " + value);
        for (var i = 0; i < sensitiveKeys.length; i++) {
            if (value.includes(sensitiveKeys[i])) {
                console.warn("[!] Sensitive Key Detected in Header Value: " + value);
            }
        }
        return this.setRequestProperty(key, value);
    };

    // HttpURLConnection.getInputStream 후킹 (응답 본문 읽기)
    HttpURLConnection.getInputStream.implementation = function () {
        console.log("[*] Hooking HttpURLConnection.getInputStream...");
        var inputStream = this.getInputStream();
        var reader = BufferedReader.$new(InputStreamReader.$new(inputStream));
        var line;
        console.log("[*] Reading HTTP Response Body:");
        while ((line = reader.readLine()) !== null) {
            console.log(line);
            for (var i = 0; i < sensitiveKeys.length; i++) {
                if (line.includes(sensitiveKeys[i])) {
                    console.warn("[!] Sensitive Data Found in Response Body: " + line);
                }
            }
        }
        return inputStream;
    };

    // HttpURLConnection.getOutputStream 후킹 (요청 본문 쓰기)
    HttpURLConnection.getOutputStream.implementation = function () {
        console.log("[*] Hooking HttpURLConnection.getOutputStream...");
        var outputStream = this.getOutputStream();
        var byteStream = ByteArrayOutputStream.$new();
        var writer = PrintWriter.$new(OutputStreamWriter.$new(byteStream));
        
        writer.write = function (str) {
            console.log("[+] Intercepted Request Body: " + str);
            for (var i = 0; i < sensitiveKeys.length; i++) {
                if (str.includes(sensitiveKeys[i])) {
                    console.warn("[!] Sensitive Data Found in Request Body: " + str);
                }
            }
            this.write(str);
        };
        writer.close();
        return outputStream;
    };

    // HttpURLConnection.disconnect 후킹
    HttpURLConnection.disconnect.implementation = function () {
        console.log("[*] Hooking HttpURLConnection.disconnect...");
        this.disconnect();
        console.log("[*] Connection Disconnected");
    };

    console.log("[*] Extended HttpURLConnection Hook Script Installed");
});
