Java.perform(function () {
    console.log("[*] 통신 암호화 점검 스크립트 시작");

    // HttpURLConnection 후킹
    var HttpURLConnection = Java.use("java.net.HttpURLConnection");
    HttpURLConnection.setRequestMethod.implementation = function (method) {
        console.log("[+] HttpURLConnection.setRequestMethod() 호출됨");
        console.log("    요청 메서드: " + method);
        if (method.toUpperCase() === "HTTP") {
            console.warn("[!] 안전하지 않은 프로토콜 탐지됨: HTTP (암호화되지 않음)");
        } else if (method.toUpperCase() === "HTTPS") {
            console.log("[+] 안전한 프로토콜 사용됨: HTTPS");
        } else {
            console.warn("[!] 알 수 없는 프로토콜 요청: " + method);
        }
        return this.setRequestMethod(method);
    };

    // SSL/TLS Context 후킹
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    SSLContext.init.implementation = function (keyManager, trustManager, secureRandom) {
        console.log("[+] SSLContext.init() 호출됨");
        var protocol = this.getProtocol();
        console.log("    프로토콜: " + protocol);
        if (protocol === "SSL" || protocol === "TLSv1" || protocol === "TLSv1.1") {
            console.warn("[!] 취약하거나 사용 중단된 프로토콜 탐지됨: " + protocol);
        } else if (protocol === "TLSv1.2" || protocol === "TLSv1.3") {
            console.log("[+] 안전한 프로토콜 사용됨: " + protocol);
        } else {
            console.warn("[!] 알 수 없는 프로토콜 탐지됨: " + protocol);
        }
        return this.init(keyManager, trustManager, secureRandom);
    };

    // OkHttp 클라이언트 HTTP/HTTPS 호출 후킹
    var OkHttpClient = Java.use("okhttp3.OkHttpClient");
    var Request = Java.use("okhttp3.Request");
    var Request$Builder = Java.use("okhttp3.Request$Builder");

    Request$Builder.build.implementation = function () {
        var request = this.build();
        var url = request.url().toString();
        console.log("[+] HTTP 요청 가로채기: " + url);
        if (url.startsWith("http://")) {
            console.warn("[!] 안전하지 않은 HTTP URL 탐지됨: " + url);
        } else if (url.startsWith("https://")) {
            console.log("[+] 안전한 HTTPS URL: " + url);
        } else {
            console.warn("[!] 알 수 없는 URL 스키마 탐지됨: " + url);
        }
        return request;
    };

    // HttpsURLConnection 후킹 (추가 범위)
    var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
    HttpsURLConnection.setDefaultSSLSocketFactory.implementation = function (sslSocketFactory) {
        console.log("[+] HttpsURLConnection.setDefaultSSLSocketFactory() 호출됨");
        if (sslSocketFactory == null) {
            console.warn("[!] SSL 소켓 팩토리가 null로 설정됨. 암호화 비활성 가능성 있음");
        } else {
            console.log("[+] SSL 소켓 팩토리 설정됨: " + sslSocketFactory);
        }
        return this.setDefaultSSLSocketFactory(sslSocketFactory);
    };

    // URL.openConnection 후킹
    var URL = Java.use("java.net.URL");
    URL.openConnection.implementation = function () {
        var connection = this.openConnection();
        console.log("[+] URL.openConnection() 호출됨: " + this.toString());
        return connection;
    };

    // Apache HttpClient 후킹 (추가 범위)
    var HttpClientBuilder = Java.use("org.apache.http.impl.client.HttpClientBuilder");
    HttpClientBuilder.build.implementation = function () {
        console.log("[+] Apache HttpClientBuilder.build() 호출됨");
        var client = this.build();
        console.log("[+] Apache HttpClient 생성됨: " + client.toString());
        return client;
    };

    console.log("[*] 통신 암호화 점검 스크립트 설치 완료");
});
