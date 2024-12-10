Java.perform(function () {
    console.log("[*] SSRF 보호 스크립트 시작");

    // HTTPURLConnection, URLConnection 및 관련 클래스 로드
    var HttpURLConnection = Java.use("java.net.HttpURLConnection");
    var URL = Java.use("java.net.URL");
    var URLConnection = Java.use("java.net.URLConnection");

    // URL.openConnection 후킹
    URL.openConnection.overload().implementation = function () {
        var url = this.toString();
        console.log("[+] URL 연결 감지: " + url);

        // 내부 네트워크 탐지
        if (isInternalNetwork(url)) {
            console.error("[!] 내부 네트워크로의 SSRF 시도 차단: " + url);
            throw new Error("내부 네트워크로의 SSRF 시도 차단: " + url);
        }

        return this.openConnection();
    };

    // HttpURLConnection.setRequestMethod 후킹
    HttpURLConnection.setRequestMethod.implementation = function (method) {
        console.log("[+] HTTP 요청 메서드 설정됨: " + method);
        if (method.toUpperCase() === "CONNECT") {
            console.warn("[!] HTTP CONNECT 메서드 탐지됨: " + method);
        }
        return this.setRequestMethod(method);
    };

    // URLConnection.getInputStream 후킹
    URLConnection.getInputStream.implementation = function () {
        console.log("[*] URLConnection.getInputStream 호출됨");
        var inputStream = this.getInputStream();
        var url = this.getURL().toString();
        console.log("[+] 요청 URL: " + url);

        // 민감한 IP 대역 확인
        if (isInternalNetwork(url)) {
            console.error("[!] 내부 네트워크로의 응답 차단: " + url);
            throw new Error("내부 네트워크로의 응답 차단: " + url);
        }
        return inputStream;
    };

    // 내부 네트워크 확인 함수
    function isInternalNetwork(url) {
        var internalPatterns = [
            "127.0.0.1",
            "localhost",
            "192.168.",
            "10.",
            "172.16.",
            "172.17.",
            "172.18.",
            "172.19.",
            "172.20.",
            "172.21.",
            "172.22.",
            "172.23.",
            "172.24.",
            "172.25.",
            "172.26.",
            "172.27.",
            "172.28.",
            "172.29.",
            "172.30.",
            "172.31.",
            "::1",
            "fc00:",
            "fd00:",
        ];

        for (var i = 0; i < internalPatterns.length; i++) {
            if (url.includes(internalPatterns[i])) {
                return true;
            }
        }

        // 로컬 파일 시스템 접근 여부 확인
        if (url.startsWith("file://")) {
            console.warn("[!] 파일 시스템 접근 감지됨: " + url);
            return true;
        }

        return false;
    }

    console.log("[*] SSRF 보호 스크립트 설치 완료");
});
