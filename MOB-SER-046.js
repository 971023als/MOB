Java.perform(function () {
    console.log("[*] Starting SSRF Protection Script");

    // HTTPURLConnection 클래스 로드
    var HttpURLConnection = Java.use("java.net.HttpURLConnection");
    var URL = Java.use("java.net.URL");

    // URL.openConnection 후킹
    URL.openConnection.overload().implementation = function () {
        var url = this.toString();
        console.log("[+] Intercepted URL Connection: " + url);

        // 내부 네트워크 탐지
        if (isInternalNetwork(url)) {
            console.error("[!] Blocked SSRF attempt to internal network: " + url);
            throw new Error("Blocked SSRF attempt to internal network: " + url);
        }

        return this.openConnection();
    };

    // HttpURLConnection.setRequestMethod 후킹
    HttpURLConnection.setRequestMethod.implementation = function (method) {
        console.log("[+] HTTP Method Set: " + method);
        return this.setRequestMethod(method);
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
        return false;
    }

    console.log("[*] SSRF Protection Script Installed");
});
