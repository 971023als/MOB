Java.perform(function () {
    console.log("[*] TLS 재협상 취약점 점검 시작");

    // SSLContext 클래스 후킹
    var SSLContextClass = Java.use("javax.net.ssl.SSLContext");

    SSLContextClass.init.overload(
        '[Ljavax.net.ssl.KeyManager;',
        '[Ljavax.net.ssl.TrustManager;',
        'java.security.SecureRandom'
    ).implementation = function (keyManagers, trustManagers, secureRandom) {
        console.log("[*] SSLContext.init() 후킹 완료");

        this.init(keyManagers, trustManagers, secureRandom);

        var protocols = this.getSupportedSSLParameters().getProtocols();
        console.log("[*] 지원되는 프로토콜: " + protocols.join(", "));

        protocols.forEach(function (protocol) {
            if (protocol === "SSLv3" || protocol === "TLSv1.0") {
                console.warn(`[!] 취약한 프로토콜 탐지됨: ${protocol}`);
                console.warn("[!] 재협상 설정 확인 필요");
            }
        });
    };

    // SSLParameters 설정 후킹
    try {
        var SSLParametersClass = Java.use("javax.net.ssl.SSLParameters");

        SSLParametersClass.setProtocols.implementation = function (protocols) {
            console.log("[*] SSLParameters.setProtocols() 후킹됨");
            console.log("[*] 설정된 프로토콜: " + protocols.join(", "));

            protocols.forEach(function (protocol) {
                if (protocol === "SSLv3" || protocol === "TLSv1.0") {
                    console.warn(`[!] 취약한 프로토콜 탐지됨: ${protocol}`);
                    console.warn("[!] 재협상 설정 점검 필요");
                }
            });

            return this.setProtocols(protocols);
        };
    } catch (error) {
        console.log("[-] SSLParameters 클래스가 존재하지 않습니다. SSLParameters 점검 생략");
    }

    // SSLSocketFactory 설정 후킹
    try {
        var SSLSocketFactoryClass = Java.use("javax.net.ssl.SSLSocketFactory");

        SSLSocketFactoryClass.createSocket.overload(
            'java.net.Socket',
            'java.lang.String',
            'int',
            'boolean'
        ).implementation = function (socket, host, port, autoClose) {
            console.log("[*] TLS 재협상을 위한 createSocket 후킹됨");

            var sslSocket = this.createSocket(socket, host, port, autoClose);
            console.log(`[+] 생성된 SSL 소켓 - 호스트: ${host}`);

            var enabledProtocols = sslSocket.getEnabledProtocols();
            console.log("[*] 활성화된 프로토콜: " + enabledProtocols.join(", "));

            enabledProtocols.forEach(function (protocol) {
                if (protocol === "TLSv1.0") {
                    console.warn("[!] TLSv1.0 탐지됨. 재협상 취약점 발생 가능");
                }
            });

            return sslSocket;
        };
    } catch (error) {
        console.log("[-] SSLSocketFactory 클래스가 존재하지 않습니다. SSLSocketFactory 점검 생략");
    }

    console.log("[*] TLS 재협상 취약점 점검 후킹 완료");
});
