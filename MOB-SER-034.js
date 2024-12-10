Java.perform(function () {
    console.log("[*] SSL/TLS 프로토콜 버전 감지 스크립트 시작");

    // SSLSocketFactory 클래스 후킹
    var SSLSocketFactoryClass = Java.use("javax.net.ssl.SSLSocketFactory");

    SSLSocketFactoryClass.getDefault.overload().implementation = function () {
        console.log("[*] SSLSocketFactory.getDefault() 후킹됨");

        var socketFactory = this.getDefault();
        var cipherSuites = socketFactory.getDefaultCipherSuites();

        console.log("[*] 지원되는 암호화 방식: " + cipherSuites.join(", "));

        // 암호화 방식 검사
        cipherSuites.forEach(function (suite) {
            if (isInsecureProtocol(suite)) {
                console.warn(`[!] 취약한 암호화 방식 감지됨: ${suite}`);
            } else {
                console.log(`[+] 안전한 암호화 방식: ${suite}`);
            }
        });

        return socketFactory;
    };

    // SSLParameters 클래스 후킹
    var SSLParametersClass = Java.use("javax.net.ssl.SSLParameters");

    SSLParametersClass.setProtocols.implementation = function (protocols) {
        console.log("[*] SSLParameters.setProtocols() 후킹됨");
        console.log("[*] 설정 중인 프로토콜: " + protocols.join(", "));

        // 프로토콜 검사
        protocols.forEach(function (protocol) {
            if (isInsecureProtocol(protocol)) {
                console.warn(`[!] 취약한 프로토콜 감지됨: ${protocol}`);
            } else {
                console.log(`[+] 안전한 프로토콜: ${protocol}`);
            }
        });

        return this.setProtocols(protocols);
    };

    // 취약한 암호화 방식 및 프로토콜 판별 함수
    function isInsecureProtocol(name) {
        const insecureProtocols = ["SSLv3", "TLSv1.0", "TLSv1.1"];
        return insecureProtocols.some(protocol => name.includes(protocol));
    }

    console.log("[*] SSL/TLS 프로토콜 감지 후킹 완료");
});
