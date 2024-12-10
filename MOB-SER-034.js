Java.perform(function () {
    console.log("[*] Starting SSL/TLS Protocol Version Detection Script");

    // SSLSocket 클래스를 후킹하여 프로토콜 확인
    var SSLSocketFactoryClass = Java.use("javax.net.ssl.SSLSocketFactory");

    SSLSocketFactoryClass.getDefault.overload().implementation = function () {
        console.log("[*] Hooking SSLSocketFactory.getDefault()");

        var socketFactory = this.getDefault();
        var protocols = socketFactory.getDefaultCipherSuites();

        console.log("[*] Supported Cipher Suites: " + protocols.join(", "));

        // 취약한 프로토콜 검사
        protocols.forEach(function (protocol) {
            if (protocol.includes("SSL") || protocol.includes("TLSv1.0") || protocol.includes("TLSv1.1")) {
                console.warn("[!] Insecure Protocol Detected: " + protocol);
            } else {
                console.log("[*] Secure Protocol: " + protocol);
            }
        });

        return socketFactory;
    };

    // SSLParameters 클래스를 후킹하여 설정된 프로토콜 확인
    var SSLParametersClass = Java.use("javax.net.ssl.SSLParameters");

    SSLParametersClass.setProtocols.implementation = function (protocols) {
        console.log("[*] Hooking SSLParameters.setProtocols()");
        console.log("[*] Protocols being set: " + protocols.join(", "));

        // 취약한 프로토콜 검출
        protocols.forEach(function (protocol) {
            if (protocol === "SSLv3" || protocol === "TLSv1.0" || protocol === "TLSv1.1") {
                console.warn("[!] Insecure Protocol Detected: " + protocol);
            } else {
                console.log("[*] Secure Protocol Detected: " + protocol);
            }
        });

        return this.setProtocols(protocols);
    };

    console.log("[*] SSL/TLS Protocol Detection Hooks Installed");
});
