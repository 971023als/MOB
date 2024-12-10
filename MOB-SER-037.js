Java.perform(function () {
    console.log("[*] Starting TLS Renegotiation Vulnerability Check");

    // SSL/TLS Socket 후킹
    var SSLContextClass = Java.use("javax.net.ssl.SSLContext");

    SSLContextClass.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function (keyManagers, trustManagers, secureRandom) {
        console.log("[*] SSLContext.init() Hooked");

        this.init(keyManagers, trustManagers, secureRandom);

        var protocols = this.getSupportedSSLParameters().getProtocols();
        console.log("[*] Supported Protocols: " + protocols.join(", "));

        protocols.forEach(function (protocol) {
            if (protocol === "SSLv3" || protocol === "TLSv1.0") {
                console.warn("[!] Insecure Protocol Detected: " + protocol);
                console.warn("[!] Check Renegotiation Settings for Potential Vulnerabilities");
            }
        });
    };

    // 재협상 허용 여부 점검
    try {
        var SSLParametersClass = Java.use("javax.net.ssl.SSLParameters");

        SSLParametersClass.setProtocols.implementation = function (protocols) {
            console.log("[*] Hooked SSLParameters.setProtocols()");
            console.log("[*] Configured Protocols: " + protocols.join(", "));

            protocols.forEach(function (protocol) {
                if (protocol === "SSLv3" || protocol === "TLSv1.0") {
                    console.warn("[!] Insecure Protocol Detected: " + protocol);
                    console.warn("[!] Verify Renegotiation Settings");
                }
            });

            return this.setProtocols(protocols);
        };
    } catch (error) {
        console.log("[-] SSLParameters Class Not Found. Skipping SSLParameters Inspection.");
    }

    // 재협상 설정 확인
    try {
        var SSLSocketFactoryClass = Java.use("javax.net.ssl.SSLSocketFactory");

        SSLSocketFactoryClass.createSocket.overload('java.net.Socket', 'java.lang.String', 'int', 'boolean').implementation = function (socket, host, port, autoClose) {
            console.log("[*] Hooked createSocket for TLS Renegotiation");

            var sslSocket = this.createSocket(socket, host, port, autoClose);
            console.log("[*] Created SSL Socket for Host: " + host);

            var enabledProtocols = sslSocket.getEnabledProtocols();
            console.log("[*] Enabled Protocols: " + enabledProtocols.join(", "));

            enabledProtocols.forEach(function (protocol) {
                if (protocol === "TLSv1.0") {
                    console.warn("[!] TLSv1.0 Detected. Renegotiation May Be Vulnerable");
                }
            });

            return sslSocket;
        };
    } catch (error) {
        console.log("[-] SSLSocketFactory Class Not Found. Skipping SSLSocketFactory Inspection.");
    }

    console.log("[*] TLS Renegotiation Vulnerability Hooks Installed");
});
