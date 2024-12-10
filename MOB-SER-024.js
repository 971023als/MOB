Java.perform(function () {
    console.log("[*] Frida Script for WebView and DOM Inspection Started");

    // WebView 클래스 후킹
    var WebView = Java.use("android.webkit.WebView");
    var suspiciousKeywords = ["password", "creditcard", "securitycode", "OTP", "residentID"];

    // WebView.loadUrl 후킹 (URL 로드 시 민감 정보 노출 점검)
    WebView.loadUrl.implementation = function (url) {
        console.log("[*] WebView.loadUrl() 호출 감지");
        console.log("    로드 URL: " + url);

        // URL에 민감 키워드 포함 여부 점검
        suspiciousKeywords.forEach(function (keyword) {
            if (url.includes(keyword)) {
                console.warn(`[!] 민감 키워드 (${keyword})가 URL에 포함되어 있음!`);
            }
        });

        // 원래의 메서드 호출
        this.loadUrl(url);
    };

    // JavaScript 인터페이스를 통해 민감 정보 노출 점검
    WebView.evaluateJavascript.implementation = function (script, callback) {
        console.log("[*] WebView.evaluateJavascript() 호출 감지");
        console.log("    실행 스크립트: " + script);

        // 스크립트 내용 점검
        suspiciousKeywords.forEach(function (keyword) {
            if (script.includes(keyword)) {
                console.error(`[!] 민감 키워드 (${keyword})가 JavaScript 코드에 포함되어 있음!`);
            }
        });

        // 원래의 메서드 호출
        this.evaluateJavascript(script, callback);
    };

    // 네트워크 통신 영역에서 DOM 데이터 분석
    var XMLHttpRequest = Java.use("org.apache.http.client.methods.HttpPost");
    XMLHttpRequest.$init.overload('java.net.URI').implementation = function (uri) {
        console.log("[*] HttpPost 요청 감지");
        console.log("    요청 URI: " + uri.toString());

        // 요청 URI에 민감 키워드 포함 여부 확인
        suspiciousKeywords.forEach(function (keyword) {
            if (uri.toString().includes(keyword)) {
                console.warn(`[!] 민감 키워드 (${keyword})가 HTTP 요청 URI에 포함됨!`);
            }
        });

        return this.$init(uri);
    };

    // DOM 데이터 접근 (예시: HTML 요소 내 민감 정보 점검)
    var DOMParser = Java.use("org.w3c.dom.DOMImplementation");
    DOMParser.createDocumentType.overload('java.lang.String', 'java.lang.String', 'java.lang.String').implementation = function (qualifiedName, publicId, systemId) {
        console.log("[*] DOM 요소 접근 감지");
        console.log(`    노드 정보: ${qualifiedName}`);

        suspiciousKeywords.forEach(function (keyword) {
            if (qualifiedName.includes(keyword)) {
                console.error(`[!] 민감 키워드 (${keyword})가 DOM 노드에 포함되어 있음!`);
            }
        });

        return this.createDocumentType(qualifiedName, publicId, systemId);
    };
});
