Java.perform(function () {
    console.log("[*] 확장된 XSS 탐지 후킹 스크립트 시작");

    // WebView 및 HTTP 요청 관련 클래스 로드
    var WebViewClass = Java.use("android.webkit.WebView");
    var OkHttpClientClass = Java.use("okhttp3.OkHttpClient");

    // 확장된 XSS 의심 패턴 목록
    // 고신호 XSS 패턴만 남김.
    // 기존 목록의 href=, style=, <img, aria-label=, send(, URL= 등은 일반 HTML/JS에 흔해
    // 사실상 모든 페이지·요청을 "XSS 의심"으로 오탐했다.
    var xssPatterns = [
        "<script", "javascript:", "vbscript:", "data:text/html",
        "onerror=", "onload=", "onfocus=", "onclick=", "onmouseover=",
        "alert(", "prompt(", "confirm(", "eval(",
        "document.cookie", "document.write", "srcdoc=",
        "<iframe", "<object", "<embed", "expression("
    ];

    // WebView.loadUrl 메서드 후킹
    WebViewClass.loadUrl.overload('java.lang.String').implementation = function (url) {
        console.log(`[+] WebView에서 URL 로드 중: ${url}`);

        // URL에서 XSS 패턴 검색
        xssPatterns.forEach(function (pattern) {
            if (url.toLowerCase().includes(pattern)) {
                console.warn(`[!] XSS 의심 URL 탐지: ${url}`);
                console.warn(`[!] 의심 패턴: ${pattern}`);
            }
        });

        return this.loadUrl(url);
    };

    // OkHttpClient.newCall 메서드 후킹
    OkHttpClientClass.newCall.overload('okhttp3.Request').implementation = function (request) {
        var url = request.url().toString();
        var body = request.body() ? request.body().toString() : "본문 없음";

        console.log(`[+] HTTP 요청 탐지 - URL: ${url}`);
        console.log(`[+] 요청 본문: ${body}`);

        // 요청 데이터에서 XSS 패턴 검색
        xssPatterns.forEach(function (pattern) {
            if (body.toLowerCase().includes(pattern) || url.toLowerCase().includes(pattern)) {
                console.warn(`[!] HTTP 요청에서 XSS 의심 패턴 탐지: ${url}`);
                console.warn(`[!] 의심 패턴: ${pattern}`);
                console.warn(`[!] 의심 본문: ${body}`);
            }
        });

        return this.newCall(request);
    };

    console.log("[*] 확장된 XSS 탐지 후킹 완료");
});
