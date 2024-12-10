Java.perform(function () {
    console.log("[*] 확장된 XSS 탐지 후킹 스크립트 시작");

    // WebView 및 HTTP 요청 관련 클래스 로드
    var WebViewClass = Java.use("android.webkit.WebView");
    var OkHttpClientClass = Java.use("okhttp3.OkHttpClient");

    // 확장된 XSS 의심 패턴 목록
    var xssPatterns = [
        "<script", "</script>", "javascript:", "onerror=", "onload=", "alert(",
        "prompt(", "confirm(", "eval(", "setTimeout(", "setInterval(", "document.cookie",
        "document.domain", "document.write", "window.location", "window.name",
        "window.open", "window.history", "localStorage", "sessionStorage",
        "innerHTML", "outerHTML", "srcdoc=", "href=", "<iframe", "</iframe>",
        "<svg", "</svg>", "<math", "<meta", "<link", "base64,", "data:text/html",
        "data:text/javascript", "data:text/css", "<object", "<embed", "javascript:void",
        "vbscript:", "expression(", "URL=", "xmlns=", "<img", "<body", "<base",
        "onfocus=", "onblur=", "onkeypress=", "onkeyup=", "onkeydown=",
        "onmouseover=", "onmouseout=", "onclick=", "onsubmit=", "onreset=",
        "onchange=", "oninput=", "onscroll=", "onwheel=", "onresize=", "onunload=",
        "fetch(", "XMLHttpRequest", "ActiveXObject", "getResponseHeader", "send(",
        "<audio", "<video", "<track", "<source", "<picture", "<canvas", "<applet",
        "background=", "style=", "script:", "xlink:href", "aria-label=", "tabindex="
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
