Java.perform(function () {
    console.log("[*] Starting Enhanced XSS Detection Hook");

    // WebView 및 HTTP 요청 관련 클래스 로드
    var WebViewClass = Java.use("android.webkit.WebView");
    var OkHttpClientClass = Java.use("okhttp3.OkHttpClient");

    // 확장된 XSS 의심 패턴
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
        "fetch(", "XMLHttpRequest", "ActiveXObject", "getResponseHeader", "send("
    ];

    // WebView.loadUrl 메서드 후킹
    WebViewClass.loadUrl.overload('java.lang.String').implementation = function (url) {
        console.log("[*] WebView Loading URL: " + url);

        // URL에서 XSS 패턴 검색
        for (var i = 0; i < xssPatterns.length; i++) {
            if (url.toLowerCase().includes(xssPatterns[i])) {
                console.warn("[!] Potential XSS Detected in URL: " + url);
                console.warn("[!] Suspicious Pattern: " + xssPatterns[i]);
            }
        }
        return this.loadUrl(url);
    };

    // OkHttpClient.newCall 메서드 후킹
    OkHttpClientClass.newCall.overload('okhttp3.Request').implementation = function (request) {
        var url = request.url().toString();
        var body = request.body() ? request.body().toString() : "No Body";

        console.log("[*] HTTP Request: " + url);
        console.log("[*] Request Body: " + body);

        // 요청 데이터에서 XSS 패턴 검색
        for (var i = 0; i < xssPatterns.length; i++) {
            if (body.toLowerCase().includes(xssPatterns[i]) || url.toLowerCase().includes(xssPatterns[i])) {
                console.warn("[!] Potential XSS Detected in HTTP Request: " + url);
                console.warn("[!] Suspicious Pattern: " + xssPatterns[i]);
                console.warn("[!] Suspicious Body: " + body);
            }
        }

        return this.newCall(request);
    };

    console.log("[*] Enhanced XSS Detection Hooks Installed");
});
