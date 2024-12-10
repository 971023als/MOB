Java.perform(function () {
    console.log("[*] Starting CSRF Detection Script");

    // 1. HTTP 요청 감지 (OkHttpClient를 사용하는 경우)
    var OkHttpClient = Java.use("okhttp3.OkHttpClient");
    var RequestBuilder = Java.use("okhttp3.Request$Builder");

    RequestBuilder.build.implementation = function () {
        var request = this.build();

        console.log("[*] HTTP 요청 감지");
        console.log("    URL: " + request.url());
        console.log("    메서드: " + request.method());

        // CSRF 의심 구문 탐지
        if (request.method() === "POST" || request.method() === "PUT") {
            var headers = request.headers();
            var csrfToken = headers.get("X-CSRF-Token");
            if (!csrfToken) {
                console.warn("[!] CSRF Token 누락된 요청 감지! URL: " + request.url());
            }
        }

        return request;
    };

    // 2. WebView 내 악성 스크립트 삽입 감지
    var WebView = Java.use("android.webkit.WebView");

    WebView.loadUrl.overload("java.lang.String").implementation = function (url) {
        console.log("[*] WebView.loadUrl() 호출");
        console.log("    URL: " + url);

        // 악성 스크립트 또는 의심 요청 감지
        if (url.includes("csrf_test") || url.includes("malicious_script")) {
            console.warn("[!] 의심스러운 URL 감지: " + url);
        }

        return this.loadUrl(url);
    };

    WebView.loadData.overload("java.lang.String", "java.lang.String", "java.lang.String").implementation = function (data, mimeType, encoding) {
        console.log("[*] WebView.loadData() 호출");
        console.log("    데이터: " + data);

        // 악성 스크립트 감지
        if (data.includes("<script>") || data.includes("document.cookie")) {
            console.warn("[!] 의심스러운 스크립트 삽입 감지!");
        }

        return this.loadData(data, mimeType, encoding);
    };

    // 3. 네트워크 라이브러리 Retrofit 점검 (예: POST 요청)
    var Retrofit = Java.use("retrofit2.Retrofit");

    Retrofit.create.implementation = function (service) {
        console.log("[*] Retrofit.create() 호출 감지");
        console.log("    생성된 서비스: " + service.toString());

        // CSRF 의심 작업을 모니터링
        return this.create(service);
    };

    // 4. CSRF 의심 작업 차단 (필요 시 요청 중단)
    var URLConnection = Java.use("java.net.URLConnection");

    URLConnection.connect.implementation = function () {
        console.log("[*] URLConnection.connect() 호출 감지");

        var url = this.getURL();
        console.log("    URL: " + url);

        if (url.toString().includes("csrf_test")) {
            console.warn("[!] CSRF 의심 URL로의 연결 차단: " + url);
            throw new Error("CSRF 의심 요청이 차단되었습니다.");
        }

        return this.connect();
    };
});
