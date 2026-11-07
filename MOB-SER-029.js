Java.perform(function () {
    console.log("[*] Starting Directory Indexing Detection Script");

    // OkHttpClient 후킹
    var OkHttpClient = Java.use("okhttp3.OkHttpClient");
    var RequestBuilder = Java.use("okhttp3.Request$Builder");
    var Response = Java.use("okhttp3.Response");

    RequestBuilder.build.implementation = function () {
        var request = this.build();

        console.log("[*] HTTP 요청 감지");
        console.log("    URL: " + request.url());

        return request;
    };

    Response.body.implementation = function () {
        var body = this.body();

        console.log("[*] HTTP 응답 감지");
        // ResponseBody.string()은 스트림을 소비한다. 그대로 반환하면 앱이 빈 바디를 받으므로
        // 읽은 내용으로 새 ResponseBody를 만들어 반환한다.
        var content = body.string();

        if (content.includes("Index of /") || content.match(/<title>Index of/)) {
            console.warn("[!] 디렉토리 인덱싱 감지됨!");
            console.log("    응답 내용: " + content.substring(0, 200) + "..."); // 응답의 일부 출력
        }

        var ResponseBody = Java.use("okhttp3.ResponseBody");
        return ResponseBody.create(body.contentType(), content);
    };

    // URLConnection의 응답 처리 감지
    var URLConnection = Java.use("java.net.URLConnection");

    URLConnection.getInputStream.implementation = function () {
        var inputStream = this.getInputStream();
        console.log("[*] URLConnection 요청 처리");
        console.log("    URL: " + this.getURL());

        var urlContent = this.getContentType();
        if (urlContent && urlContent.includes("text/html")) {
            console.log("[*] HTML 응답 감지");
            // 여기서 추가적으로 응답 데이터 분석 가능
        }

        return inputStream;
    };

    // WebView URL 감지 및 분석
    var WebView = Java.use("android.webkit.WebView");

    WebView.loadUrl.overload("java.lang.String").implementation = function (url) {
        console.log("[*] WebView.loadUrl 호출");
        console.log("    URL: " + url);

        if (url.includes("/")) {
            console.log("[*] 디렉토리 경로 의심 URL: " + url);
        }

        return this.loadUrl(url);
    };

    WebView.loadData.overload("java.lang.String", "java.lang.String", "java.lang.String").implementation = function (data, mimeType, encoding) {
        console.log("[*] WebView.loadData 호출");

        if (data.includes("Index of /")) {
            console.warn("[!] WebView 내 디렉토리 인덱싱 감지됨!");
        }

        return this.loadData(data, mimeType, encoding);
    };
});
