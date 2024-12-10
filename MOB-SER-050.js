Java.perform(function () {
    console.log("[*] 딥링크 악용 탐지 스크립트 시작");

    // 커스텀 스킴 처리 클래스 후킹
    var Intent = Java.use("android.content.Intent");
    var Uri = Java.use("android.net.Uri");
    var Activity = Java.use("android.app.Activity");
    var WebView = Java.use("android.webkit.WebView");

    // Intent 기반 URI 조작 탐지
    Intent.setData.implementation = function (uri) {
        console.log("[+] Intent.setData() 호출됨, URI: " + uri);
        if (uri.toString().startsWith("customscheme://")) {
            console.warn("[!] 커스텀 스킴 URI 감지됨: " + uri);
        }
        return this.setData(uri);
    };

    Intent.getData.overload().implementation = function () {
        var uri = this.getData();
        if (uri != null) {
            console.log("[+] Intent.getData() 호출됨, URI: " + uri.toString());
            if (uri.toString().includes("javascript:")) {
                console.warn("[!] URI에 JavaScript 코드 실행 가능성 탐지됨: " + uri);
            }
        }
        return uri;
    };

    // Activity.startActivity()를 후킹하여 DeepLink 도용 탐지
    Activity.startActivity.overload("android.content.Intent").implementation = function (intent) {
        console.log("[+] Activity.startActivity() 호출됨, Intent: " + intent);
        var data = intent.getData();
        if (data != null) {
            console.log("    URI: " + data.toString());
            if (data.toString().startsWith("customscheme://")) {
                console.warn("[!] 커스텀 스킴 Intent 감지됨: " + data);
            } else if (data.toString().includes("javascript:")) {
                console.warn("[!] JavaScript 삽입 가능성 탐지됨: " + data);
            }
        }
        return this.startActivity(intent);
    };

    // WebView.loadUrl() 후킹
    WebView.loadUrl.overload("java.lang.String").implementation = function (url) {
        console.log("[+] WebView.loadUrl() 호출됨, URL: " + url);
        if (url.includes("javascript:")) {
            console.warn("[!] WebView에서 JavaScript 코드 실행 가능성 탐지됨: " + url);
        } else if (url.startsWith("file://")) {
            console.warn("[!] 로컬 파일 접근 가능성 탐지됨: " + url);
        }
        return this.loadUrl(url);
    };

    // WebView.addJavascriptInterface() 후킹
    WebView.addJavascriptInterface.implementation = function (obj, interfaceName) {
        console.log("[+] WebView.addJavascriptInterface() 호출됨");
        console.log("    인터페이스 이름: " + interfaceName);
        console.warn("[!] JavaScript 인터페이스 추가됨: 적절히 보호되지 않을 경우 악용 가능성 있음");
        return this.addJavascriptInterface(obj, interfaceName);
    };

    console.log("[*] 딥링크 악용 탐지 스크립트 설치 완료");
});
