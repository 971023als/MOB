Java.perform(function () {
    console.log("[*] Starting DeepLink Exploitation Detection Script");

    // Custom Scheme 처리 클래스 후킹
    var Intent = Java.use("android.content.Intent");
    var Uri = Java.use("android.net.Uri");
    var Activity = Java.use("android.app.Activity");
    var WebView = Java.use("android.webkit.WebView");

    // Intent 기반 URI 조작 탐지
    Intent.setData.implementation = function (uri) {
        console.log("[+] Intent.setData() called with URI: " + uri);
        if (uri.toString().startsWith("customscheme://")) {
            console.warn("[!] Custom Scheme URI Detected: " + uri);
        }
        return this.setData(uri);
    };

    Intent.getData.overload().implementation = function () {
        var uri = this.getData();
        if (uri != null) {
            console.log("[+] Intent.getData(): " + uri.toString());
            if (uri.toString().includes("javascript:")) {
                console.warn("[!] Potential JavaScript Code Execution Detected in URI: " + uri);
            }
        }
        return uri;
    };

    // Activity.startActivity()를 후킹하여 DeepLink 도용 탐지
    Activity.startActivity.overload("android.content.Intent").implementation = function (intent) {
        console.log("[+] Activity.startActivity() called with Intent: " + intent);
        var data = intent.getData();
        if (data != null) {
            console.log("    URI: " + data.toString());
            if (data.toString().startsWith("customscheme://")) {
                console.warn("[!] Custom Scheme Intent Detected: " + data);
            } else if (data.toString().includes("javascript:")) {
                console.warn("[!] Potential JavaScript Injection Detected: " + data);
            }
        }
        return this.startActivity(intent);
    };

    // WebView.loadUrl() 후킹
    WebView.loadUrl.overload("java.lang.String").implementation = function (url) {
        console.log("[+] WebView.loadUrl() called with URL: " + url);
        if (url.includes("javascript:")) {
            console.warn("[!] JavaScript Code Execution Detected in WebView: " + url);
        } else if (url.startsWith("file://")) {
            console.warn("[!] Potential Local File Access Detected: " + url);
        }
        return this.loadUrl(url);
    };

    // WebView.addJavascriptInterface() 후킹
    WebView.addJavascriptInterface.implementation = function (obj, interfaceName) {
        console.log("[+] WebView.addJavascriptInterface() called");
        console.log("    Interface Name: " + interfaceName);
        console.warn("[!] JavaScript Interface Added: This may be exploited if not properly secured");
        return this.addJavascriptInterface(obj, interfaceName);
    };

    console.log("[*] DeepLink Exploitation Detection Script Installed");
});
