Java.perform(function () {
    console.log("[*] Starting Frida Script for Screen Launch & Authentication Bypass Detection");

    // 1. Intent 객체 감지 및 강제 실행 감지
    var Intent = Java.use("android.content.Intent");
    var Activity = Java.use("android.app.Activity");

    Intent.setComponent.implementation = function (component) {
        console.log("[*] Intent.setComponent() 호출 감지");
        console.log("    대상 컴포넌트: " + component);
        return this.setComponent(component);
    };

    Activity.startActivity.overload('android.content.Intent').implementation = function (intent) {
        console.log("[*] Activity.startActivity() 호출 감지");
        console.log("    인텐트 정보: " + intent.toUri(0));

        // 강제 실행 시도 감지
        var action = intent.getAction();
        var data = intent.getDataString();
        console.log("    액션: " + action + ", 데이터: " + data);

        // 특정 화면으로의 강제 이동 감지
        if (data && data.includes("bypass") || action && action.includes("bypass")) {
            console.warn("[!] 강제 실행 의심 인텐트 감지!");
        }

        return this.startActivity(intent);
    };

    // 2. 인증 관련 파일 접근 감지
    var File = Java.use("java.io.File");

    File.$init.overload('java.lang.String').implementation = function (path) {
        console.log("[*] 파일 접근 감지: " + path);

        // 인증 관련 파일 검출
        if (path.includes("auth") || path.includes("session") || path.includes("token")) {
            console.error("[!] 인증 파일 접근 감지: " + path);
        }

        return this.$init(path);
    };

    // 3. 인증 파일 삭제/조작 시도 감지
    File.delete.implementation = function () {
        console.warn("[!] 파일 삭제 시도 감지: " + this.getAbsolutePath());
        return this.delete();
    };

    var FileOutputStream = Java.use("java.io.FileOutputStream");
    FileOutputStream.write.overload('[B', 'int', 'int').implementation = function (b, off, len) {
        console.log("[*] 파일 조작 감지: " + this.toString());
        return this.write(b, off, len);
    };

    // 4. 인증 단계 우회 의심 데이터 조작 탐지
    var SharedPreferences = Java.use("android.content.SharedPreferences");
    var SharedPreferencesEditor = Java.use("android.content.SharedPreferences$Editor");

    SharedPreferencesEditor.putString.overload('java.lang.String', 'java.lang.String').implementation = function (key, value) {
        console.log("[*] SharedPreferences 조작 감지");
        console.log("    Key: " + key + ", Value: " + value);

        if (key.toLowerCase().includes("auth") || value.toLowerCase().includes("bypass")) {
            console.warn("[!] 인증 단계 우회 의심 데이터 발견! Key: " + key + ", Value: " + value);
        }

        return this.putString(key, value);
    };
});
