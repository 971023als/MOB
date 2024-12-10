Java.perform(function () {
    console.log("[*] Starting Activity Lifecycle Hooking");

    // Activity 클래스 로드
    var Activity = Java.use("android.app.Activity");

    // 후킹 함수 생성
    function hookLifecycleMethod(methodName) {
        Activity[methodName].implementation = function () {
            console.log(`[+] ${methodName} called for Activity: ${this.getLocalClassName()}`);

            // 원래 메서드 호출
            var result = this[methodName].apply(this, arguments);

            // 추가 동작
            if (methodName === "onPause") {
                try {
                    var window = this.getWindow();
                    if (window) {
                        console.log(`[+] Setting FLAG_SECURE during ${methodName}`);
                        var WindowManager = Java.use("android.view.WindowManager");
                        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE.value, WindowManager.LayoutParams.FLAG_SECURE.value);
                        console.log(`[+] FLAG_SECURE set successfully during ${methodName}`);
                    }
                } catch (e) {
                    console.error(`[!] Error during ${methodName}: ${e.message}`);
                }
            }

            return result;
        };
    }

    // Activity 라이프사이클 메서드 후킹
    var lifecycleMethods = ["onCreate", "onStart", "onResume", "onPause", "onStop", "onDestroy"];
    lifecycleMethods.forEach(function (methodName) {
        hookLifecycleMethod(methodName);
    });

    console.log("[*] All Activity Lifecycle Hooks Installed");
});
