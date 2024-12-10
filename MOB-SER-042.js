Java.perform(function () {
    console.log("[*] 디버그 로그 및 Activity 라이프사이클 모니터링 시작");

    // Android Log 클래스 로드
    var Log = Java.use("android.util.Log");

    // 중요 정보 키워드 목록 정의
    var sensitiveKeywords = [
        "password", "card number", "otp", "security code", "social security number",
        "personal info", "authentication", "token", "key", "credential",
        "session", "private", "confidential", "bank account", "pin"
    ];

    // Log 메서드 후킹
    ["d", "e", "i", "v", "w"].forEach(function (method) {
        Log[method].overload("java.lang.String", "java.lang.String").implementation = function (tag, msg) {
            console.log(`[+] Log.${method.toUpperCase()} 호출됨 - 태그: ${tag}, 메시지: ${msg}`);

            // 메시지에서 중요 정보 키워드 검색
            sensitiveKeywords.forEach(function (keyword) {
                if (msg.toLowerCase().includes(keyword)) {
                    console.warn(`[!] 로그에 민감한 데이터 노출 가능성 탐지!`);
                    console.warn(`[!] 키워드: ${keyword}`);
                    console.warn(`[!] 메시지: ${msg}`);
                }
            });

            // 원래의 Log 메서드 호출
            return this[method](tag, msg);
        };
    });

    console.log("[*] 디버그 로그 모니터링 후킹 완료");

    // Activity 클래스 로드
    var Activity = Java.use("android.app.Activity");

    // Activity 라이프사이클 후킹 함수 생성
    function hookLifecycleMethod(methodName) {
        Activity[methodName].implementation = function () {
            console.log(`[+] ${methodName} 호출됨 - Activity: ${this.getLocalClassName()}`);

            // 원래 메서드 호출
            var result = this[methodName].apply(this, arguments);

            // 각 라이프사이클 메서드 추가 동작
            switch (methodName) {
                case "onCreate":
                    console.log(`[+] onCreate: Activity가 생성되었습니다 - ${this.getLocalClassName()}`);
                    break;
                case "onStart":
                    console.log(`[+] onStart: Activity가 시작되었습니다 - ${this.getLocalClassName()}`);
                    break;
                case "onResume":
                    console.log(`[+] onResume: Activity가 활성화되었습니다 - ${this.getLocalClassName()}`);
                    console.log(`[+] onResume: 네트워크 연결 상태 확인`);
                    // 네트워크 상태 확인 로직 추가 가능
                    break;
                case "onPause":
                    console.log(`[+] onPause: Activity가 비활성화 상태로 전환되었습니다 - ${this.getLocalClassName()}`);
                    try {
                        var window = this.getWindow();
                        if (window) {
                            console.log(`[+] onPause: FLAG_SECURE 설정 시도`);
                            var WindowManager = Java.use("android.view.WindowManager");
                            window.setFlags(WindowManager.LayoutParams.FLAG_SECURE.value, WindowManager.LayoutParams.FLAG_SECURE.value);
                            console.log(`[+] onPause: FLAG_SECURE 설정 완료`);
                        }
                    } catch (e) {
                        console.error(`[!] onPause 중 에러 발생: ${e.message}`);
                    }
                    break;
                case "onStop":
                    console.log(`[+] onStop: Activity가 중지되었습니다 - ${this.getLocalClassName()}`);
                    break;
                case "onDestroy":
                    console.log(`[+] onDestroy: Activity가 종료되었습니다 - ${this.getLocalClassName()}`);
                    console.log(`[+] onDestroy: 메모리 정리 중`);
                    // 메모리 정리 로직 추가 가능
                    break;
                default:
                    console.warn(`[!] 알 수 없는 메서드 호출: ${methodName}`);
            }

            return result;
        };
    }

    // Activity 라이프사이클 메서드 후킹
    var lifecycleMethods = ["onCreate", "onStart", "onResume", "onPause", "onStop", "onDestroy"];
    lifecycleMethods.forEach(function (methodName) {
        hookLifecycleMethod(methodName);
    });

    console.log("[*] 모든 Activity 라이프사이클 후킹 완료");
});
