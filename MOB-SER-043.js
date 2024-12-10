Java.perform(function () {
    console.log("[*] Activity 라이프사이클 후킹 스크립트 시작");

    // Activity 클래스 로드
    var Activity = Java.use("android.app.Activity");

    // 후킹 함수 생성
    function hookLifecycleMethod(methodName) {
        Activity[methodName].implementation = function () {
            console.log(`[+] ${methodName} 호출됨 - Activity: ${this.getLocalClassName()}`);

            // 원래 메서드 호출
            var result = this[methodName].apply(this, arguments);

            // 각 라이프사이클 메서드에 대한 추가 동작
            switch (methodName) {
                case "onCreate":
                    console.log(`[+] onCreate: Activity가 생성되었습니다 - ${this.getLocalClassName()}`);
                    break;

                case "onStart":
                    console.log(`[+] onStart: Activity가 시작되었습니다 - ${this.getLocalClassName()}`);
                    break;

                case "onResume":
                    console.log(`[+] onResume: Activity가 활성화되었습니다 - ${this.getLocalClassName()}`);
                    break;

                case "onPause":
                    console.log(`[+] onPause: Activity가 비활성화 상태로 전환 중입니다 - ${this.getLocalClassName()}`);
                    try {
                        var window = this.getWindow();
                        if (window) {
                            console.log(`[+] onPause: FLAG_SECURE 설정 중...`);
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
                    break;

                default:
                    console.log(`[!] 알 수 없는 메서드 호출: ${methodName}`);
                    break;
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
