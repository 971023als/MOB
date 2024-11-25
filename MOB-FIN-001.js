Java.perform(function () {
    // 대상 클래스와 메서드 정의
    var targetClass = Java.use("com.example.financial.TransactionAuth"); // 가상의 인증 클래스

    // 디버깅 탐지 우회
    var Debug = Java.use("android.os.Debug");
    Debug.isDebuggerConnected.implementation = function () {
        console.log("[우회]: 디버깅 탐지 우회 수행 중");
        return false; // 항상 디버거가 연결되지 않았다고 반환
    };

    // JNI 네이티브 함수 호출 감시 및 우회
    var System = Java.use("java.lang.System");
    System.loadLibrary.implementation = function (libName) {
        console.log("[알림]: 네이티브 라이브러리 로드 시도 - " + libName);
        if (libName === "native-lib") {
            console.log("[우회]: 의심스러운 네이티브 라이브러리 로드 차단");
            return; // 로드를 차단하거나 대체 동작 수행
        }
        return this.loadLibrary(libName); // 원래 동작 유지
    };

    // 거래 인증 메서드 후킹
    targetClass.verifyAuthenticationMethod.implementation = function (authData) {
        // 인증 데이터 유효성 검사 함수
        function isAuthMethodValid(data) {
            // 예시: 인증 데이터가 null이 아니고, 특정 형식(예: 길이, 포맷)을 만족하는지 검사
            var isValidLength = data != null && data.length >= 8;
            var containsNumbers = /\d/.test(data);
            var containsLetters = /[a-zA-Z]/.test(data);
            return isValidLength && containsNumbers && containsLetters;
        }

        console.log("거래 인증수단 검증 시작: " + authData);
        if (isAuthMethodValid(authData)) {
            console.log("[양호]: 거래 인증수단이 정상적으로 검증되었습니다.");
        } else {
            console.log("[취약]: 거래 인증수단 검증 오류가 발생하였습니다.");
        }

        // 원래 메서드 호출
        try {
            var result = this.verifyAuthenticationMethod(authData);
            console.log("[결과]: 원래 메서드의 반환값 - " + result);
            return result;
        } catch (e) {
            console.log("[오류]: 원래 메서드 호출 중 예외 발생 - " + e);
            return false; // 예외 발생 시 기본 반환값 제공
        }
    };

    // 네이티브 메서드 호출 감시
    var nativeClass = Java.use("com.example.financial.NativeHandler");
    nativeClass.nativeProcessData.implementation = function (data) {
        console.log("[알림]: 네이티브 메서드 호출 감지 - 입력 데이터: " + data);
        // 원본 데이터 수정 가능
        var modifiedData = "우회된 데이터";
        console.log("[우회]: 데이터 수정 - " + modifiedData);
        return this.nativeProcessData(modifiedData); // 수정된 데이터로 호출
    };
});
