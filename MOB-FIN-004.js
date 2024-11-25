Java.perform(function () {
    console.log("[알림]: 코드 후킹 시작");

    // 디버깅 탐지 우회
    var Debug = Java.use("android.os.Debug");
    Debug.isDebuggerConnected.implementation = function () {
        console.log("[우회]: 디버깅 탐지 차단 (Debug.isDebuggerConnected)");
        return false; // 디버거가 연결되지 않았다고 반환
    };

    var Debugger = Java.use("java.lang.System");
    Debugger.getProperty.implementation = function (property) {
        if (property === "ro.debuggable" || property === "ro.secure") {
            console.log(`[우회]: 디버깅 속성 우회 (속성: ${property})`);
            return "0"; // 디버깅 속성 비활성화
        }
        return this.getProperty(property);
    };

    // JNI 네이티브 호출 우회 및 감시
    var System = Java.use("java.lang.System");
    System.loadLibrary.implementation = function (libName) {
        console.log(`[알림]: 네이티브 라이브러리 로드 요청 - ${libName}`);
        if (libName === "native-lib") {
            console.log("[우회]: 특정 네이티브 라이브러리 로드 차단");
            return; // 특정 라이브러리 로드 차단
        }
        return this.loadLibrary(libName); // 원래 동작 유지
    };

    // 거래 클래스 후킹
    var transactionClass = Java.use("com.example.financial.Transaction");
    transactionClass.verifyIntegrity.implementation = function (transactionData) {
        console.log("거래 데이터 무결성 검증 시작: " + JSON.stringify(transactionData));

        // 무결성 검사 로직
        function isIntegrityValid(data) {
            // 무결성 검사 (예: 특정 필드가 null인지 확인)
            var isValid = data != null && data.someImportantField != null;
            var fieldLog = isValid
                ? "[양호]: 거래 데이터의 필드가 정상적입니다."
                : "[취약]: 거래 데이터의 필드에 문제가 있습니다.";
            console.log(fieldLog);
            return isValid;
        }

        if (isIntegrityValid(transactionData)) {
            console.log("[양호]: 거래 데이터의 무결성이 유지되고 있습니다.");
        } else {
            console.log("[취약]: 거래 데이터 무결성에 문제가 발견되었습니다.");
        }

        // 원래 메서드 호출
        try {
            var result = this.verifyIntegrity(transactionData);
            console.log("[결과]: 원래 메서드의 반환값 - " + result);
            return result;
        } catch (e) {
            console.log("[오류]: 원래 메서드 호출 중 예외 발생 - " + e);
            return false; // 예외 발생 시 기본 반환값 제공
        }
    };

    // 네이티브 메서드 호출 감시 및 우회
    var nativeHandlerClass = Java.use("com.example.financial.NativeHandler");
    nativeHandlerClass.nativeProcessData.implementation = function (data) {
        console.log("[알림]: 네이티브 메서드 호출 감지 - 입력 데이터: " + data);
        var modifiedData = "우회된 데이터"; // 데이터 조작
        console.log("[우회]: 데이터 수정 - " + modifiedData);
        return this.nativeProcessData(modifiedData); // 수정된 데이터로 호출
    };

    // 프로세스 종료 방지
    var ActivityManager = Java.use("android.app.ActivityManager");
    ActivityManager.killBackgroundProcesses.implementation = function (packageName) {
        console.log(`[우회]: 프로세스 종료 시도 차단 - 패키지명: ${packageName}`);
    };

    console.log("[알림]: 코드 후킹 완료");
});
