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

    // JNI 네이티브 호출 감시 및 우회
    var System = Java.use("java.lang.System");
    System.loadLibrary.implementation = function (libName) {
        console.log(`[알림]: 네이티브 라이브러리 로드 요청 - ${libName}`);
        if (libName === "native-lib") {
            console.log("[우회]: 특정 네이티브 라이브러리 로드 차단");
            return; // 특정 라이브러리 로드 차단
        }
        return this.loadLibrary(libName); // 원래 동작 유지
    };

    // 거래 처리 클래스 후킹
    var transactionClass = Java.use("com.example.financial.TransactionProcessor");
    transactionClass.processTransaction.implementation = function (transactionData) {
        console.log("[알림]: 거래 데이터 처리 시작 - " + JSON.stringify(transactionData));

        // 거래 데이터 재사용 검사 로직
        function isReused(data) {
            // 예시: 재사용된 데이터인지 확인하는 로직
            var reusedDataStore = Java.use("com.example.financial.DataStore").getReusedData();
            var isReused = reusedDataStore.contains(data.someIdentifier); // 가상 필드명 'someIdentifier'
            var reuseLog = isReused
                ? "[경고]: 거래 데이터가 재사용되었습니다!"
                : "[정상]: 새로운 거래 데이터입니다.";
            console.log(reuseLog);
            return isReused;
        }

        // 무결성 검사 로직
        function isIntegrityValid(data) {
            var isValid = data != null && data.someImportantField != null;
            var integrityLog = isValid
                ? "[양호]: 거래 데이터의 무결성이 유지되고 있습니다."
                : "[취약]: 거래 데이터 무결성에 문제가 있습니다.";
            console.log(integrityLog);
            return isValid;
        }

        // 검사 수행
        if (isReused(transactionData)) {
            console.log("[경고]: 재사용된 거래 데이터로 인해 처리를 중단합니다.");
            return false; // 재사용 데이터는 처리 중단
        }

        if (!isIntegrityValid(transactionData)) {
            console.log("[경고]: 무결성 검증 실패로 인해 처리를 중단합니다.");
            return false; // 무결성 실패는 처리 중단
        }

        // 원래 메서드 호출
        try {
            var result = this.processTransaction(transactionData);
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

    console.log("[알림]: 코드 후킹 완료");
});
