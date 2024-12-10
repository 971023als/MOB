Java.perform(function () {
    // 시스템 속성 검사
    var SystemProperties = Java.use("android.os.SystemProperties");
    SystemProperties.get.overload('java.lang.String').implementation = function (key) {
        var value = this.get(key);
        if (key === "ro.debuggable") {
            console.log("디버깅 가능 시스템 속성 탐지: " + value);
        }
        return value;
    };

    // 프로세스 상태 검사
    var ActivityManager = Java.use("android.app.ActivityManager");
    var context = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();

    ActivityManager.isRunningInTestHarness.implementation = function () {
        console.log("테스트 하네스 상태 검사");
        return this.isRunningInTestHarness();
    };

    ActivityManager.getRunningAppProcesses.implementation = function () {
        console.log("실행 중인 앱 프로세스 목록 검색");
        var processes = this.getRunningAppProcesses();
        processes.forEach(function (process) {
            if (process.processName.value === context.getPackageName() && process.importance.value === 100) {
                console.log("현재 앱의 프로세스 정보: " + process.toString());
            }
        });
        return processes;
    };

    // 특정 파일 또는 리소스 접근
    var File = Java.use("java.io.File");
    File.exists.implementation = function () {
        var path = this.getAbsolutePath().toString();
        if (path === "/특정/경로/디버그_정보") {
            console.log("디버그 정보 파일 접근 감지: " + path);
        }
        return this.exists();
    };

    // 디버깅 탐지 클래스와 메소드
    var debugDetectionClass = Java.use("com.example.security.DebugDetector");
    debugDetectionClass.isDebuggerConnected.implementation = function () {
        var isDebugMode = this.isDebuggerConnected();
        console.log("디버깅 탐지 상태: " + isDebugMode);
        return isDebugMode;
    };
});
