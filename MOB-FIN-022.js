Java.perform(function () {
    console.log("[*] 보안 프로그램 최신 업데이트 여부 점검 시작...");

    // ======================
    // 1. 프로그램 버전 확인 클래스
    // ======================
    const PackageManager = Java.use("android.content.pm.PackageManager");
    const PackageInfo = Java.use("android.content.pm.PackageInfo");

    // 보안 프로그램 패키지명 설정
    const securityProgramPackage = "com.example.security";

    // ======================
    // 2. 최신 버전 정보 설정 (사전 정의)
    // ======================
    const latestVersionCode = 102; // 최신 버전 코드
    const latestVersionName = "1.2.0"; // 최신 버전 이름

    // ======================
    // 3. 설치된 보안 프로그램 버전 점검
    // ======================
    function checkSecurityProgramVersion() {
        try {
            const context = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
            const packageManager = context.getPackageManager();
            const packageInfo = packageManager.getPackageInfo(securityProgramPackage, PackageManager.GET_META_DATA);

            const installedVersionCode = packageInfo.versionCode.value;
            const installedVersionName = packageInfo.versionName.value;

            console.log(`[+] 보안 프로그램 버전 정보:`);
            console.log(`    - 설치된 버전 코드: ${installedVersionCode}`);
            console.log(`    - 설치된 버전 이름: ${installedVersionName}`);

            if (installedVersionCode < latestVersionCode) {
                console.log("[!] 보안 프로그램이 최신 버전으로 업데이트되지 않음!");
                console.log(`[!] 설치된 버전: ${installedVersionName} (코드: ${installedVersionCode})`);
                console.log(`[!] 최신 버전: ${latestVersionName} (코드: ${latestVersionCode})`);

                // 경고 또는 실행 차단 로직 추가 가능
                alertUser("보안 프로그램을 최신 버전으로 업데이트해야 합니다!");
            } else {
                console.log("[+] 보안 프로그램이 최신 버전입니다.");
            }
        } catch (err) {
            console.log(`[!] 보안 프로그램 버전 확인 중 오류 발생: ${err.message}`);
        }
    }

    // ======================
    // 4. 사용자 경고 메시지 출력 함수
    // ======================
    function alertUser(message) {
        console.log(`[!] 경고: ${message}`);

        Java.scheduleOnMainThread(function () {
            const context = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
            const AlertDialog = Java.use("android.app.AlertDialog");
            const Builder = AlertDialog.Builder;

            const builder = Builder.$new(context);
            builder.setTitle("보안 경고");
            builder.setMessage(message);
            builder.setPositiveButton("확인", null);
            builder.show();
        });
    }

    // ======================
    // 5. 최신 업데이트 여부 점검 실행
    // ======================
    Java.scheduleOnMainThread(function () {
        console.log("[*] 보안 프로그램 최신 업데이트 여부 점검 실행 중...");
        checkSecurityProgramVersion();
    });

    console.log("[*] 보안 프로그램 최신 업데이트 여부 점검 완료.");
});
