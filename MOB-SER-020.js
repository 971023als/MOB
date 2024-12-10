Java.perform(function () {
    console.log("[*] 화면 내 중요정보 평문 노출 탐지 및 방지 스크립트 시작");

    // Android Content Resolver를 이용한 화면 캡처 탐지 및 차단
    const SecureSettings = Java.use("android.provider.Settings$Secure");
    const Activity = Java.use("android.app.Activity");
    const Context = Java.use("android.content.Context");

    // =========================================================
    // 1. 중요 정보가 포함된 화면의 캡처 방지 설정
    // =========================================================
    Activity.setContentView.overload('int').implementation = function (layoutResID) {
        console.log("[+] 화면 설정 감지: Layout ID - " + layoutResID);

        // 캡처 방지 플래그 추가
        this.getWindow().setFlags(0x80000000, 0x80000000); // FLAG_SECURE
        console.log("[+] 화면 캡처 방지 적용 완료");

        return this.setContentView(layoutResID);
    };

    // =========================================================
    // 2. 화면 내 중요정보 감지
    // =========================================================
    const TextView = Java.use("android.widget.TextView");
    TextView.setText.overload('java.lang.CharSequence').implementation = function (text) {
        console.log("[+] 텍스트 설정 감지: " + text);

        // 중요 정보 패턴 감지
        const sensitivePatterns = [
            /\d{6}-\d{7}/, // 주민등록번호
            /\d{16}/, // 카드번호
            /\d{4}-\d{4}-\d{4}-\d{4}/, // 카드번호(포맷)
            /\d{6}/, // OTP
        ];

        for (let pattern of sensitivePatterns) {
            if (pattern.test(text)) {
                console.warn("[!] 화면 내 중요정보 평문 노출 탐지: " + text);
                alertUser("중요정보 평문 노출 탐지: " + text);
                break;
            }
        }

        return this.setText(text);
    };

    // =========================================================
    // 3. 사용자 경고 함수
    // =========================================================
    function alertUser(message) {
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

    console.log("[*] 화면 내 중요정보 평문 노출 탐지 및 방지 스크립트 완료");
});
