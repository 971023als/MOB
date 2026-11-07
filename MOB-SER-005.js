Java.perform(function () {
    console.log("[*] 고정된 인증정보 점검 시작...");

    // ======================
    // 1. 인증 코드 생성 메서드 후킹
    // ======================

    // 민감정보 평문 로깅 방지: 값 대신 길이만 남긴다
    function mask(value) {
        if (value === null || value === undefined) return "(null)";
        return "***" + "(len=" + value.toString().length + ")";
    }

    const SmsManager = Java.use("android.telephony.SmsManager"); // SMS 관리 클래스
    const Random = Java.use("java.util.Random"); // 랜덤 값 생성기
    let generatedCodes = new Set(); // 생성된 인증 코드 저장

    // SMS 인증 코드 생성 로직 후킹
    SmsManager.sendTextMessage.overload("java.lang.String", "java.lang.String", "java.lang.String", "android.app.PendingIntent", "android.app.PendingIntent").implementation = function (destinationAddress, scAddress, text, sentIntent, deliveryIntent) {
        console.log(`[+] SMS 전송 감지 - 목적지: ${mask(destinationAddress)}`);
        console.log(`[+] 전송 메시지: ${mask(text)}`);

        if (isCodeFixed(text)) {
            console.log("[!] 경고: 고정된 인증 코드 감지!");
            alertUser("고정된 인증 코드가 사용되고 있습니다.");
        } else {
            console.log("[+] 인증 코드가 고정되지 않음.");
        }

        return this.sendTextMessage(destinationAddress, scAddress, text, sentIntent, deliveryIntent);
    };

    // Random 클래스 후킹
    Random.nextInt.overload("int").implementation = function (bound) {
        const result = this.nextInt(bound);
        console.log(`[+] Random 값 생성: ${mask(result.toString())}`);
        trackCode(result);
        return result;
    };

    // ======================
    // 2. 고정된 코드 검증 함수
    // ======================
    function isCodeFixed(code) {
        if (generatedCodes.has(code)) {
            return true; // 고정된 인증 코드로 판단
        }
        generatedCodes.add(code);
        return false;
    }

    // ======================
    // 3. 코드 추적 함수
    // ======================
    function trackCode(code) {
        if (generatedCodes.has(code)) {
            console.log(`[!] 중복된 인증 코드 발견: ${code}`);
        } else {
            console.log(`[+] 새로운 인증 코드 저장: ${code}`);
            generatedCodes.add(code);
        }
    }

    // ======================
    // 4. 실시간 경고 알림
    // ======================
    function alertUser(message) {
        Java.scheduleOnMainThread(function () {
            const context = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
            // 중첩 클래스는 외부 클래스의 속성이 아니라 $ 이름으로 직접 로드해야 함
            const Builder = Java.use("android.app.AlertDialog$Builder");

            const builder = Builder.$new(context);
            builder.setTitle("보안 경고");
            builder.setMessage(message);
            builder.setPositiveButton("확인", null);
            builder.show();
        });
    }

    console.log("[*] 고정된 인증정보 점검 로직 설정 완료.");
});
