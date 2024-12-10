Java.perform(function () {
    console.log("[*] 리다이렉트 보호 스크립트 시작...");

    // Intent 클래스 후킹
    const Intent = Java.use("android.content.Intent");

    // setData 메서드 후킹 (URL 설정)
    Intent.setData.overload("android.net.Uri").implementation = function (uri) {
        const redirectUrl = uri.toString();
        console.log(`[+] 리다이렉트 URL 감지: ${redirectUrl}`);

        // URL 검증 로직 추가
        if (isPhishingUrl(redirectUrl)) {
            console.warn(`[!] 잠재적 피싱 URL 탐지: ${redirectUrl}`);
            alertUser(`잠재적 피싱 URL 탐지: ${redirectUrl}`);
            return; // URL 설정 차단
        }

        // 원래의 메서드 호출
        return this.setData(uri);
    };

    // startActivity 메서드 후킹
    const Activity = Java.use("android.app.Activity");
    Activity.startActivity.overload("android.content.Intent").implementation = function (intent) {
        const redirectUrl = intent.getDataString();
        if (redirectUrl) {
            console.log(`[+] startActivity 리다이렉트 URL 감지: ${redirectUrl}`);

            // URL 검증 로직 추가
            if (isPhishingUrl(redirectUrl)) {
                console.warn(`[!] 피싱 시도로 의심되는 리다이렉트 URL: ${redirectUrl}`);
                alertUser(`피싱 시도로 의심되는 리다이렉트 URL: ${redirectUrl}`);
                return; // 리다이렉트 차단
            }
        }

        // 원래의 메서드 호출
        return this.startActivity(intent);
    };

    // ====================================================
    // 1. URL 검증 함수
    // ====================================================
    function isPhishingUrl(url) {
        // 신뢰할 수 있는 도메인 목록
        const trustedDomains = ["example.com", "trustedsite.org"];

        try {
            const parsedUrl = Java.use("java.net.URL").$new(url);
            const host = parsedUrl.getHost();

            // 신뢰할 수 있는 도메인인지 확인
            for (let i = 0; i < trustedDomains.length; i++) {
                if (host.endsWith(trustedDomains[i])) {
                    console.log(`[+] 신뢰할 수 있는 도메인: ${host}`);
                    return false;
                }
            }

            // 신뢰할 수 없는 도메인
            return true;
        } catch (e) {
            console.error(`[!] URL 파싱 오류: ${e}`);
            return true; // URL이 유효하지 않은 경우도 차단
        }
    }

    // ====================================================
    // 2. 사용자 경고 함수
    // ====================================================
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

    console.log("[*] 리다이렉트 보호 스크립트 준비 완료.");
});
