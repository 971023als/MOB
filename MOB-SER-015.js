Java.perform(function () {
    console.log("[*] XML 외부객체 공격(XXE) 방지 시작...");

    // XML 파서 클래스 후킹 (예시: javax.xml.parsers.DocumentBuilderFactory)
    const DocumentBuilderFactory = Java.use("javax.xml.parsers.DocumentBuilderFactory");

    // setFeature 메서드 후킹
    DocumentBuilderFactory.setFeature.overload("java.lang.String", "boolean").implementation = function (name, value) {
        console.log(`[+] setFeature 호출 감지: ${name}, ${value}`);

        // XXE 방지를 위한 중요한 옵션 설정 확인
        if (name.includes("http://xml.org/sax/features/external-general-entities") ||
            name.includes("http://apache.org/xml/features/disallow-doctype-decl")) {
            if (!value) {
                console.warn(`[!] 위험한 설정 감지: ${name} = ${value} (XXE 가능성 있음)`);
            } else {
                console.log(`[+] 안전한 설정: ${name} = ${value}`);
            }
        }

        // 원래의 메서드 호출
        return this.setFeature(name, value);
    };

    // 파싱 메서드 후킹 (예시: parse())
    const DocumentBuilder = Java.use("javax.xml.parsers.DocumentBuilder");
    DocumentBuilder.parse.overload("java.io.InputStream").implementation = function (inputStream) {
        console.log("[*] XML 파싱 시작");

        // XML 내용 확인 (원하는 경우)
        const ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");
        const InputStreamReader = Java.use("java.io.InputStreamReader");
        const BufferedReader = Java.use("java.io.BufferedReader");

        let baos = ByteArrayOutputStream.$new();
        let reader = BufferedReader.$new(InputStreamReader.$new(inputStream));
        let line;
        while ((line = reader.readLine()) !== null) {
            baos.write(line.getBytes());
        }

        let xmlContent = baos.toString();
        console.log(`[XML Content]:\n${xmlContent}`);

        // XML 내부에 DOCTYPE 또는 ENTITY 태그 탐지
        if (xmlContent.includes("<!DOCTYPE") || xmlContent.includes("<!ENTITY")) {
            console.warn("[!] XXE 공격 가능성 높은 XML 감지");
            alertUser("잠재적 XXE 공격이 탐지되었습니다.");
        }

        // 원래의 메서드 호출
        return this.parse(inputStream);
    };

    // ====================================================
    // 1. 사용자 경고 함수
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

    console.log("[*] XML 외부객체 공격(XXE) 방지 준비 완료.");
});
