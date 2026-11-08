Java.perform(function () {
    console.log("[*] XML 외부객체 공격(XXE) 방지 시작...");

    // XML 파서 클래스 후킹 (예시: javax.xml.parsers.DocumentBuilderFactory)
    const DocumentBuilderFactory = Java.use("javax.xml.parsers.DocumentBuilderFactory");

    // 기능별 안전한 값: 이 값과 다르면 XXE 위험으로 경고
    // - disallow-doctype-decl: true 가 안전 (DOCTYPE 자체 금지)
    // - external-general-entities / external-parameter-entities / load-external-dtd: false 가 안전 (외부 엔티티 해석 금지)
    const SAFE_FEATURE_VALUES = {
        "http://apache.org/xml/features/disallow-doctype-decl": true,
        "http://xml.org/sax/features/external-general-entities": false,
        "http://xml.org/sax/features/external-parameter-entities": false,
        "http://apache.org/xml/features/nonvalidating/load-external-dtd": false
    };

    // setFeature 메서드 후킹
    DocumentBuilderFactory.setFeature.overload("java.lang.String", "boolean").implementation = function (name, value) {
        console.log(`[+] setFeature 호출 감지: ${name}, ${value}`);

        if (SAFE_FEATURE_VALUES.hasOwnProperty(name)) {
            const safeValue = SAFE_FEATURE_VALUES[name];
            if (value !== safeValue) {
                console.warn(`[!] 위험한 설정 감지: ${name} = ${value} (안전한 값: ${safeValue}, XXE 가능성 있음)`);
            } else {
                console.log(`[+] 안전한 설정: ${name} = ${value}`);
            }
        }

        // 원래의 메서드 호출
        return this.setFeature(name, value);
    };

    // 파싱 메서드 후킹 (예시: parse())
    const DocumentBuilder = Java.use("javax.xml.parsers.DocumentBuilder");
    const ByteArrayInputStream = Java.use("java.io.ByteArrayInputStream");
    DocumentBuilder.parse.overload("java.io.InputStream").implementation = function (inputStream) {
        console.log("[*] XML 파싱 시작");

        // 스트림을 끝까지 읽어 바이트로 보관한 뒤, 원본 호출에는 "새" 스트림을 넘긴다.
        // (기존 코드는 스트림을 소비한 채 그대로 this.parse에 전달해 EOF 오류를 유발했음)
        const ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");
        const baos = ByteArrayOutputStream.$new();
        const buffer = Java.array("byte", new Array(4096).fill(0));
        let read;
        while ((read = inputStream.read(buffer)) !== -1) {
            baos.write(buffer, 0, read);
        }
        const xmlBytes = baos.toByteArray();

        const xmlContent = Java.use("java.lang.String").$new(xmlBytes);
        // XML 원문은 민감한 값을 포함할 수 있으므로 크기만 기록한다
        console.log(`[XML Content]: ${xmlBytes.length}바이트 수신 (내용 비공개)`);

        // XML 내부에 DOCTYPE 또는 ENTITY 태그 탐지
        if (xmlContent.includes("<!DOCTYPE") || xmlContent.includes("<!ENTITY")) {
            console.warn("[!] XXE 공격 가능성 높은 XML 감지");
            alertUser("잠재적 XXE 공격이 탐지되었습니다.");
        }

        // 원래의 메서드 호출 (읽어들인 내용과 동일한 바이트의 새 스트림)
        return this.parse(ByteArrayInputStream.$new(xmlBytes));
    };

    // ====================================================
    // 1. 사용자 경고 함수
    // ====================================================
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

    console.log("[*] XML 외부객체 공격(XXE) 방지 준비 완료.");
});
