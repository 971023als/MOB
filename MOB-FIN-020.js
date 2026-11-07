Java.perform(function () {
    console.log("[*] 소스코드 난독화 적용 여부 점검 시작...");

    // 대상 패키지 이름 설정 (실제 앱 패키지로 교체)
    const packageName = "com.example.app";

    // ======================
    // 1. 대상 패키지 클래스 이름 분석
    // 기존 코드는 1~2글자 이름만 "난독화"로 보고 나머지를 전부 미난독화로 보고해
    // 사실상 모든 클래스·메서드가 경고로 나왔다.
    // 난독화는 "의미 있는 이름의 비율"로 판단한다.
    // ======================
    const loadedClasses = Java.enumerateLoadedClassesSync();
    const targetClasses = loadedClasses.filter(c => c.startsWith(packageName) && c.indexOf("$") === -1);

    let obfuscatedCount = 0;
    let readableCount = 0;
    const readableSamples = [];

    targetClasses.forEach(function (className) {
        const simpleName = className.substring(className.lastIndexOf(".") + 1);
        if (isObfuscatedName(simpleName)) {
            obfuscatedCount++;
        } else {
            readableCount++;
            if (readableSamples.length < 10) readableSamples.push(className);
        }
    });

    console.log(`[+] 대상 패키지 클래스 수: ${targetClasses.length}, 난독화 추정: ${obfuscatedCount}, 의미 있는 이름: ${readableCount}`);
    if (targetClasses.length > 0 && readableCount / targetClasses.length > 0.5) {
        console.log("[!] 클래스 이름 절반 이상이 의미 있는 이름입니다. 난독화 미적용 가능성이 있습니다.");
        readableSamples.forEach(c => console.log(`    예: ${c}`));
    } else if (targetClasses.length > 0) {
        console.log("[+] 클래스 이름 대부분이 난독화된 형태입니다.");
    }

    // ======================
    // 2. 주요 메서드 이름 분석 (표준 콜백·생성자 제외)
    // ======================
    const LIFECYCLE_NAMES = [
        "onCreate", "onStart", "onResume", "onPause", "onStop", "onDestroy",
        "onClick", "onReceive", "onActivityResult", "onRequestPermissionsResult",
        "<init>", "<clinit>", "toString", "hashCode", "equals", "clone", "finalize"
    ];

    targetClasses.slice(0, 50).forEach(function (className) {
        try {
            const klass = Java.use(className);
            const methods = klass.class.getDeclaredMethods();
            for (let i = 0; i < methods.length; i++) {
                const methodName = methods[i].getName();
                if (methodName.startsWith("access$") || LIFECYCLE_NAMES.indexOf(methodName) !== -1) continue;
                if (!isObfuscatedName(methodName)) {
                    console.log(`[!] 의미 있는 메서드 이름 - 클래스: ${className}, 메서드: ${methodName}`);
                }
            }
        } catch (err) {
            console.log(`[!] 메서드 분석 중 오류 발생 - 클래스: ${className}, 오류: ${err.message}`);
        }
    });

    console.log("[*] 소스코드 난독화 적용 여부 점검 완료.");

    // ======================
    // 난독화 형태 판별 함수
    // ======================
    function isObfuscatedName(name) {
        // 1~2글자 소문자(예: a, ab) 또는 소문자+숫자 조합의 무의미한 이름을 난독화로 간주
        return /^[a-z]{1,2}[0-9]?$/.test(name);
    }
});
