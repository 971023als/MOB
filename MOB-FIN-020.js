Java.perform(function () {
    console.log("[*] 소스코드 난독화 적용 여부 점검 시작...");

    // ======================
    // 1. 주요 클래스 이름 분석
    // ======================
    const loadedClasses = Java.enumerateLoadedClassesSync();

    console.log("[+] 로드된 클래스 분석 시작...");
    loadedClasses.forEach(function (className) {
        if (!isObfuscated(className)) {
            console.log(`[!] 난독화되지 않은 클래스 감지: ${className}`);
        }
    });

    // ======================
    // 2. 주요 메서드 이름 분석
    // ======================
    const packageName = "com.example.app"; // 대상 패키지 이름 설정
    const targetClasses = loadedClasses.filter(c => c.startsWith(packageName));

    targetClasses.forEach(function (className) {
        try {
            const klass = Java.use(className);
            const methods = klass.class.getDeclaredMethods();
            methods.forEach(function (method) {
                const methodName = method.getName();
                if (!isObfuscated(methodName)) {
                    console.log(`[!] 난독화되지 않은 메서드 감지 - 클래스: ${className}, 메서드: ${methodName}`);
                }
            });
        } catch (err) {
            console.log(`[!] 메서드 분석 중 오류 발생 - 클래스: ${className}, 오류: ${err.message}`);
        }
    });

    console.log("[*] 소스코드 난독화 적용 여부 점검 완료.");

    // ======================
    // 난독화 감지 함수
    // ======================
    function isObfuscated(name) {
        // 난독화된 이름의 특징을 기반으로 판단 (예: 짧거나 무의미한 이름)
        const obfuscatedPattern = /^[a-zA-Z]{1,2}$/; // 예: "a", "ab", "x1"
        return obfuscatedPattern.test(name);
    }
});
