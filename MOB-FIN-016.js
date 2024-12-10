Java.perform(function () {
    console.log("[*] HTS 실행 파라미터 재사용 점검 시작...");

    // ======================
    // 1. 실행 파라미터 관리 클래스
    // ======================
    const Intent = Java.use("android.content.Intent"); // 인텐트 클래스
    const Bundle = Java.use("android.os.Bundle"); // 번들 클래스
    const ProcessBuilder = Java.use("java.lang.ProcessBuilder"); // 프로세스 빌더 클래스

    // ===========================================
    // 2. 실행 파라미터 분석 및 재사용 점검
    // ===========================================
    Intent.getStringExtra.overload('java.lang.String').implementation = function (name) {
        const value = this.getStringExtra(name);
        console.log(`[+] getStringExtra 호출됨 - 키: ${name}, 값: ${value}`);

        // 인증 정보가 포함된 실행 파라미터 감지
        if (name.includes("token") || name.includes("session") || name.includes("auth")) {
            console.log("[!] 중요 인증 정보가 실행 파라미터에 포함되어 있음");
            console.log(`[!] 파라미터 값: ${value}`);
        }

        return value; // 원래 값 반환
    };

    Bundle.getString.overload('java.lang.String').implementation = function (key) {
        const value = this.getString(key);
        console.log(`[+] Bundle.getString 호출됨 - 키: ${key}, 값: ${value}`);

        // 인증 정보가 포함된 실행 파라미터 감지
        if (key.includes("token") || key.includes("session") || key.includes("auth")) {
            console.log("[!] 중요 인증 정보가 번들에 포함되어 있음");
            console.log(`[!] 파라미터 값: ${value}`);
        }

        return value; // 원래 값 반환
    };

    // ===========================================
    // 3. 프로세스 빌더 실행 파라미터 점검
    // ===========================================
    ProcessBuilder.command.overload('java.util.List').implementation = function (commands) {
        console.log("[+] ProcessBuilder.command 호출됨 - 명령어 목록");

        for (let i = 0; i < commands.size(); i++) {
            const command = commands.get(i);
            console.log(`    - 명령 ${i}: ${command}`);

            // 인증 정보가 포함된 실행 파라미터 감지
            if (command.includes("token") || command.includes("session") || command.includes("auth")) {
                console.log("[!] 중요 인증 정보가 실행 명령어에 포함되어 있음");
                console.log(`[!] 명령어: ${command}`);
            }
        }

        return this.command(commands);
    };

    ProcessBuilder.command.overload('[Ljava.lang.String;').implementation = function (commands) {
        console.log("[+] ProcessBuilder.command 호출됨 - 명령어 배열");

        for (let i = 0; i < commands.length; i++) {
            console.log(`    - 명령 ${i}: ${commands[i]}`);

            // 인증 정보가 포함된 실행 파라미터 감지
            if (commands[i].includes("token") || commands[i].includes("session") || commands[i].includes("auth")) {
                console.log("[!] 중요 인증 정보가 실행 명령어에 포함되어 있음");
                console.log(`[!] 명령어: ${commands[i]}`);
            }
        }

        return this.command(commands);
    };

    // ===========================================
    // 4. 실행 파라미터 재사용 테스트
    // ===========================================
    Intent.putExtra.overload('java.lang.String', 'java.lang.String').implementation = function (name, value) {
        console.log(`[+] putExtra 호출됨 - 키: ${name}, 값: ${value}`);

        // 인증 정보 재사용 테스트
        if (name.includes("token") || name.includes("session")) {
            console.log("[!] 실행 파라미터 재사용 테스트 수행");
            console.log(`[!] 재사용된 인증 정보: ${value}`);

            // 테스트: 기존 세션 토큰을 다른 사용자 인증으로 사용
            const testValue = "hijacked_session_token";
            console.log(`[+] 재사용된 파라미터 값 변경: ${testValue}`);
            value = testValue; // 파라미터 값 변경
        }

        return this.putExtra(name, value);
    };

    console.log("[*] HTS 실행 파라미터 재사용 점검 완료.");
});
