Java.perform(function () {
    console.log("[*] 프로그램 실행 명령줄 내 중요정보 평문 노출 점검 시작...");

    // ======================
    // 1. 명령줄 인자 접근 관련 클래스
    // ======================
    const Runtime = Java.use("java.lang.Runtime"); // 런타임 클래스
    const ProcessBuilder = Java.use("java.lang.ProcessBuilder"); // 프로세스 빌더 클래스

    // ===========================================
    // 2. Runtime.exec() 후킹
    // ===========================================
    Runtime.exec.overload('java.lang.String').implementation = function (command) {
        console.log(`[+] Runtime.exec 호출됨 - 명령어: ${command}`);

        // 평문 중요정보 탐지
        if (command.includes("password") || command.includes("token")) {
            console.log("[!] 중요정보 평문 노출 감지 - 명령어에 포함된 중요정보");
            console.log(`[!] 명령어: ${command}`);
        } else {
            console.log("[+] 중요정보가 평문으로 노출되지 않음");
        }

        // 원래 동작 수행
        return this.exec(command);
    };

    Runtime.exec.overload('[Ljava.lang.String;').implementation = function (commands) {
        console.log("[+] Runtime.exec 호출됨 - 명령어 배열");

        for (let i = 0; i < commands.length; i++) {
            console.log(`    - 명령 ${i}: ${commands[i]}`);

            // 평문 중요정보 탐지
            if (commands[i].includes("password") || commands[i].includes("token")) {
                console.log("[!] 중요정보 평문 노출 감지 - 명령 배열에 포함된 중요정보");
                console.log(`[!] 명령어: ${commands[i]}`);
            }
        }

        // 원래 동작 수행
        return this.exec(commands);
    };

    // ===========================================
    // 3. ProcessBuilder.command() 후킹
    // ===========================================
    ProcessBuilder.command.overload('java.util.List').implementation = function (commands) {
        console.log("[+] ProcessBuilder.command 호출됨 - 명령어 목록");

        for (let i = 0; i < commands.size(); i++) {
            const command = commands.get(i);
            console.log(`    - 명령 ${i}: ${command}`);

            // 평문 중요정보 탐지
            if (command.includes("password") || command.includes("token")) {
                console.log("[!] 중요정보 평문 노출 감지 - 명령 목록에 포함된 중요정보");
                console.log(`[!] 명령어: ${command}`);
            }
        }

        // 원래 동작 수행
        return this.command(commands);
    };

    ProcessBuilder.command.overload('[Ljava.lang.String;').implementation = function (commands) {
        console.log("[+] ProcessBuilder.command 호출됨 - 명령어 배열");

        for (let i = 0; i < commands.length; i++) {
            console.log(`    - 명령 ${i}: ${commands[i]}`);

            // 평문 중요정보 탐지
            if (commands[i].includes("password") || commands[i].includes("token")) {
                console.log("[!] 중요정보 평문 노출 감지 - 명령 배열에 포함된 중요정보");
                console.log(`[!] 명령어: ${commands[i]}`);
            }
        }

        // 원래 동작 수행
        return this.command(commands);
    };

    console.log("[*] 프로그램 실행 명령줄 내 중요정보 평문 노출 점검 완료.");
});
