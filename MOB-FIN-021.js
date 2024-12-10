Java.perform(function () {
    console.log("[*] 디버깅 탐지 및 안티 디버깅 점검 시작...");

    // ======================
    // 1. 디버깅 여부 탐지
    // ======================
    const Debug = Java.use("android.os.Debug");

    Debug.isDebuggerConnected.implementation = function () {
        const result = this.isDebuggerConnected();
        console.log(`[+] isDebuggerConnected 호출됨 - 디버거 연결 상태: ${result ? "연결됨" : "연결되지 않음"}`);

        if (result) {
            console.log("[!] 디버깅 감지 - 프로그램 역분석 시도 가능성");
        }

        return result;
    };

    Debug.waitForDebugger.implementation = function () {
        console.log("[!] waitForDebugger 호출됨 - 디버거가 연결되기를 대기 중");
        console.log("[!] 안티 디버깅: 대기 상태 강제로 우회");
        return; // 대기 상태 강제로 우회
    };

    // ======================
    // 2. ptrace 호출 탐지 (리눅스 시스템 호출)
    // ======================
    const libc = Module.findExportByName("libc.so", "ptrace");
    if (libc) {
        Interceptor.attach(libc, {
            onEnter: function (args) {
                console.log(`[+] ptrace 호출 탐지됨 - 요청: ${args[0].toInt32()}`);
                if (args[0].toInt32() === 0 /* PTRACE_TRACEME */) {
                    console.log("[!] PTRACE_TRACEME 요청 감지 - 디버깅 방지 시도");
                }
            },
            onLeave: function (retval) {
                console.log(`[+] ptrace 호출 종료 - 반환값: ${retval.toInt32()}`);
            }
        });
    } else {
        console.log("[!] ptrace 함수가 libc.so에서 찾을 수 없음");
    }

    // ======================
    // 3. 디버깅 도구 탐지 (프로세스 검사)
    // ======================
    const Process = Java.use("java.lang.ProcessBuilder");

    Process.command.overload("java.util.List").implementation = function (commands) {
        console.log("[+] ProcessBuilder.command 호출됨 - 명령어 목록:");

        for (let i = 0; i < commands.size(); i++) {
            const command = commands.get(i);
            console.log(`    - 명령 ${i}: ${command}`);

            if (command.includes("gdb") || command.includes("lldb") || command.includes("windbg")) {
                console.log("[!] 디버깅 도구 탐지 - 프로그램 실행 중지 권장");
            }
        }

        return this.command(commands);
    };

    Process.command.overload("[Ljava.lang.String;").implementation = function (commands) {
        console.log("[+] ProcessBuilder.command 호출됨 - 명령어 배열:");

        for (let i = 0; i < commands.length; i++) {
            console.log(`    - 명령 ${i}: ${commands[i]}`);

            if (commands[i].includes("gdb") || commands[i].includes("lldb") || commands[i].includes("windbg")) {
                console.log("[!] 디버깅 도구 탐지 - 프로그램 실행 중지 권장");
            }
        }

        return this.command(commands);
    };

    console.log("[*] 디버깅 탐지 및 안티 디버깅 점검 완료.");
});
