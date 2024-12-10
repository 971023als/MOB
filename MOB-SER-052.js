Java.perform(function () {
    console.log("[*] SSTI 탐지 스크립트 시작");

    // 특정 템플릿 엔진 클래스 후킹 (예: Thymeleaf, Freemarker, Velocity 등)
    var TemplateEngine = Java.use("org.thymeleaf.TemplateEngine");
    var Configuration = Java.use("freemarker.template.Configuration");
    var VelocityEngine = Java.use("org.apache.velocity.app.VelocityEngine");

    // Thymeleaf 템플릿 엔진 후킹
    if (TemplateEngine) {
        console.log("[+] Thymeleaf 템플릿 엔진 후킹");
        TemplateEngine.process.overload("java.lang.String", "org.thymeleaf.context.IContext").implementation = function (templateName, context) {
            console.log("[+] Thymeleaf 템플릿 처리됨:");
            console.log("    템플릿 이름: " + templateName);
            console.log("    컨텍스트 데이터: " + context.toString());
            if (context.toString().includes("${") || context.toString().includes("#{")) {
                console.warn("[!] Thymeleaf 템플릿에서 SSTI 의심 패턴 탐지됨");
            } else {
                console.log("[+] Thymeleaf 템플릿에서 이상 없음");
            }
            return this.process(templateName, context);
        };
    }

    // Freemarker 템플릿 엔진 후킹
    if (Configuration) {
        console.log("[+] Freemarker 설정 후킹");
        Configuration.getTemplate.overload("java.lang.String").implementation = function (templateName) {
            console.log("[+] Freemarker 템플릿 로드됨:");
            console.log("    템플릿 이름: " + templateName);
            if (templateName.includes("test") || templateName.includes("debug")) {
                console.warn("[!] Freemarker 템플릿 이름에서 의심스러운 패턴 발견");
            }
            return this.getTemplate(templateName);
        };
    }

    // Velocity 템플릿 엔진 후킹
    if (VelocityEngine) {
        console.log("[+] VelocityEngine 후킹");
        VelocityEngine.evaluate.overload(
            "org.apache.velocity.context.Context", 
            "java.io.Writer", 
            "java.lang.String", 
            "java.lang.String"
        ).implementation = function (context, writer, logTag, source) {
            console.log("[+] Velocity 템플릿 평가됨:");
            console.log("    소스 코드: " + source);
            if (source.includes("$") || source.includes("#{")) {
                console.warn("[!] Velocity 템플릿에서 SSTI 의심 패턴 탐지됨");
            } else {
                console.log("[+] Velocity 템플릿에서 이상 없음");
            }
            return this.evaluate(context, writer, logTag, source);
        };
    }

    console.log("[*] SSTI 탐지 스크립트 설치 완료");
});
