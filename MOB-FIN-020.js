Java.perform(function () {
    // 난독화된 클래스와 메소드 후킹
    var targetClass = Java.use("com.example.obfuscated.ClassName");
    var obfuscatedMethod = targetClass.obfuscatedMethod;
    obfuscatedMethod.implementation = function (arg) {
        console.log("난독화된 메소드 호출됨: " + arg);
        var result = obfuscatedMethod.call(this, arg);
        console.log("결과: " + result);
        return result;
    };

    // 리플렉션 사용 감시
    var ReflectMethod = Java.use("java.lang.reflect.Method");
    ReflectMethod.invoke.overload('java.lang.Object', '[Ljava.lang.Object;').implementation = function (obj, args) {
        console.log("리플렉션을 통한 메소드 호출 감지: " + this.getName());
        return this.invoke(obj, args);
    };

    // 클래스 로딩 감시
    var ClassLoader = Java.use("java.lang.ClassLoader");
    ClassLoader.loadClass.overload('java.lang.String').implementation = function (name) {
        console.log("클래스 로드 감지: " + name);
        return this.loadClass(name);
    };

    // 네트워크 통신 감시
    var HttpURLConnection = Java.use("java.net.HttpURLConnection");
    HttpURLConnection.getOutputStream.implementation = function () {
        console.log("HttpURLConnection을 통한 네트워크 통신 감지");
        return this.getOutputStream();
    };

    // 추가적인 동적 행동 감시
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload('java.lang.String').implementation = function (command) {
        console.log("Runtime.exec 호출 감지: " + command);
        return this.exec(command);
    };

    var ProcessBuilder = Java.use("java.lang.ProcessBuilder");
    ProcessBuilder.start.implementation = function () {
        console.log("ProcessBuilder.start 호출 감지");
        return this.start.call(this);
    };
});
