Java.perform(function () {
    var accountClass = Java.use("com.example.financial.AccountManager");
    var File = Java.use("java.io.File");
    var FileInputStream = Java.use("java.io.FileInputStream");
    var MessageDigest = Java.use("java.security.MessageDigest");

    // 파일 존재 여부 확인 함수
    function fileExists(filePath) {
        var file = File.$new(filePath);
        return file.exists();
    }

    // 파일의 해시 값을 계산하는 함수
    function getFileHash(filePath) {
        try {
            var file = File.$new(filePath);
            var fis = FileInputStream.$new(file);
            var md = MessageDigest.getInstance("SHA-256");

            var buffer = Java.array('byte', Java.newArray('byte', 1024));
            var numRead;
            while ((numRead = fis.read(buffer)) != -1) {
                md.update(buffer, 0, numRead);
            }
            fis.close();

            var bytes = md.digest();
            var result = '';
            for (var i = 0; i < bytes.length; i++) {
                result += (bytes[i] & 0xff).toString(16).padStart(2, '0');
            }
            return result;
        } catch (e) {
            console.log("Error getting file hash: " + e);
            return null;
        }
    }

    // 루트 탐지 로직 세부 구현
    function checkIfDeviceIsRooted() {
        // 일반적인 루팅 표시 파일 경로
        var rootBinaries = ["/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/su", "/system/bin/.ext/.su"];
        for (var i = 0; i < rootBinaries.length; i++) {
            if (fileExists(rootBinaries[i])) {
                return true; // 루트된 기기로 판단
            }
        }
        // 기타 루팅 탐지 로직 (예: 시스템 속성 확인)
        // ...
        return false;
    }

    // 시스템 파일 무결성 확인 로직 세부 구현
    function checkIfSystemFilesAreModified() {
        // 예시 시스템 파일과 그 예상 해시값
        var systemFiles = ["/system/bin/bootloader", "/system/bin/recovery"];
        var expectedHashes = ["expected_hash1", "expected_hash2"]; // 실제 해시값으로 대체 필요

        for (var i = 0; i < systemFiles.length; i++) {
            if (getFileHash(systemFiles[i]) !== expectedHashes[i]) {
                return true; // 파일이 수정되었음을 나타냄
            }
        }
        return false;
    }

    // OS 변조 탐지 메소드
    accountClass.isOSTampered.implementation = function () {
        return checkIfDeviceIsRooted() || checkIfSystemFilesAreModified();
    };

    // ... 기존 비밀번호 변경 메소드 ...

});
