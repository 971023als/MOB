Java.perform(function () {
    // 파일 업로드를 담당하는 클래스와 메소드 후킹
    var FileUploadClass = Java.use("com.example.upload.FileUploadManager");
    var uploadMethod = FileUploadClass.uploadFile;
    var File = Java.use("java.io.File");
    var URLConnection = Java.use("java.net.URLConnection");

    // 업로드 메소드 후킹
    uploadMethod.implementation = function (fileUri) {
        console.log("파일 업로드 감지: " + fileUri);

        // 파일 URI를 실제 파일 경로로 변환
        var filePath = fileUriToPath(fileUri);
        var file = File.$new(filePath);

        // 파일 속성 검사
        if (file.exists()) {
            console.log("파일 이름: " + file.getName());
            console.log("파일 크기: " + file.length() + " 바이트");

            // 파일 확장자 검사
            var fileName = file.getName();
            var fileExtension = fileName.substring(fileName.lastIndexOf('.') + 1);
            console.log("파일 확장자: " + fileExtension);

            // MIME 타입 추정
            var mimeType = URLConnection.guessContentTypeFromName(fileName);
            console.log("MIME 타입: " + mimeType);
        } else {
            console.log("파일이 존재하지 않음: " + filePath);
        }

        return uploadMethod.call(this, fileUri);
    };

    // fileUri를 실제 파일 경로로 변환하는 함수
    function fileUriToPath(fileUri) {
        if (fileUri.startsWith("file://")) {
            // 'file://'을 제거하고 나머지 부분을 파일 경로로 사용
            return fileUri.substring(7);
        } else {
            // 다른 유형의 URI 처리 (예: content://)
            console.log("변환할 수 없는 URI 형식: " + fileUri);
            return null;
        }
    }
});
