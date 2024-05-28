Java.perform(function () {
    var SecurityManagerClass = Java.use("com.example.security.SecurityManager");
    var changePasswordMethod = SecurityManagerClass.changePassword;

    changePasswordMethod.implementation = function (userId, oldPassword, newPassword) {
        console.log("비밀번호 변경 시도: 사용자 ID - " + userId);

        if (!isPasswordComplex(newPassword)) {
            console.error("비밀번호 복잡성 요구사항을 충족하지 않음");
            return false;
        }

        if (!isPasswordUnique(userId, newPassword)) {
            console.error("이전에 사용된 비밀번호임");
            return false;
        }

        if (!isUserBehaviorNormal(userId)) {
            console.error("비정상적인 사용자 행동 감지");
            return false;
        }

        return changePasswordMethod.call(this, userId, oldPassword, newPassword);
    };

    function isPasswordComplex(password) {
        var hasUpperCase = /[A-Z]/.test(password);
        var hasLowerCase = /[a-z]/.test(password);
        var hasNumbers = /\d/.test(password);
        var hasSpecialChars = /[\W_]/.test(password);
        var isLongEnough = password.length >= 8;
        return hasUpperCase && hasLowerCase && hasNumbers && hasSpecialChars && isLongEnough;
    }

    function isPasswordUnique(userId, newPassword) {
        var passwordHistory = getPasswordHistoryForUser(userId);
        return !passwordHistory.includes(newPassword);
    }

    function isUserBehaviorNormal(userId) {
        var userBehaviorData = getUserBehaviorData(userId);
        if (userBehaviorData.loginAttempts > 5) {
            console.log("경고: 빈번한 로그인 시도 감지");
            return false;
        }
        if (userBehaviorData.currentLocation !== userBehaviorData.lastKnownLocation) {
            console.log("경고: 지리적 위치 변경 감지");
            return false;
        }
        if (userBehaviorData.currentDevice !== userBehaviorData.lastUsedDevice) {
            console.log("경고: 새로운 기기 사용 감지");
            return false;
        }
        return true;
    }

    function getPasswordHistoryForUser(userId) {
        return ["hashedPassword1", "hashedPassword2", "hashedPassword3"];
    }

    function getUserBehaviorData(userId) {
        return {
            loginAttempts: 3,
            currentLocation: '서울',
            lastKnownLocation: '서울',
            currentDevice: 'Galaxy S21',
            lastUsedDevice: 'Galaxy S21'
        };
    }
});
