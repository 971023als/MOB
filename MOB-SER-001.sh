Java.perform(function () {
    var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
    var rawQuery = SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;');

    rawQuery.implementation = function (sql, selectionArgs) {
        console.log("실행되는 SQL 쿼리: " + sql);

        // 잠재적인 SQL 인젝션 패턴 검사 및 실행 시간 분석
        detectSQLInjection(sql, selectionArgs);

        var startTime = Date.now();
        var result = rawQuery.call(this, sql, selectionArgs);
        var executionTime = Date.now() - startTime;

        if (executionTime > 1000) { // 1초 이상 걸리는 쿼리에 대한 경고
            console.log("경고: 비정상적으로 긴 실행 시간 (" + executionTime + "ms)");
        }

        return result;
    };

    function detectSQLInjection(sql, args) {
        var suspiciousPatterns = [
            'union', 'select', '--', ';', '\\', '/', '/*', '*/', '@@', '@', 'char', 'nchar', 'varchar', 'nvarchar', 
            'alter', 'begin', 'cast', 'create', 'cursor', 'declare', 'delete', 'drop', 'end', 'exec', 'execute', 
            'fetch', 'insert', 'kill', 'open', 'sys', 'sysobjects', 'syscolumns', 'table', 'update'
        ];
        var lowerSql = sql.toLowerCase();
        
        // SQL 쿼리 문자열 및 파라미터에서 의심스러운 패턴 검사
        suspiciousPatterns.forEach(function(pattern) {
            if (lowerSql.includes(pattern)) {
                console.log("경고: 잠재적인 SQL 인젝션 패턴 발견 (" + pattern + ")");
            }
        });

        if (args !== null) {
            for (var i = 0; i < args.length; i++) {
                var arg = args[i].toLowerCase();
                suspiciousPatterns.forEach(function(pattern) {
                    if (arg.includes(pattern)) {
                        console.log("경고: 쿼리 파라미터에서 잠재적인 SQL 인젝션 패턴 발견 (" + pattern + ")");
                    }
                });
            }
        }

        // 특정 키워드의 사용 빈도수 분석
        var keywordCount = (sql.match(/union|select|insert|delete|update/gi) || []).length;
        if (keywordCount > 5) {
            console.log("경고: 비정상적인 키워드 사용 빈도 (" + keywordCount + "회)");
        }
    }
});
