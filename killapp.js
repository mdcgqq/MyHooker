function main(){
    Java.perform(function(){
        //finish();
        var clazz = Java.use("android.app.Activity");
        clazz.finish.overload().implementation = function(){
            console.warn(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
        }

        //android.os.Process.killProcess(android.os.Process.myPid());
        var clazz2 = Java.use("android.os.Process");
        clazz2.killProcess.implementation = function(){
            console.warn(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
        }

        // System.exit(0);//正常退出
        // System.exit(1);//非正常退出
        var clazz3 = Java.use("java.lang.System");
        clazz3.exit.implementation = function(){
            console.warn(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
        }
    });
}
setImmediate(main);