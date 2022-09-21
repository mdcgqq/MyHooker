var jclazz = null;
var jobj = null;
function getObjClassName(obj) {
	if (!jclazz) {
		var jclazz = Java.use("java.lang.Class");
	}
	if (!jobj) {
		var jobj = Java.use("java.lang.Object");
	}
	return jclazz.getName.call(jobj.getClass.call(obj));
}

function watch(obj, mtdName) {
	var listener_name = getObjClassName(obj);
	var target = Java.use(listener_name);
	if (!target || !mtdName in target) {
		return;
	}
	target[mtdName].overloads.forEach(function (overload) {
		overload.implementation = function () {
			console.log("[WatchEvent] " + mtdName + ": " + getObjClassName(this))
			return this[mtdName].apply(this, arguments);
		};
	})
}

function OnClickListener() {
	Java.perform(function () {
		Java.use("android.view.View").setOnClickListener.implementation = function (listener) {
			if (listener != null) {
				watch(listener, 'onClick');
			}
			return this.setOnClickListener(listener);
		};
		
		Java.choose("android.view.View$ListenerInfo", {
			onMatch: function (instance) {
				instance = instance.mOnClickListener.value;
				if (instance) {
					console.log("mOnClickListener name is :" + getObjClassName(instance));
					watch(instance, 'onClick');
				}
			},
			onComplete: function () {
			}
		})
	})
}
setImmediate(OnClickListener);