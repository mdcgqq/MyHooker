function hook_hasOnlyVpnAndAppsTrustAnchors() {
    Java.perform(function () {
        var cls = Java.use("com.android.certinstaller.CredentialHelper")
        cls.hasOnlyVpnAndAppsTrustAnchors.implementation = function () {
            var ret = this.hasOnlyVpnAndAppsTrustAnchors.apply(this, arguments)
            console.log("The result is " + ret)
            ret = false
            return ret
        }
    })
}

function main() {
    hook_hasOnlyVpnAndAppsTrustAnchors()
}
setImmediate(main)