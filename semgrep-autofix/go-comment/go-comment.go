// Modified
// https://github.com/returntocorp/semgrep-rules/blob/develop/go/lang/security/audit/net/cookie-missing-httponly.go.

package util

import (
    "net/http"
    "time"
)

/* cookie setter getter */

func SetCookie(w http.ResponseWriter, name, value string){
    // ruleid: cookie-missing-httponly
    cookie := http.Cookie{
        Name: name,
        Value: value,
    }
    http.SetCookie(w, &cookie)
}

func SetSecureCookie(w http.ResponseWriter, name, value string){
    // ok: cookie-missing-httponly
    cookie := http.Cookie{
        Secure: true,
        HttpOnly: true,
        Name: name,
        Value: value,
    }
    http.SetCookie(w, &cookie)
}

func DeleteCookie(w http.ResponseWriter, cookies []string){
    for _,name := range cookies{
        // ruleid: cookie-missing-httponly
        cookie := &http.Cookie{
            Name:     name,
            Value:    "",
            Expires: time.Unix(0, 0),
        }
        http.SetCookie(w, cookie)
    }
}
