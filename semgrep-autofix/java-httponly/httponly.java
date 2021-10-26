// Modified from
// https://github.com/returntocorp/semgrep-rules/blob/develop/java/lang/security/audit/cookie-missing-httponly.java.
@Controller
public class CookieController {

    @RequestMapping(value = "/cookie1", method = "GET")
    public void setCookie(@RequestParam String value, HttpServletResponse response) {
        Cookie cookie = new Cookie("cookie", value);
        response.addCookie(cookie);
    }

    @RequestMapping(value = "/cookie4", method = "GET")
    public void explicitDisable(@RequestParam String value, HttpServletResponse response) {
        Cookie cookie = new Cookie("cookie", value);
        cookie.setHttpOnly(false);
        response.addCookie(cookie);
    }
}
