// Modified from https://github.com/returntocorp/semgrep-rules/blob/develop/go/lang/security/audit/xss/import-text-template.go

package main

// ruleid: import-text-template-fix
import (
  "net/http"
  "text/template"
  "encoding/json"
  "io/ioutil"
  "os"
)
// removed