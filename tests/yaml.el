(provide 'yaml)

(defun yaml-parse-string (string &rest args)
  "Mock yaml-parse-string for testing."
  (cond
   ((string-match-p "repro-machine" string)
    '(("repro-machine" . [ (("machine" . "machine.example.com") ("password" . "secure")) ])))
   ((string-match-p "repro-sudo" string)
    '(("repro-sudo" . [ (("host" . "sudo-host") ("port" . "sudo") ("user" . "root") ("password" . "sudo-password")) ])))
   ((string-match-p "malformed" string)
    (error "YAML parsing error"))
   (t
    '(("github" . "1")
      ("github.com" . "2")
      ("example@github.com" . "3")
      ("github.com:22" . "4")
      ("example@github.com:22" . "5")
      ("api.github.com" . [ (("user" . "apikey") ("secret" . "6")) ])
      ("origin@api.github.com" . [ (("user" . "override") ("secret" . "7")) ])
      ("nested" . [ (("user" . "example") ("secret" . "8") ("test" . (("deep" . 1)))) ])
      ("me@email.com@complex-host:123" . "99")
    ))))
