;;; auth-source-sops.el --- Integrate auth-source with sops -*- lexical-binding: t -*-

;; Author: Inkpot Monkey <inkpot@palebluebytes.space>,
;; Version: 1.0.0
;; Created: 22 Jun 2025
;; URL: https://github.com/inkpot-monkey/auth-source-sops
;; Package-Requires: ((emacs "25.1") (yaml "0.5.1"))

;;; Commentary:

;; Integrates sops (https://getsops.io/) within auth-source.

;;; Code:
(require 'auth-source)
(require 'cl-lib)
(require 'yaml)
(require 'subr-x)
(require 'json)

(declare-function yaml-parse-string "yaml" (string &rest args))

(defgroup auth-source-sops nil
  "Sops integration within auth-source."
  :prefix "auth-source-sops-"
  :group 'auth-source
  :version "30.1")

(defcustom auth-source-sops-executable "sops"
  "Path to the sops executable."
  :type 'string)

(defcustom auth-source-sops-file "~/.authinfo.sops.yaml"
  "File in which sops credentials are stored."
  :type 'file)

(defcustom auth-source-sops-age-key nil
  "A file containing the SOPS_AGE_KEY."
  :type 'file)

(cl-defun auth-source-sops-search
    (&rest spec &key backend require type max host user port &allow-other-keys)
  "Given some search query, return matching credentials.

See `auth-source-search' for details on the parameters SPEC, BACKEND, TYPE,
HOST, USER, PORT, REQUIRE, and MAX."
  (cl-assert (or (null type) (eq type (oref backend type)))
             t "Invalid sops search: %s %s")
  (cond ((eq host t)
         (warn "auth-source-sops does not handle host wildcards")
         nil)
        ((null host)
         ;; Do not build a result, as none will match when HOST is nil
         nil)
        (t
         (auth-source-sops--multiple-results host user port require max))))

(defun auth-source-sops--match-p (val criteria)
  "Return non-nil if VAL matches CRITERIA (string, list, or t)."
  (cond
   ((eq criteria t) t)
   ((null criteria) t)
   ((listp criteria) (member val criteria))
   (t (string-equal val criteria))))

(defun auth-source-sops--entry-matches-criteria-p (entry host user port require)
  "Check if ENTRY matches search criteria HOST, USER, PORT, and REQUIRE."
  (let ((entry-host (alist-get 'host entry))
        (entry-user (alist-get 'user entry))
        (entry-port (alist-get 'port entry))
        (entry-secret (or (alist-get 'secret entry)
                          (alist-get 'password entry))))
    (and
     ;; Basic criteria matching
     entry-host
     (auth-source-sops--match-p entry-host host)
     (or (null user) (auth-source-sops--match-p entry-user user))
     (or (null port)
         (auth-source-sops--match-p (and entry-port (format "%s" entry-port))
                                    (if (listp port)
                                        (mapcar (lambda (p) (format "%s" p)) port)
                                      (format "%s" port))))
     entry-secret
     ;; Required fields check
     (cl-every (lambda (field)
                 (let ((sym-field (if (keywordp field)
                                      (intern (substring (symbol-name field) 1))
                                    field)))
                   (if (eq sym-field 'secret)
                       entry-secret
                     (alist-get sym-field entry))))
               require))))

(defun auth-source-sops--build-result (entry user port)
  "Build a properly formatted result from ENTRY with fallback USER and PORT."
  (let ((entry-host (alist-get 'host entry))
        (entry-user (alist-get 'user entry))
        (entry-port (alist-get 'port entry))
        (entry-secret (or (alist-get 'secret entry)
                          (alist-get 'password entry))))
    (list :host entry-host
          :user (or entry-user user)
          :port (or entry-port port)
          :secret (lambda () (format "%s" entry-secret)))))

(defun auth-source-sops--find-matching-entries (sops-parsed host user port require)
  "Find entries in SOPS-PARSED matching HOST, USER, PORT, and REQUIRE."
  (let (results)
    (dolist (entry sops-parsed)
      (when (auth-source-sops--entry-matches-criteria-p entry host user port require)
        (push (auth-source-sops--build-result entry user port) results)))
    (nreverse results)))

(defun auth-source-sops--multiple-results (host user port &optional require max)
  "Search the sops file for matching credentials.
Returns results matching HOST, USER, PORT criteria.
Only include entries with REQUIRE fields if specified.
Limit to MAX results if specified."
  (let ((results (thread-last
                   (auth-source-sops-decrypt)
                   (auth-source-sops-parse auth-source-sops-file)
                   (mapcar #'auth-source-sops-parse-entry)
                   (cl-remove-if-not (lambda (entry)
                                       (auth-source-sops--entry-matches-criteria-p
                                        entry host user port require)))
                   (mapcar (lambda (entry)
                             (auth-source-sops--build-result entry user port))))))
    (if max
        (seq-take results max)
      results)))

(defvar auth-source-sops-backend
  (auth-source-backend
   :source "."
   :type 'sops
   :search-function #'auth-source-sops-search)
  "Auth-source backend for sops.")

(defun auth-source-sops-backend-parse (entry)
  "Create a sops auth-source backend from ENTRY."
  (when (eq entry 'sops)
    (auth-source-backend-parse-parameters entry auth-source-sops-backend)))

(if (boundp 'auth-source-backend-parser-functions)
    (add-hook 'auth-source-backend-parser-functions #'auth-source-sops-backend-parse)
  (advice-add 'auth-source-backend-parse :before-until #'auth-source-sops-backend-parse))



(defun auth-source-sops-get-string-from-file (filePath)
  "Return file content of FILEPATH as string."
  (with-temp-buffer
    (insert-file-contents filePath)
    (buffer-string)))

(defun auth-source-sops--file-modes (file)
  "Return file modes for FILE. Wrapper around `file-modes'."
  (file-modes file))

(defun auth-source-sops--check-permissions (file)
  "Check if FILE has secure permissions (0600).
Warn if permissions are too open."
  (let ((modes (auth-source-sops--file-modes file)))
    (when (and modes (> (logand modes #o077) 0))
      (warn "File %s has insecure permissions %o. Should be 0600." file modes))))

(defun auth-source-sops-decrypt ()
  "Decrypt the sops-encrypted auth file and return its contents as a string.
If `auth-source-sops-age-key' is set, use it to set the SOPS_AGE_KEY
environment variable before decryption."
  (let ((process-environment (copy-sequence process-environment)))
    (when (file-exists-p auth-source-sops-file)
      (auth-source-sops--check-permissions auth-source-sops-file))
    (with-temp-buffer
      (when auth-source-sops-age-key
        (when (file-exists-p auth-source-sops-age-key)
          (auth-source-sops--check-permissions auth-source-sops-age-key))
        (setenv "SOPS_AGE_KEY" (auth-source-sops-get-string-from-file auth-source-sops-age-key)))
      
      (let ((output-buffer (generate-new-buffer " *sops-output*"))
            (error-buffer (generate-new-buffer " *sops-error*"))
            (exit-code nil)
            (proc-done nil))
        (unwind-protect
            (progn
              (let ((proc (make-process
                           :name "sops-decrypt"
                           :buffer output-buffer
                           :stderr error-buffer
                           :connection-type 'pipe  ; Use pipe to avoid PTY issues
                           :command (list auth-source-sops-executable "decrypt" auth-source-sops-file)
                           :sentinel (lambda (p _e)
                                       (when (if (fboundp 'process-live-p)
                                                 (not (process-live-p p))
                                               (memq (process-status p) '(exit signal failed)))
                                         (setq exit-code (process-exit-status p))
                                         (setq proc-done t))))))
                  (set-process-query-on-exit-flag proc nil)
                  ;; Also handle the stderr pipe process if it exists
                  (let ((stderr-proc (get-buffer-process error-buffer)))
                    (when (processp stderr-proc)
                      (set-process-query-on-exit-flag stderr-proc nil)))
                  
                  (let ((start-time (float-time)))
                    (while (not proc-done)
                      (accept-process-output proc 0.1)
                      (when (> (- (float-time) start-time) 10.0) ;; 10 second timeout
                        (delete-process proc)
                        (error "Sops decryption timed out after 10 seconds")))))
              
              (unless (zerop exit-code)
                (error "Sops decryption failed with exit code %s: %s"
                       exit-code (with-current-buffer error-buffer (buffer-string))))
              (with-current-buffer output-buffer (buffer-string)))
          ;; Cleanup
          (when (get-buffer-process output-buffer)
            (delete-process (get-buffer-process output-buffer)))
          (kill-buffer output-buffer)
          (kill-buffer error-buffer))))))

(defun auth-source-sops-parse (file output)
  "Parse decrypted sops OUTPUT based on FILE extension."
  (cond ((string-suffix-p ".yaml" file)
         (yaml-parse-string output :object-type 'alist :object-key-type 'string))
        ((string-suffix-p ".json" file)
         (json-parse-string output :object-type 'alist :array-type 'array))
        (t (error "File parser not implemented"))))

(defun auth-source-sops-get (key entry)
  "Get value for KEY from parsed sops ENTRY.
KEY is a symbol representing the field to retrieve (e.g. `user', `host').
ENTRY is a cons cell containing the raw sops entry data."
  (let ((data (auth-source-sops-parse-entry entry)))
    (cdr (assoc key data))))

(defun auth-source-sops-parse-entry (entry)
  "Parse ENTRY into a normalized alist of credential data.
ENTRY should be a cons cell where car is the key (e.g. user@host:port)
and cdr is the value containing secret data.
Returns an alist containing parsed components (host, user, port)
merged with the secret data and original key."
  (let* ((key (car entry))
         (parsed (auth-source-sops-entry-parse-key key))
         (value (auth-source-sops-entry-parse-value (cdr entry))))
    (append value parsed `((key . ,key)))))

(defun auth-source-sops-entry-parse-key (key)
  "Parse KEY into host, user, and port components.
Supports standard auth-source formats:
 - host
 - user@host
 - host:port
 - user@host:port
 - user@email.com@host
 - user@email.com@host:port (only if port is numeric)"
  (let* ((key-str (format "%s" key))
         (host nil)
         (user nil)
         (port nil))
    ;; Extract port if present (must be at end of string, preceded by colon)
    (if (string-match ":\\([0-9]+\\)$" key-str)
        (progn
          (setq port (string-to-number (match-string 1 key-str)))
          ;; Remove port from key-str for further parsing
          (setq key-str (substring key-str 0 (match-beginning 0)))))
    
    ;; Extract user and host
    ;; Greedy match ensures everything before the LAST @ is captured as user
    (if (string-match "^\\(.*\\)@\\([^@]+\\)$" key-str)
        (progn
          (setq user (match-string 1 key-str))
          (setq host (match-string 2 key-str)))
      ;; No @ found, entire string is host
      (setq host key-str))
    
    `((host . ,host)
      (user . ,user)
      (port . ,port))))

(defun auth-source-sops-entry-parse-value (value)
  "Extract sequence items from VALUE."
  (if (and (eq (type-of value) 'vector) (> (length value) 0))
      (cl-loop for pair in (aref value 0)
               for key-unparsed = (car pair)
               for val = (cdr pair)
               when (or (stringp val) (numberp val))
               collect (cons (let ((key-str (if (symbolp key-unparsed)
                                                (symbol-name key-unparsed)
                                              (format "%s" key-unparsed))))
                               (if (string-equal key-str "machine")
                                   'host
                                 (intern key-str)))
                             val))
    (list (cons 'secret value))))

;;;###autoload
(defun auth-source-sops-enable ()
  "Enable auth-source-sops."
  (if (executable-find auth-source-sops-executable)
      (progn
        (add-to-list 'auth-sources 'sops)
        (auth-source-forget-all-cached))
    (user-error "Could not find sops executable at %s" auth-source-sops-executable)))

(provide 'auth-source-sops)
;;; auth-source-sops.el ends here

;; Local Variables:
;; ispell-buffer-session-localwords: ("auth" "yaml")
;; End:
