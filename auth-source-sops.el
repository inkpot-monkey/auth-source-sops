;;; auth-source-sops.el --- Integrate auth-source with sops -*- lexical-binding: t -*-

;; Author: Inkpot Monkey <inkpot@palebluebytes.space>,
;; Version: 1.0.0
;; Created: 22 Jun 2025

;;; Commentary:

;; Integrates sops (https://getsops.io/) within auth-source.

;;; Code:
(require 'auth-source)
(require 'yaml)

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

(cl-defun auth-source-sops-search (&rest spec
                                   &key backend type host user port require max
                                     &allow-other-keys)
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
     (string= host entry-host)
     (or (null user)
         (and entry-user (string= user entry-user)))
     (or (null port)
         (and entry-port
              (if (numberp port)
                  (equal port entry-port)
                (equal (string-to-number port) entry-port))))
     entry-secret
     ;; Required fields check
     (or (null require)
         (seq-every-p (lambda (field)
                        (and (alist-get field entry) t))
                      require)))))

(defun auth-source-sops--build-result (entry user port)
  "Build a properly formatted result from ENTRY with fallback USER and PORT."
  (let ((entry-host (alist-get 'host entry))
        (entry-user (alist-get 'user entry))
        (entry-port (alist-get 'port entry)))
    (list :host entry-host
          :user (or entry-user user)
          :port (or entry-port port)
          :secret (lambda ()
                    (let* ((key (alist-get 'key entry))
                           (sops-output (auth-source-sops-decrypt))
                           (sops-data (auth-source-sops-parse auth-source-sops-file sops-output))
                           (entry (assoc key sops-data))
                           (data (auth-source-sops-parse-entry entry))
                           (secret (or (alist-get 'secret data)
                                       (alist-get 'password data))))
                      (format "%s" secret))))))

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
  (let* ((sops-output (auth-source-sops-decrypt))
         (sops-data (auth-source-sops-parse auth-source-sops-file sops-output))
         (sops-parsed (mapcar #'auth-source-sops-parse-entry sops-data))
         (matching-entries (auth-source-sops--find-matching-entries
                            sops-parsed host user port require)))
    
    ;; Apply max limit if specified
    (if (and max (> (length matching-entries) max))
        (seq-take matching-entries max)
      matching-entries)))

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



(defun get-string-from-file (filePath)
  "Return file content of FILEPATH as string."
  (with-temp-buffer
    (insert-file-contents filePath)
    (buffer-string)))

(defun auth-source-sops-decrypt ()
  "Decrypt the sops-encrypted auth file and return its contents as a string.
If `auth-source-sops-age-key' is set, use it to set the SOPS_AGE_KEY
environment variable before decryption."
  (let ((process-environment (copy-sequence process-environment)))
    (with-temp-buffer
      (when auth-source-sops-age-key
        (setenv "SOPS_AGE_KEY" (get-string-from-file auth-source-sops-age-key)))
      (call-process auth-source-sops-executable nil t nil
                    "decrypt" auth-source-sops-file)
      (buffer-string))))

(defun auth-source-sops-parse (file output)
  "Parse decrypted sops OUTPUT based on FILE extension.
FILE is the path to the encrypted file.
OUTPUT is the decrypted content as a string.
Currently only supports YAML files (.yaml extension).
Returns an alist representation of the parsed data."
  (cond ((string-suffix-p ".yaml" file)
         (yaml-parse-string output :object-type 'alist :object-key-type 'string))
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
  "Parse KEY into host, user, and port components."
  (let* ((key-str (format "%s" key))
         (user-host (split-string key-str "@"))
         (user (if (> (length user-host) 1)
                   (car user-host)
                 nil))
         (host-port (if (> (length user-host) 1)
                        (nth 1 user-host)
                      (car user-host)))
         (host-port-split (split-string host-port ":"))
         (host (car host-port-split))
         (port (if (> (length host-port-split) 1)
                   (string-to-number (nth 1 host-port-split))
                 nil)))
    `((host . ,host)
      (user . ,user)
      (port . ,port))))

(defun auth-source-sops-entry-parse-value (value)
  "Extract sequence items from VALUE."
  (if (eq (type-of value) 'vector)
      (cl-remove-if-not
       (lambda (pair)
         (or (stringp (cdr pair))
             (numberp (cdr pair))))
       (mapcar (lambda (pair)
                 (cons (intern (car pair)) (cdr pair)))
               (aref value 0)))
    (list (cons 'secret value))))

(defun auth-source-sops-enable ()
  "Enable auth-source-sops."
  (if (executable-find auth-source-sops-executable)
      (progn
        (add-to-list 'auth-sources 'sops)
        (auth-source-forget-all-cached))
    (user-error "Could not find sops executable at %s" auth-source-sops-executable)))

(provide 'auth-source-sops)
;;; auth-source-sops.el ends here
