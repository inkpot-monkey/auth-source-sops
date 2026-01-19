;;; auth-source-sops.el --- Integrate auth-source with sops -*- lexical-binding: t -*-

;; Author: Inkpot Monkey <inkpot@palebluebytes.space>,
;; Version: 1.0.1
;; Created: 22 Jun 2025
;; URL: https://github.com/inkpot-monkey/auth-source-sops
;; Keywords: comm, tools, system
;; Package-Requires: ((emacs "28.1") (yaml "0.5.1"))

;;; Commentary:

;; This package integrates `sops' (https://getsops.io/) with the Emacs
;; `auth-source' library.  It allows you to store your credentials in
;; encrypted YAML or JSON files, providing better structure and security
;; than traditional .netrc files.

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
  :group 'auth-source)

(defcustom auth-source-sops-executable "sops"
  "Path to the sops executable."
  :type 'string)

(defcustom auth-source-sops-process-timeout 20.0
  "Timeout in seconds for sops process execution."
  :type 'float)

(defcustom auth-source-sops-error-on-fail t
  "If non-nil, signal an error when sops fails.
If nil, return nil (fail gracefully) which allows other auth-sources to be tried."
  :type 'boolean)

(defcustom auth-source-sops-file "~/.authinfo.sops.yaml"
  "File in which sops-encrypted credentials are stored."
  :type 'file)

(defcustom auth-source-sops-age-key nil
  "File containing the SOPS_AGE_KEY."
  :type '(choice (const :tag "None" nil) file))

(defcustom auth-source-sops-search-method :incremental
  "Method used to search for credentials in the sops file."
  :type '(choice (const :tag "Incremental Search" :incremental)
                 (const :tag "Full Decryption" :full)))

(cl-defun auth-source-sops-search
    (&rest spec &key backend require type max host user port &allow-other-keys)
  "Main search function for the sops auth-source backend."
  (cl-assert (or (null type) (eq type (oref backend type)))
             t "Invalid sops search: %s %s")
  (cond ((null host) nil)
        (t
         (let* ((delete-p (plist-get spec :delete))
                (results (auth-source-sops--multiple-results host user port require max)))
           (cond
            (delete-p
             (auth-source-sops--do-delete results host user port require))
            ((and (null results) (plist-get spec :create))
             (let ((created (auth-source-sops--do-create spec)))
               (if created (list created) nil)))
            ((and (eq max 0) results) t)
            (t results))))))

(defun auth-source-sops--match-p (val criteria)
  "Return non-nil if VAL matches CRITERIA."
  (cond
   ((eq criteria t) t)
   ((null criteria) t)
   ((listp criteria) (member val criteria))
   (t (and (stringp val)
           (stringp criteria)
           (not (not (string-match-p criteria val)))))))

(defun auth-source-sops--entry-matches-criteria-p (entry host user port require)
  "Check if a normalized ENTRY matches all search criteria."
  (let ((entry-host (alist-get 'host entry))
        (entry-user (alist-get 'user entry))
        (entry-port (alist-get 'port entry))
        (entry-secret (or (alist-get 'secret entry)
                          (alist-get 'password entry))))
    (and
     entry-host
     (auth-source-sops--match-p entry-host host)
     (or (null user) (auth-source-sops--match-p entry-user user))
     (or (null port)
         (auth-source-sops--match-p (and entry-port (format "%s" entry-port))
                                     (if (listp port)
                                         (mapcar (lambda (p) (format "%s" p)) port)
                                       (format "%s" port))))
     entry-secret
     (cl-every (lambda (field)
                 (let ((sym-field (if (keywordp field)
                                      (intern (substring (symbol-name field) 1))
                                    field)))
                   (if (eq sym-field 'secret)
                       entry-secret
                     (alist-get sym-field entry))))
               require))))

(defun auth-source-sops--build-result (entry user port)
  "Build a properly formatted auth-source result from normalized ENTRY."
  (let* ((entry-host (cdr (assoc 'host entry)))
         (entry-user (cdr (assoc 'user entry)))
         (entry-port (cdr (assoc 'port entry)))
         (entry-key (cdr (assoc 'key entry)))
         (entry-idx (cdr (assoc 'index entry)))
         (entry-secret (or (cdr (assoc 'secret entry))
                           (cdr (assoc 'password entry)))))
    (list :host entry-host
          :user (or entry-user user)
          :port (or entry-port port)
          :secret (lambda () (when entry-secret (format "%s" entry-secret)))
          :sops-key entry-key
          :sops-index entry-idx
          :backend auth-source-sops-backend)))

(defvar auth-source-sops--raw-cache nil
  "Cache for raw (undecrypted) structure of the sops file.
Format: ((filename . (mod-time . parsed-structure)))")

(defun auth-source-sops--get-raw-structure ()
  "Return the parsed structure of the sops file without full decryption."
  (let* ((filename (expand-file-name auth-source-sops-file))
         (attributes (file-attributes filename))
         (mod-time (file-attribute-modification-time attributes))
         (cached (assoc filename auth-source-sops--raw-cache)))
    (if (and cached (equal (car (cdr cached)) mod-time))
        (cdr (cdr cached))
      (let* ((content (auth-source-sops-get-string-from-file filename))
             (parsed (auth-source-sops-parse filename content)))
        (setq auth-source-sops--raw-cache
              (cons (cons filename (cons mod-time parsed))
                    (cl-remove filename auth-source-sops--raw-cache :test #'equal :key #'car)))
        parsed))))

(defun auth-source-sops--extract-branch (key)
  "Decrypt only the branch at KEY using `sops --extract'."
  (let ((output-buffer (generate-new-buffer " *sops-extract*"))
        (error-buffer (generate-new-buffer " *sops-extract-error*"))
        (exit-code nil)
        (proc-done nil))
    (let ((process-environment (copy-sequence process-environment)))
      (unwind-protect
          (progn
            (when auth-source-sops-age-key
              (setenv "SOPS_AGE_KEY" (auth-source-sops-get-string-from-file auth-source-sops-age-key)))
            (let ((proc (make-process
                         :name "sops-extract"
                         :buffer output-buffer
                         :stderr error-buffer
                         :connection-type 'pipe
                         :command (list auth-source-sops-executable "decrypt"
                                        "--extract" (format "[\"%s\"]" key)
                                        auth-source-sops-file)
                         :sentinel (lambda (p _e)
                                     (when (not (process-live-p p))
                                       (setq exit-code (process-exit-status p))
                                       (setq proc-done t))))))
              (set-process-query-on-exit-flag proc nil)
              (when-let ((err-proc (get-buffer-process error-buffer)))
                (set-process-query-on-exit-flag err-proc nil))
              (let ((start-time (float-time)))
                (while (not proc-done)
                  (accept-process-output proc 0.1)
                  (unless (process-live-p proc)
                    (setq exit-code (process-exit-status proc))
                    (setq proc-done t))
                  (when (> (- (float-time) start-time) auth-source-sops-process-timeout)
                    (delete-process proc)
                    (error "Sops extract timed out for %s" key))))
              (if (zerop exit-code)
                  (with-current-buffer output-buffer (buffer-string))
                (error "Sops extract failed: %s"
                       (with-current-buffer error-buffer (buffer-string))))))
        (kill-buffer output-buffer)
        (kill-buffer error-buffer)))))

(defun auth-source-sops--multiple-results (host user port &optional require max)
  "Execute the search using the configured search method."
  (if (eq auth-source-sops-search-method :full)
      (let* ((decrypted (auth-source-sops-decrypt))
             (parsed (auth-source-sops-parse auth-source-sops-file decrypted))
             (exploded (mapcan #'auth-source-sops-parse-entry parsed))
             (results (mapcar (lambda (entry)
                                (auth-source-sops--build-result entry user port))
                              (cl-remove-if-not (lambda (entry)
                                                  (auth-source-sops--entry-matches-criteria-p
                                                   entry host user port require))
                                                exploded))))
        (if (and max (> max 0)) (seq-take results max) results))
    (let* ((raw-parsed (auth-source-sops--get-raw-structure))
           (results nil))
      (cl-loop for (key . _value) in raw-parsed
               until (and max (> max 0) (>= (length results) max))
               do (let ((key-str (format "%s" key)))
                    (unless (member key-str '("sops" "data"))
                      (let ((parsed-key (auth-source-sops-entry-parse-key key)))
                        (when (auth-source-sops--match-p (alist-get 'host parsed-key) host)
                          (let* ((decrypted-branch (auth-source-sops--extract-branch key))
                                 (branch-parsed (auth-source-sops-parse auth-source-sops-file decrypted-branch))
                                 (exploded (auth-source-sops-parse-entry (cons key branch-parsed)))
                                 (branch-results (mapcar (lambda (entry)
                                                           (auth-source-sops--build-result entry user port))
                                                         (cl-remove-if-not (lambda (entry)
                                                                             (auth-source-sops--entry-matches-criteria-p
                                                                              entry host user port require))
                                                                           exploded))))
                            (setq results (append results branch-results))))))))
      (if (and max (> max 0)) (seq-take results max) results))))

(defvar auth-source-sops-backend
  (auth-source-backend
   :source "."
   :type 'sops
   :type 'sops
   :search-function #'auth-source-sops-search)
  "Auth-source backend for sops.")

(defun auth-source-sops-delete (entry)
  "Delete ENTRY from sops file."
  (auth-source-sops--do-delete (list entry) nil nil nil nil))

(defun auth-source-sops-backend-parse (entry)
  "Parse sops backend entry."
  (when (eq entry 'sops)
    (auth-source-backend-parse-parameters entry auth-source-sops-backend)))

(if (boundp 'auth-source-backend-parser-functions)
    (add-hook 'auth-source-backend-parser-functions #'auth-source-sops-backend-parse)
  (advice-add 'auth-source-backend-parse :before-until #'auth-source-sops-backend-parse))

(defun auth-source-sops-get-string-from-file (file-path)
  (with-temp-buffer
    (insert-file-contents file-path)
    (buffer-string)))

(defun auth-source-sops--file-modes (file)
  (file-modes file))

(defun auth-source-sops--check-permissions (file)
  (let ((modes (auth-source-sops--file-modes file)))
    (when (and modes (> (logand modes #o077) 0))
      (warn "File %s has insecure permissions %o. Should be 0600." file modes))))

(defun auth-source-sops-decrypt ()
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
                           :connection-type 'pipe
                           :command (list auth-source-sops-executable "decrypt" auth-source-sops-file)
                           :sentinel (lambda (p _e)
                                       (when (not (process-live-p p))
                                         (setq exit-code (process-exit-status p))
                                         (setq proc-done t))))))
                (set-process-query-on-exit-flag proc nil)
                (when-let ((err-proc (get-buffer-process error-buffer)))
                  (set-process-query-on-exit-flag err-proc nil))
                (let ((start-time (float-time)))
                  (while (not proc-done)
                    (accept-process-output proc 0.1)
                    (when (> (- (float-time) start-time) auth-source-sops-process-timeout)
                      (delete-process proc)
                      (error "Sops decryption timed out")))))
              (unless (zerop exit-code)
                (error "Sops decryption failed: %s"
                       (with-current-buffer error-buffer (buffer-string))))
              (with-current-buffer output-buffer (buffer-string)))
          (kill-buffer output-buffer)
          (kill-buffer error-buffer))))))

(defun auth-source-sops-parse (file output)
  (cond ((string-suffix-p ".yaml" file)
         (yaml-parse-string output :object-type 'alist :object-key-type 'string))
        ((or (string-suffix-p ".json" file)
             (string-suffix-p ".sops" file))
         (json-parse-string output :object-type 'alist :array-type 'array))
        (t (error "File parser not implemented for %s" file))))

(defun auth-source-sops-get (key entry)
  (let ((data (auth-source-sops-parse-entry entry)))
    (cdr (assoc key (car data)))))

(defun auth-source-sops--list-of-alists-p (val)
  "Return non-nil if VAL is a list of alists."
  (and (listp val)
       (consp (car-safe val))
       (consp (car-safe (car-safe val)))))

(defun auth-source-sops-parse-entry (entry)
  (let* ((key (car entry))
         (parsed-key (auth-source-sops-entry-parse-key key))
         (values (auth-source-sops-entry-parse-value (cdr entry)))
         (idx 0))
    (mapcar (lambda (value)
              (let ((res (append value parsed-key `((key . ,key) (index . ,idx)))))
                (setq idx (1+ idx))
                res))
            values)))

(defun auth-source-sops-entry-parse-key (key)
  (let* ((key-str (format "%s" key))
         (host nil)
         (user nil)
         (port nil))
    (if (string-match ":\\([0-9]+\\)$" key-str)
        (progn
          (setq port (string-to-number (match-string 1 key-str)))
          (setq key-str (substring key-str 0 (match-beginning 0)))))
    (if (string-match "^\\(.*\\)@\\([^@]+\\)$" key-str)
        (progn
          (setq user (match-string 1 key-str))
          (setq host (match-string 2 key-str)))
      (setq host key-str))
    `((host . ,host) (user . ,user) (port . ,port))))

(defun auth-source-sops-entry-parse-value (value)
  "Normalize the VALUE part of a sops entry.
If VALUE is a list/vector, it is treated as multiple credential sets.
Keys like `machine' and `password' are normalized."
  (cond
   ((and (vectorp value) (> (length value) 0))
    (cl-loop for item across value
             collect (auth-source-sops--normalize-entry-alist item)))
   ((auth-source-sops--list-of-alists-p value)
    (mapcar #'auth-source-sops--normalize-entry-alist value))
   ((and (listp value) (consp (car-safe value)))
    (list (auth-source-sops--normalize-entry-alist value)))
   (t (list (list (cons 'secret value))))))

(defun auth-source-sops--normalize-entry-alist (alist)
  (cl-loop for pair in alist
           for key-unparsed = (car pair)
           for val = (cdr pair)
           when (or (stringp val) (numberp val))
           collect (cons (let ((key-str (if (symbolp key-unparsed)
                                            (symbol-name key-unparsed)
                                          (format "%s" key-unparsed))))
                           (cond ((string-equal key-str "machine") 'host)
                                 ((string-equal key-str "password") 'secret)
                                 (t (intern key-str))))
                         val)))

;;;###autoload
(defun auth-source-sops-enable ()
  (if (executable-find auth-source-sops-executable)
      (progn
        (add-to-list 'auth-sources 'sops)
        (auth-source-forget-all-cached))
    (user-error "Could not find sops executable at %s" auth-source-sops-executable)))

(defun auth-source-sops--do-create (spec)
  (let* ((host (plist-get spec :host))
         (user (plist-get spec :user))
         (port (plist-get spec :port))
         (user (or user (read-string (format "User for %s: " host))))
         (secret (read-passwd (format "Password for %s@%s: " user host)))
         (port (or port (let ((p (read-string (format "Port for %s: " host))))
                          (if (string-empty-p p) nil p))))
         (entry `((user . ,user) (secret . ,secret))))
    (when port
      (setq entry (append entry `((port . ,port)))))
    (if (auth-source-sops--save-entry host entry)
        (list :host host :user user :port port :secret (lambda () secret)
              :backend (plist-get spec :backend))
      nil)))

(defun auth-source-sops--save-entry (host entry &optional overwrite)
  (let* ((raw-parsed (auth-source-sops--get-raw-structure))
         (host-str (format "%s" host))
         (existing-pair (cl-find host-str raw-parsed
                                 :key (lambda (x) (format "%s" (car x)))
                                 :test #'equal))
         (new-val (if (and existing-pair (not overwrite))
                      (let* ((decrypted-branch (auth-source-sops--extract-branch host))
                             (branch-parsed (auth-source-sops-parse auth-source-sops-file decrypted-branch)))
                        (if (vectorp branch-parsed)
                            (append (append branch-parsed nil) (list entry))
                          (list branch-parsed entry)))
                    entry))
         (exit-code 0))

      (when auth-source-sops-age-key
        (setenv "SOPS_AGE_KEY" (auth-source-sops-get-string-from-file auth-source-sops-age-key)))

      ;; 1. Unset the key first to ensure a clean state and type
      (when existing-pair
               (call-process auth-source-sops-executable nil nil nil
                             "unset" auth-source-sops-file (format "[\"%s\"]" host-str)))

      ;; 2. Save the value. If it's a list, build an array via indexed paths to circumvent sops limitations.
      (if (or (vectorp new-val) (auth-source-sops--list-of-alists-p new-val))
          (let ((idx 0)
                (new-list (if (vectorp new-val) (append new-val nil) new-val)))
            (dolist (item new-list)
              (let ((json-item (json-encode item))
                    (path (format "[\"%s\"][%d]" host-str idx)))
                (let ((curr-exit (call-process auth-source-sops-executable nil nil nil
                                               "set" auth-source-sops-file path json-item)))
                  (unless (zerop curr-exit) (setq exit-code curr-exit))))
              (setq idx (1+ idx))))
        ;; Single entry
        (let ((json-item (json-encode new-val))
              (path (format "[\"%s\"]" host-str)))
          (setq exit-code
                (call-process auth-source-sops-executable nil nil nil
                              "set" auth-source-sops-file path json-item))))
    
      (if (zerop exit-code)
          (progn
            (setq auth-source-sops--raw-cache nil)
            t)
        (error "Sops set failed with exit code %s" exit-code))))

(defun auth-source-sops--do-delete (results _host _user _port _require)
  (let ((by-key (make-hash-table :test 'equal)))
    (dolist (res results)
      (let ((key (plist-get res :sops-key)))
        (puthash key (cons res (gethash key by-key)) by-key)))
    (maphash
     (lambda (key key-results)
       (let* ((decrypted-branch (auth-source-sops--extract-branch key))
              (full-branch (auth-source-sops-parse auth-source-sops-file decrypted-branch))
              (indices-to-delete (mapcar (lambda (r) (plist-get r :sops-index)) key-results))
              (new-branch nil))
         (if (not (or (vectorp full-branch) (auth-source-sops--list-of-alists-p full-branch)))
             (auth-source-sops--unset key)
           (let ((branch-list (if (vectorp full-branch) (append full-branch nil) full-branch))
                 (kept nil))
             (cl-loop for item in branch-list
                      for idx from 0
                      do (unless (member idx indices-to-delete)
                           (push item kept)))
             (setq new-branch (nreverse kept))
             (if (null new-branch)
                 (auth-source-sops--unset key)
               (auth-source-sops--save-entry key new-branch t))))))
     by-key)
    results))

(defun auth-source-sops--unset (key)
  (let ((exit-code nil))
    (let ((process-environment (copy-sequence process-environment)))
      (with-temp-buffer
        (when auth-source-sops-age-key
          (setenv "SOPS_AGE_KEY" (auth-source-sops-get-string-from-file auth-source-sops-age-key)))
        (setq exit-code
              (call-process auth-source-sops-executable nil (list t t) nil
                            "unset" auth-source-sops-file (format "[\"%s\"]" key)))
        (if (zerop exit-code)
            (progn
              (setq auth-source-sops--raw-cache nil)
              t)
          (error "Sops unset failed: %s" (buffer-string)))))))

(provide 'auth-source-sops)
;;; auth-source-sops.el ends here
