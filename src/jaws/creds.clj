(in-ns 'jaws.native)

;;; Some tools for parsing credential files for jaws.native.
;;;
;;; Read http://docs.aws.amazon.com/AWSSdkDocsJava/latest/DeveloperGuide/java-dg-roles.html
;;; for an overview of using role-based credentials.
;;;
;;; Ways to supply credentials to this module:
;;; 1) Use 'add-cred-file' or 'add-cred-files' to slurp up the contents
;;;    of credentials files you have on disk into a credentials dictionary.
;;; 2) Use 'def-cred' to specify credentials without a file.
;;; 3) Use 'def-cred-instance' to add a handle to the credentials map that
;;;    uses credentials based solely on the InstanceMetadataService (IMDS)
;;;    via the com.amazonaws.auth.InstanceProfileCredentialsProvider class.
;;;    (uses the permissions associated with an EC2 instance via an IAM Role and policy.)
;;;
;;; Credentials are stored in an in-memory location so that we can quickly access them
;;; for AWS credential building operations without file I/O.  That means if you change
;;; credentials on disk you may need to 'reload-cred-files' or otherwise arrange for
;;; updating the in-memory structures.
;;;
;;; Credentials are also keyed.  The nature of the key depends on the API you use
;;; to define the credentials in this module, but you have opportunity what you'd like
;;; the key to be.


(def- ACCESS_KEY_PATTERN
  "AWS access key pattern for re-find or re-match.
   Basically <blah>access<blah>=<blah>key-id<blah>
   where <blah> is whitespace, and for the right hand expression, optional quotes.
   We try to be flexible.  Case is ignored on matching."
  #"(?i)^.*access.*=\s*[\"']?(\S{20})[\"']?\s*$")
(def- SECRET_KEY_PATTERN
  "Secret key pattern for re-find or re-match.
   Basically <blah>secret<blah>=<blah>secret-id<blah>
   where <blah> is whitespace, and for the right hand expression, optional quotes.
   We try to be flexible.  Case is ignored on matching."
  #"(?i)^.*secret.*=\s*[\"']?(\S{40})[\"']?\s*$")


(defn parse-cred
  "Return [access-key secret-key] or throw an exception if no credentials were found in the file."
  [f]
  (let [file-lines (readlines (io/as-file f))
        matchmap (select-matching-strings file-lines 
                                          {:key ACCESS_KEY_PATTERN :secret SECRET_KEY_PATTERN} re-find)
        keylines (:key matchmap)
        secretlines (:secret matchmap)
        ensure-one-line
        (fn [matches pattern file]
          (when (> (count matches) 1)
            (throw (Exception.
                    (cl-format nil
                      "Pattern ~s matched too many lines:~%~{  ~s~^~%~} in file ~s~%"
                      pattern matches file))))
          (when (< (count matches) 1)
            (throw (Exception.
                    (cl-format nil "Pattern ~s didn't match any lines in file ~s~%"
                      pattern file)))))
        must-have (fn [thing name file]
                     (if-not thing
                       (throw (Exception. (str "No " name " was found in " file)))))]
    (ensure-one-line keylines ACCESS_KEY_PATTERN f)
    (ensure-one-line secretlines SECRET_KEY_PATTERN f)
    (let [access-key (second (re-find ACCESS_KEY_PATTERN (first keylines)))
          key-secret (second (re-find SECRET_KEY_PATTERN (first secretlines)))]
      (must-have access-key "access key" f)
      (must-have key-secret "key secret" f)
      [access-key key-secret])))

;; Memory-cached information about AWS credentials
;; supplied by callers through various APIs, keyed by 'handle' in a map.
;;
;; This could go away and not be missed, unless bridging AWSCredentials and
;; AWSCredentialsProvider interfaces is somehow useful.
(defrecord CredentialInfo
    [;; File from which credentials were read, or nil if there wasn't one
     source-file
     ;; key/handle by which the user would like to refer to the credentials
     ;; This is required and must be distinct for all credentials, we use it as a
     ;; map key.  That's only likely to be a problem if you're using same named
     ;; files from multiple directories and don't use the file path as a key.
     handle

     ;; AWS clients (e.g. EC2, S3Client, etc) take either AWSCredentials
     ;; AWSCredentialsProvider
     ;;
     ;; If we have AWSCredentials, the interface supports getAWSAccessKeyId()
     ;; and getAWSSecretKey()
     credentials
     ;; If we have AWSCredentialsProvider, the interface supports getCredentials()
     ;; which returns AWSCredentials.
     credentials-provider
     ])

;;;
;;; Cred-map definition and updaters
;;;

(defonce cred-map
  ;;"Map keyed by credential handle, valued by CredentialInfo"
  (atom {}))

(defn def-cred
  "Add or update a credential entry in the cred-map.
   'handle' is the key tha will be used to refer to the credential.
   It can be whatever you like it to be.

   'access-key' is the AWS access key id.
   'key-secret' is the AWS secret key value.

   Returns the created/updated CredentialInfo object."
  [handle access-key key-secret]
  (let [cred-info
        (map->CredentialInfo
         {:handle handle
          :credentials (BasicAWSCredentials. access-key key-secret)})]
    (swap! cred-map assoc handle cred-info)
    cred-info))

(defn def-cred-instance
  "Add a handle to the credentials map that uses credentials based
   on the InstanceMetadataService (IMDS)
   via the com.amazonaws.auth.InstanceProfileCredentialsProvider class.
   Use of these credentials grants permissions based on the EC2 instance associated
   IAM Role and permissions policy.

   'handle' is the key tha will be used to refer to the credential.
   It can be whatever you like it to be.

   A com.amazonaws.AmazonClientException may arise when this credential is
   used to construct a client (e.g. an EC2 Client) if the call to this
   function was made outside of a viable role-bearing EC2 instance
   context (though it won't arise at the time def-cred-instance is called).

   Returns the created/updated CredentialInfo object."
  [handle]
  (let [cred-info
        (map->CredentialInfo
         {:handle handle
          :credentials-provider (InstanceProfileCredentialsProvider.)})]
    (swap! cred-map assoc handle cred-info)
    cred-info))

(defn add-cred-file
  "Specify a credential file to be added/updated in cred-map.
   This function has side effects, it adds credentials to an in-memory map.

   'file-spec' a java.io.File coercible file specification, tilde expansion is performed.

   'handle' a key to be used to search for the CredentialInfo in the cred-map.
   It can be any non-nil/false object type you want for a map key.
   If nil/false, the resulting credential handle will be a File object representing the
   file specification.
  
   Returns the handle used for the credentials added to cred-map."
  [file-spec handle]
  (let [path (easyfs/to-path file-spec)]
    (unless (exists? path)
      (throw (IllegalArgumentException. (str "No such file: " file-spec))))
    (let [file (easyfs/to-file path)
          handle (or handle file)
          [access-key key-secret] (parse-cred file)
          cred-info (map->CredentialInfo
                     {:handle handle :source-file file
                      :credentials (BasicAWSCredentials. access-key key-secret)})]
      (swap! cred-map assoc handle cred-info)
      handle)))
      
(defn add-cred-files
  "Specify a sequence of credential file-coercible file specs to be parsed and
   placed into cred-map for subsequent use with use-cred similar cred-binding
   functions.  If function 'handle-fn' is specified, it will be used to derive
   handles for the files (should be a function of one argument, a File).  If
   no function is specified, the file handles (keys inc red-map) will default
   to the file objects.   Returns nil.

   This function has side effects, it adds credentials to an in-memory map."
  [file-specs handle-fn]
  {:pre [(or (nil? handle-fn) (fn? handle-fn))]}
  (let [handle-fn (or handle-fn identity)
        files (map (fn [f] (easyfs/to-file (easyfs/to-path f))) file-specs)]
    (doseq [file files]
      (add-cred-file file (handle-fn file)))))

;; See also 'clear-creds' which updates cred-map as well as other stuff declared below this point.

;;;
;;; 'current' credential update and selection
;;; 

(defonce
  ^{:private true :dynamic true :doc
    "Key/handle in cred-map whose credentials we're using."}
  *current-cred-handle* (atom nil))

(defn clear-creds
  "Remove all credentials from the in-memory credentials map and auxiliary structures."
  []
  (reset! cred-map {})
  (reset! *current-cred-handle* nil))

(defn use-cred
  "Select amazon credentials for use in forthcoming AWS operations.
  The key specified must be a key in 'cred-map'.
  (use-cred (prompt-for-credentials)) may be useful.
  See also: with-cred"
  [cred-handle]
  (if-let [cred-info (get @cred-map cred-handle)]
    (reset! *current-cred-handle* cred-handle)
    (throw (Exception. (str "Credential key/handle: " cred-handle
                            " has not been defined.")))))
  
(defn get-cred-map-entry-for-access-key
  "Return the map entry access key (vs. cred-map key), or nil if there isn't one."
  [access-key]
  (first (filter #(= (:access-key %) access-key) @cred-map)))

;; Need a version of this in advance of IAM definitions below, for the prompt process
(defn get-user-account-number-for-prompt
  "Get the AWS account number of an iam user (as a string) given a
   CredentialInfo,  AWSCredentials, AWSCredentialsProvider instance."
  [cred]
  (let [cred (cond (instance? CredentialInfo cred)
                   (:credentials cred)
                   :else cred)]
    (try
      (let [iam (AmazonIdentityManagementClient. cred)]
        (second (re-find #".*::(\d+):" (.getArn (.getUser (.getUser iam))))))
      (catch Exception x "<unknown>"))))

(defn cred-account-number
  "Given a keyword/handle for credentials, return (as a string)
  the AWS account number for the credentials, or
   '<unknown>' if the credentials aren't valid."
  [cred-keyword]
  (let [cred-info (get @cred-map cred-keyword)]
    (if-not cred-info
      (throw (Exception. (str "Credentials keyword " cred-keyword
                              " is not in the credentials map."))))
    (get-user-account-number-for-prompt cred-info)))

(defn list-credentials
  "Print and return a sequence of known credentials and account numbers" []
  (println "The following credential files are known:")
  (let [cred-seq (seq @cred-map)
        max-key-length (reduce max 0 (map (fn [e] (count (str (key e)))) cred-seq))]
    (doseq [entry cred-seq]
      (let [cred-info (val entry)]
        (cl-format true "  ~vs  (~12a)  maps to ~a~%"
                   max-key-length
                   (key entry)
                   (get-user-account-number-for-prompt cred-info)
                   (or (if-let [file (:source-file cred-info)]
                         (str file))
                       "<no file specified>"))))
    cred-seq))

(defn known-cred? [cred-key]
  "Retrn true if cred-key is a keyword for which we have credential information,
   false otherwise."
  (if (get @cred-map cred-key)
    true
    false))

(defn prompt-for-credentials
  "Prompt user for keyword into cred-map for credential set to use.
  Return the (validated) keyword."
  []
  (if (empty? (list-credentials))
    (do
      (println "There are no credentials to choose from.")
      (println "Add some to the pool of credentials with def-cred, add-cred-file, and so on."))
    (loop [answer (read-string
                   (prompt "Which credentials would you like to use? (specify keyword)"))]
      (if (answer @cred-map)
        answer
        (recur (do (println "Invalid credential keyword" answer)
                   (read-string (prompt "Which credential keyword?"))))))))
      
(defn current-cred-map-entry
  "Return the map entry in cred-map indicating current credentials in use
   or nil if there aren't any except those imposed by the process' calling environment
  (Which you can get with environment-creds)."
  []
  (if-let [key (deref *current-cred-handle*)]
    (find @cred-map key)))

(defn call-with-cred
  "Dynamically bind the current AWS credentials to the specified credential key
   and execute function (taking no arguments) with the binding in effect.
   The key must be a key in the 'cred-map'.
   Example: (call-with-cred :foo #(println \"AWS user:\" (iam-get-user-account-number))).
   Returns the value of fn."
  [key fn]
  (binding [*current-cred-handle* (atom key)]
    (fn)))

(defmacro with-cred
  "Dynamically bind the current AWS credentials to the specified credential key
   and execut body with the binding in effect.  The key must be a key in the 'cred-map'.
   Example: (with-cred :foo (println \"AWS user:\" (iam-get-user-account-number)))
   Returns the value of body."
  [key & body]
  `(call-with-cred ~key (fn [] ~@body)))

(defn choose-creds
  "Interactive selection of credentials for future AWS interaction."
  []
  (use-cred (prompt-for-credentials))
  (println "Current creds:" (current-cred-map-entry)))

(defn make-aws-creds
  "Make some flavor of aws credentials such as BasicAWSCredentials from
   previously selected credentials and return them. Complain if credentials
   haven't been set with (choose-creds) or similar mechanism."
  []
  (if-not @*current-cred-handle*
    (throw (Exception. "Credentials have not been set, use (choose-creds) or (use-cred)")))
  (let [cred-info (val (current-cred-map-entry))]
    (or (:credentials cred-info)
        (:credentials-provider cred-info))))

(defn add-jdt-cred-files
  "Install JDT's ~/*.aws.cred files with handles derived from the file name
   prefixing .aws.cred.  Return sequence of paths of the cred files found."
  []
  (let [paths (children "~" {:glob "*.aws.cred"})]
    (add-cred-files paths
       (fn [file]
         (keyword (second (re-find #"([^.]+).aws.cred" (.getName file))))))
    paths))

