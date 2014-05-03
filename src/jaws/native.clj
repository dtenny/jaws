(ns jaws.native
  (:use clojure.repl)
  (:use clojure.set)
  (:use [jdt core cl shell])
  (:use [jdt.easyfs :exclude [copy]])
  (:use [clojure.java.io])
  (:use [clojure.pprint :only [cl-format]])
  (:use [clojure.tools.logging :exclude [trace]])
  (:import [com.amazonaws AmazonServiceException])
  (:import [com.amazonaws.auth BasicAWSCredentials])
  (:import [com.amazonaws.regions Regions Region])
  (:import [com.amazonaws.services.autoscaling AmazonAutoScalingClient])
  (:import [com.amazonaws.services.cloudwatch AmazonCloudWatchClient])
  (:import [com.amazonaws.services.cloudwatch.model
            DescribeAlarmsRequest])
  (:import [com.amazonaws.services.ec2 AmazonEC2Client AmazonEC2])
  (:import [com.amazonaws.services.ec2.model
            GetConsoleOutputRequest CreateImageRequest CreateTagsRequest
            DeleteSnapshotRequest DeregisterImageRequest
            DescribeImagesRequest DescribeInstancesRequest DescribeInstancesResult 
            DescribeInstanceStatusRequest
            DescribeKeyPairsRequest DescribeSecurityGroupsRequest DescribeTagsRequest
            Filter Instance InstanceAttributeName Image
            LaunchPermissionModifications LaunchPermission
            ModifyImageAttributeRequest ModifyInstanceAttributeRequest RunInstancesRequest
            StartInstancesRequest StopInstancesRequest Tag TerminateInstancesRequest])
  (:import [com.amazonaws.services.elasticloadbalancing AmazonElasticLoadBalancingClient])
  (:import [com.amazonaws.services.elasticloadbalancing.model DescribeLoadBalancersRequest])
  (:import [com.amazonaws.services.identitymanagement AmazonIdentityManagementClient])
  (:import [com.amazonaws.services.identitymanagement.model
            GetInstanceProfileRequest GetRolePolicyRequest GetRoleRequest
            ListRolePoliciesRequest])
  (:import java.io.File))

;;;
;;;
;;; Fixes to jdt.core 0.1.0
;;;
(defn listify-safe                      ;-> listify, but that loses order of elements
  "Similar to seqify, but ensures that the returned collection type is a List.
   If x is a singleton datum, return a list of one element, x.
   If x is a non-list collection return a list for it.
   If x is a sequence, return it as a list.
   Nil is given special treatment and is turned into an empty list
   however false is not converted into an empty sequence.
   Element order is retrained so that sorted inputs preserve their order."
  [x]
  (cond (list? x) x
        (seq? x) (apply list x)
        (coll? x) (apply list x)
        (nil? x) ()
        :else (list x)))


;;;
;;; Conventions
;;;
;;; Functions named 'describe-*' or 'list-*' are named after AWS methods.
;;; Functions named 'report-*' are things that use 'describe-*' results to print reports on that data.
;;; Most report functions default to one-line-per-entity formats unless other options are specified.
;;;
;;; Unless an identifier says "*-id" then the object in question is probably an AWS entity, not an entity id.
;;; I.e. 'instance' will be an Instance object, not an instance id.  Usually the documentation will clarify
;;; questions on the formal parameters, if there are any.
;;;

(defn- ensure-one-line "Fail we matched other than one line" [matched-lines key]
  (when (> (count matched-lines) 1)
    (throw (Exception. (cl-format nil "Matched too many ~s lines:~%~{  ~s~^~%~}~%"
                                  key matched-lines))))
  (when (< (count matched-lines) 1)
    (throw (Exception. (str "Didn't match any lines for" key)))))

(def- ACCESS_KEY_PATTERN "Access key pattern for re-find or re-match"
  #"(?i)^.*access.*=\s*(\S{20})\s*$")
(def- SECRET_KEY_PATTERN "Secret key pattern for re-find or re-match"
  #"(?i)^.*secret.*=\s*(\S{40})\s*$")

(defn parse-cred "Return [access-key secret-key] or nil if not found in file"
  [f]
  (let [matchmap (select-matching-strings (readlines (as-file f))
                   {:key ACCESS_KEY_PATTERN :secret SECRET_KEY_PATTERN} re-find)
        keylines (:key matchmap)
        secretlines (:secret matchmap)]
    (ensure-one-line keylines :key)
    (ensure-one-line secretlines :secret)
    [(second (re-find ACCESS_KEY_PATTERN (first keylines)))
     (second (re-find SECRET_KEY_PATTERN (first secretlines)))]))

(def cred-paths "Files we consult for credentials"
  (children "~" {:glob "*.aws.cred"}))

(def cred-map
  "Map keyed by partial cred file identifier, valued by [key secret path] vectors."
  (atom 
   (into {}
         (map (fn [path]
                (let [keyname (keyword (second (re-find #"([^.]+).aws.cred"
                                                        (str (.getFileName path)))))
                      key-secret-vec (parse-cred path)]
                  (unless key-secret-vec
                          (warn "Unable to find credentials in " path))
                  {keyname (conj key-secret-vec path)}))
              cred-paths))))

(defn third [coll] (nth coll 2))
(defn cred-map-entry-access-key [map-entry] (first (val map-entry)))
(defn cred-map-entry-secret [map-entry] (second (val map-entry)))
(defn cred-map-entry-file-path [map-entry] (third (val map-entry)))
(defn get-cred-map-entry-for-access-key
  "Return the map entry access key (vs. cred-map key), or nil if there isn't one."
  [access-key]
  (first (filter #(= (cred-map-entry-access-key %) access-key) @cred-map)))

;; Need a version of this in advance of IAM definitions below, for the prompt process
(defn get-user-account-number-for-prompt
  "Get the AWS account number of an iam user (as a string)"
  ([accesskey secret]
     (try
       (let [iam (AmazonIdentityManagementClient. (BasicAWSCredentials. accesskey secret))]
         (second (re-find #".*::(\d+):" (.getArn (.getUser (.getUser iam))))))
       (catch Exception x "<unknown>"))))

(defn cred-account-number
  "Given a keyword for credentials, return (as a string) the AWS account for the credentials, or
   '<unknown>' if the credentials aren't valid."
  [cred-keyword]
  (let [cred-info (get @cred-map cred-keyword)]
    (if-not cred-info
      (throw (Exception. (str "Credentials keyword " cred-keyword
                              " is not in the credentials map."))))
    (let [[access-key secret-key _] cred-info]
      (get-user-account-number-for-prompt access-key secret-key))))

(defn list-credentials "Print list of known credentials and account numbers" []
  (println "The following credential files are known:")
  (let [cred-seq (seq @cred-map)
        max-key-length (reduce max (map (fn [e] (count (str (key e)))) cred-seq))]
    (doseq [entry cred-seq]
      (let [[access-key secret-key cred-file-path] (val entry)]
        (cl-format true "  ~vs  (~12a)  maps to ~a~%"
                   max-key-length
                   (key entry)
                   (get-user-account-number-for-prompt access-key secret-key)
                   (str cred-file-path))))))

(defn prompt-for-credentials
  "Prompt user for keyword into cred-map for credential set to use.
  Return the (validated) keyword."
  []
  (list-credentials)
  (loop [answer (read-string
                 (prompt "Which credentials would you like to use? (specify keyword)"))]
    (if-let [creds (answer @cred-map)]
      answer
      (recur (do (println "Invalid credential keyword" answer)
                 (read-string (prompt "Which credential keyword?")))))))
      
;; We wrap amazonica's defcedential so we can query the credentials in use
;; (which amazonica hides in a private atom), and so we can see the creds represented
;; as a keyword in cred-map isntead of something less intuitive.
(defonce
  ^{:private true :dynamic true :doc
    "Key in cred-map whose credentials we're using.
    A nil key means we're using whatever is in the calling process environment."}
  *current-cred-key* (atom nil))

(defn current-cred-map-entry
  "Return the map entry in cred-map indicating current credentials in use
   or nil if there aren't any except those imposed by the process' calling environment
  (Which you can get with environment-creds)."
  []
  (if-let [key (deref *current-cred-key*)]
    (find @cred-map key)))

;;DefaultAWSCredentialsProviderChain 	
;;AWS credentials provider chain that looks for credentials in this order: Environment Variables - AWS_ACCESS_KEY_ID and AWS_SECRET_KEY Java System Properties - aws.accessKeyId and aws.secretKey Instance profile credentials delivered through the Amazon EC2 metadata service
;;EnvironmentVariableCredentialsProvider 	
;;AWSCredentialsProvider implementation that provides credentials by looking at the: AWS_ACCESS_KEY_ID (or AWS_ACCESS_KEY) and AWS_SECRET_KEY (or AWS_SECRET_ACCESS_KEY) environment variables.
(defn environment-creds []
  "Return information on credentials in the calling process environment that could
  be used by this module if not superseded by use of 'defcred' or related amazonica behavior."
  ;; I'm using here what the EC2 CLI uses.
  (let [key (System/getenv "AWS_ACCESS_KEY")
        secret (System/getenv "AWS_SECRET_KEY")]
    (if (and key secret)
      {:*env* [key secret nil]})))

(defn defcred
  "Specify in-process amazon credentials which will override any active in the
  jaws process environment. The key specified must be a key in the 'cred-map'.
  (defcred (prompt-for-credentials)) may be useful."
  [key]
  (if-let [creds (key @cred-map)]
    (reset! *current-cred-key* key)
    (throw (Exception. (str "Invalid cred-map key: " key)))))
  
(defn call-with-cred
  "Dynamically bind the current AWS credentials to the specified credential key
   and execute function (taking no arguments) with the binding in effect.
   The key must be a key in the 'cred-map'.
   Example: (call-with-cred :foo #(println \"AWS user:\" (iam-get-user-account-number))).
   Returns the value of fn."
  [key fn]
  (binding [*current-cred-key* (atom key)]
    (fn)))

(defmacro with-cred
  "Dynamically bind the current AWS credentials to the specified credential key
   and execut body with the binding in effect.  The key must be a key in the 'cred-map'.
   Example: (with-cred :foo (println \"AWS user:\" (iam-get-user-account-number)))
   Returns the value of body."
  [key & body]
  `(call-with-cred ~key (fn [] ~@body)))

(defn choose-creds
  "Interactive selectiobn and activataion of credentials for future AWS interaction."
  []
  (defcred (prompt-for-credentials))
  (println "Current creds:" (current-cred-map-entry)))

(defn make-aws-creds
  "Make some flavor of aws credentials such as BasicAWSCredentials from previously selected credentials
   and return them. Complain if credentials haven't been set with (choose-creds) or similar mechanism."
  []
  (if-not @*current-cred-key*
    (throw (Exception. "Credentials have not been set, use (choose-creds) or (defcred)")))
  (let [current-creds (val (current-cred-map-entry))]
    (BasicAWSCredentials. (first current-creds) (second current-creds))))

(defn update-cred
  "Given a key value pair as would be present in 'cred-map',
  update or add the key (with new value) in the cred-map."
  [credkey credvalue]
  (when-let [old-creds (credkey @cred-map)]
    (println "Replacing" credkey "credentials")
    (println "  Old:" old-creds)
    (println "  New:" credvalue)
    (do (reset! cred-map (assoc @cred-map credkey credvalue))
        (when (= credkey @*current-cred-key*)
          (println "Using new AWS credentials")))))

(defonce
  ^{:doc "region keyword to Regions enum mapping"}
  region-map
  (into {}
        (map (fn [region-enum]
               [(keyword (.getName region-enum))
                (Region/getRegion region-enum)])
             (seq (Regions/values)))))

(def ^{:dynamic true :doc "Keyword indicating desired region for operations that don't otherwise specify a region."}
  *region* :us-east-1)

(defn regions-for-key
  "Return a collection of regions (usually one) for some region-keyword from
   'region-map' or :all.  If region-keyword is not in region-map or :all,
   return the value of *region*.  If the keyword is :all, return all regions of
   interest (a subset of all known regions, since I don't have any accounts
   where I use all known regions yet)."
  [region-key]
  (cond (get region-map region-key)
        [(region-key region-map)]
        (= region-key :all)
        [(:us-east-1 region-map) (:eu-west-1 region-map)
         (:us-west-2 region-map) (:ap-southeast-1 region-map)]
        :else
        [(*region* region-map)]))



;;; Stupid reporting aids
(def- ^:dynamic *indent* "Number of spaces to indent each line printed" 0)

(defn- do-indent "Print n spaces *out*"
  ([] (do-indent *indent*))
  ([n] (dorun (map #(.append *out* %) (repeat n \space)))))


;;;
;;; IdentityManagement (IAM)
;;;

(defn ^AmazonIdentityManagementClient iam
  "Return an AmazonIdentityManagementClient ready for calls."
  []
  (let [iam (AmazonIdentityManagementClient. (make-aws-creds))]
    (.setRegion iam (*region* region-map))
    iam))

(defn iam-get-user-name
  "Get a the currently credential user's user name"
  []
  (.getUserName (.getUser (.getUser (iam)))))

(defn iam-get-user-account-number
  "Return the account number as a string from a User"
  []
  (second (re-find #".*::(\d+):" (.getArn (.getUser (.getUser (iam)))))))

(defn role-name-exists?
  "Return true if the specified IAM role name exists, false otherwise"
  [role-name]
  (try
    ;; This throws an exception if the role does not exist 
    (.getRole (iam) 
              (doto (GetRoleRequest.) (.setRoleName role-name)))
    true
    (catch Exception e false)))

(defn get-instance-profile
  "Return an InstanceProfile object if the indicated name exists, nil if it does not
   exist."
  [ip-name]
  (try
    (.getInstanceProfile
     (.getInstanceProfile (iam)
                          (doto (GetInstanceProfileRequest.)
                            (.setInstanceProfileName ip-name))))
    (catch Exception e nil)))

(defn get-role-policy-names
  "Retrieve all role policy names for the specified role-name, or nil if
   there aren't any.
   *TBD* May or may not need a catch block inserted for invalid role names."
  [role-name]
  (.getPolicyNames
   (.listRolePolicies
    (iam) (doto (ListRolePoliciesRequest.)
            (.setRoleName role-name)))))
    
(defn get-role-policy-documents
  "Retrieve all role policy documents for the specified role-name, or nil if there
   aren't any.
   *TBD* May or may not need a catch block inserted for invalid role names."
  [role-name]
  (map (fn [policy-name]
         ;; Note that this decodes application/x-www-form-urlencoded MIME format, 
         ;; not true RFC3986 format. It differs on only an escape or two, I suspect.
         (java.net.URLDecoder/decode 
          (.getPolicyDocument
           (.getRolePolicy
            (iam) (doto (GetRolePolicyRequest.)
                    (.setPolicyName policy-name)
                    (.setRoleName role-name)))) "UTF-8"))
       (get-role-policy-names role-name)))

(defn get-instance-profile-policy-documents
  "Retrieve all policy documents for all roles associated with an instance profile.
   Throw an exception if the instance profile name is invalid.
   Name should not be the ARN, but the general user name."
  [ip-name]
  (if-let [instanceProfile (get-instance-profile ip-name)]
    (flatten
     (map (fn [role] (get-role-policy-documents (.getRoleName role)))
          (.getRoles instanceProfile)))
    (throw (Exception. (str "InstanceProfile name '" ip-name "' does not exist.")))))

(defn report-roles
  []
  (let [result (.listRoles (iam))
        dateFormatter (java.text.SimpleDateFormat. "yyyyMMdd-HHmmssZ")
        dateFormat (fn [date] (.format dateFormatter date))]
    (if (.getIsTruncated result)
      (println "** TRUNCATED **"))      ;TODO: make sure we don't get this
    (doseq [role (.getRoles result)]
      (println (.getRoleId role)
               ;;(.getRoleName role)
               ;;(.getPath role)
               (dateFormat (.getCreateDate role))
               (.getArn role))
      ;;(println "   " (.getAssumeRolePolicyDocument role))
      )))

(defn report-instance-profiles
  []
  (let [result (.listInstanceProfiles (iam))]
    (if (.getIsTruncated result)
      (println "** TRUNCATED **"))      ;TODO: make sure we don't get this.
    (println "ProfileId ProfileName Arn Roles")
    (doseq [ip (.getInstanceProfiles result)]
      (println (.getInstanceProfileId ip)
               (.getInstanceProfileName ip)
               ;; (.getPath ip)
               (.getArn ip)
               (map (fn [role] (.getRoleName role)) (.getRoles ip))))))


;;;
;;; EC2 - General
;;;

(defn ^AmazonEC2Client ec2
  "Return an AmazonEC2Client instance ready for calls for a single (optional) region.
   'region' is a keyword defaulting to *region*."
  ([] (ec2 *region*))
  ([region]
     (let [ec2 (AmazonEC2Client. (make-aws-creds))
           region (if (instance? Region region) region (get-valid region-map region))]
       (.setRegion ec2 region)
       ec2)))


(defn key-pair-exists?
  "Return true if key pair name exists on current credentialed account, false otherwise"
  [key-pair-name]
  (let [result (.describeKeyPairs (ec2)
                (doto (DescribeKeyPairsRequest.)
                  (.setFilters [(Filter. "key-name" [key-pair-name])])))
        key-pairs (.getKeyPairs result)]
    (= (count key-pairs) 1)))

(defn security-group-id-exists?
  "Return true if the specified security group id exists, false if it does not."
  [group-id]
  ;; Throws if the group does not exist.
  (try 
    (let [result (.describeSecurityGroups (ec2)
                                          (doto (DescribeSecurityGroupsRequest.)
                                            (.setGroupIds [group-id])))]
      (>= (count (.getSecurityGroups result)) 1))
    true
    (catch Exception e false)))

(defn security-group-name-exists?
  "Return true if the specified security group name exists, false if it does not."
  [group-name]
  ;; Throws if the group does not exist.
  (try 
    (let [result (.describeSecurityGroups (ec2)
                                          (doto (DescribeSecurityGroupsRequest.)
                                            (.setGroupNames [group-name])))]
      (>= (count (.getSecurityGroups result)) 1))
    true
    (catch Exception e false)))

(defn- sort-aws-tags
  "Given a sequence of Tags, 
   sort them lexicographically by key and value names unless there is a supplied
   collection of key strings, in which case the order of keys in the collection
   will be used as the sort order for any keys in map entries.  Tag keys whose names aren't

   Example (sort-aws-tags (#Tag<:key foo :value bar> #Tag<:key Name :value fred>) [\"Name\"])
           => (#Tag<:key Name :value fred> #Tag<:key foo :value bar>)
   Normally the map with :key 'foo' would come first"
  [tag-list preferred-keys]
  (let [keysmap (if preferred-keys
                  (into {} (for [x (range (count preferred-keys))] [(nth preferred-keys x) x]))
                  {})
        comp (fn [tag1 tag2]
               (let [p1 (get keysmap (.getKey tag1)) ;'p' for priority
                     p2 (get keysmap (.getKey tag2))]
                 (cond (and p1 p2) (compare [p1 (.getValue tag1)] [p2 (.getValue tag2)])
                       p1 -1               ;prioritied key sorts < nonprioritied key
                       p2 1                ;nonprioritied key is > prioritied key
                       ;; Neither map has a priority key
                       :else (compare [(.getKey tag1) (.getValue tag1)]
                                      [(.getKey tag2) (.getValue tag2)]))))]
    (sort comp tag-list)))

(defn- squish-tags
  "Tag a list of tags and compress them into a single vector of strings of the form 'key=val'.
   E.g. [Name=this is a tag description, ...]"
  [tag-list]
  (mapv (fn [tag] (str (.getKey tag) "=" (.getValue tag)))
        (sort-aws-tags tag-list ["Name" "aws:autoscaling:groupName"])))

(defn report-tags
  "Print tag information for any specific EC2 entity that can have tags.
   Specify the entity ID."
  [entity]
  (let [result (.describeTags (ec2)
                 (doto (DescribeTagsRequest.)
                   (.setFilters [(Filter. "resource-id" [entity])])))
        tagDescriptions (.getTags result)]
    (if (empty? tagDescriptions)
      (println "No tags exist for" entity)
      (doseq [tagDescription tagDescriptions]
        (println (.getResourceId tagDescription)
                 (.getKey tagDescription)
                 (.getResourceType tagDescription)
                 (.getValue tagDescription))))))
  
(defn create-tags
  "Create tags for any specific EC2 entity that can have tags.
   Specify the entity ID (or list of entity IDs) and a map of tag key/value pairs.
   Strings and vals are assumed strings, however keywords are acceptable
   in which case their names will be used.
   Returns nil."
  [entity tag-map]
  {:pre [(map? tag-map)]}
  (let [strify (fn [x] (if (keyword? x) (name x) (str x)))
        tags (map (fn [e] (Tag. (strify (key e)) (strify (val e)))) tag-map)]
    (.createTags (ec2) (CreateTagsRequest. (listify-safe entity) tags))))

;;;
;;; EC2 - Filter construction
;;;

(defn make-ec2-filter
  "Make and return an ec2.model.Filter given a key and value.
   If key-map is specified, it must be a map
   that is used to convert one key to another before placing it in the filter,
   typically used to conver valid clojure keywords to keyword strings that aren't
   valid as clojure keywords, but are valid as ec2 model Filters.

   E.g. (make-ec2-filter :state :ready #{:state \"state.status\"})
        => #<Filter>(\"state.status\", \"ready\")
   The key-map can also specify other keywords as values, it doesn't have to be a string,
   though it's more efficient that way."
  [k v & [key-map]]
  (let [k (or (and key-map (get key-map k)) k)]
    (Filter. (cond (keyword? k) (name k)
                   (string? k) k
                   :else (throw (Exception.
                                 (str "key " k " of type " (type k)
                                      " cannot be converted to a Filter key."))))
             [(cond (keyword? v) (name v)
                    (integer? v) (int v)
                    :else v)])))

(defn- map->ec2-filters
  "Given a map convert keys and values to Filter elements,
   return a collection of ec2.mode.Filters
   for use with setFilters(Collection<Filter>) on some ec2 model request.
   If 'key-map' is specified, translate keys in 'm' before converting them to
   Filter keys."
  [m & [key-map]]
  {:pre [(map? m)]}
  (into '() (map (fn [e] (make-ec2-filter (key e) (val e) key-map)) (seq m))))


;;;
;;; EC2 - instance status
;;;

(def instance-state-code-map "Map of InstanceState codes to keywords"
  {0 :pending, 16 :running, 32 :shutting-down, 48 :terminated, 64 :stopping, 80 :stopped})
(def instance-statuses "Valid instance status values"
  #{:ok :impaired :initializing :insufficient-data :not-applicable})
(def instance-reachabilities "Valid instance reachability values"
  #{:passed :failed :initializing :insufficient-data})

(def describe-instance-status-filter-map
  "Map filter keys for describe-instance-status to valid Filter names for the request."
  {:az "availability-zone"
   :event-code "event.code"
   :event-description "event.description"
   :event-not-after "event.not-after"
   :event-not-before "event.not-before"
   :instance-state "instance-state-name"
   :instance-reachability "instance-status.reachability"
   :instance-status "instance-status.status"
   :system-reachability "system-status.reachability"
   :system-status "system-status.status"
   })
   
(defn describe-instance-status
  "Return a sequence of InstanceStatus objects for EC2 instances.
  :ids - instance ids (or collection thereof) to describe, default nil (all instances).
  :all - if true include status for instances in states other than running.
  :filters - map of attributes/values to filter on. Keys:
           :az - availability zone of the instance
           :event-code - instance-{reboot,retirement,stop}, system-{reboot,maintenance}
           :event-description - event description
           :event-not-after - latest end time for the scheduled event
           :event-not-before - earliest start time for the scheduled event
           :instance-state-code - key from instance-state-code-maap (e.g. 0)
           :instance-state - one of the values in instance-state-code-map (e.g. :pending)
           :instance-reachability - one of 'instance-reachabilities'
           :instance-status:  - one of 'instance-statuses'
           :system-reachability - one of 'instance-rechabilities'
           :system-status - one of 'instance-statuses'"
  [& {:keys [ids all filters]}]
  (let [request (DescribeInstanceStatusRequest.)]
    (if ids (.setInstanceIds request (listify-safe ids)))
    (if all (.setIncludeAllInstances request true))
    (if filters
      (.setFilters request (map->ec2-filters filters describe-instance-status-filter-map)))
    (let [result (.describeInstanceStatus (ec2) request)]
      (if (.getNextToken result)
        (println "*FINISH*: pagination for missing entries in DescribeInstanceStatus"))
      (.getInstanceStatuses result))))

(defn report-instance-status
  "Report details of InstanceStatus objects.
   If no instance-statuses are specified, retrieve them as with describe-instance-status."
  [& [instance-statuses]]
  (let [instance-statuses (or instance-statuses (describe-instance-status))]
    (doseq [status instance-statuses]
      (println (.getInstanceId status)
               (.getName (.getInstanceState status))
               (.getAvailabilityZone status))
      (doseq [event (.getEvents status)]
        (println "  Events:")
        (println "   " (.getCode event)
                 (.getDescription event)
                 "Not After:" (.getNotAfter event)
                 "Not Before:" (.getNotBefore event)))
      (let [i-status (.getInstanceStatus status)
            s-status (.getSystemStatus status)
            detail-fn (fn [details]
                        (doseq [detail details]
                          (println "   " (.getName detail) (.getStatus detail)
                                   "impaired since:" (str (.getImpairedSince detail)))))]
        (println "  Instance status: " (.getStatus i-status))
        (detail-fn (.getDetails i-status))
        (println "  System status: " (.getStatus s-status))
        (detail-fn (.getDetails s-status))))))

(defn report-problem-instances
  "Wrapper around report-instance-status + describe-instance-status and some filters
   to find instances we can't reach or that are otherwise known to have problems."
  []
  (let [instances
        (into #{}                       ;filters duplicates
              (concat (describe-instance-status :filters {:instance-reachability :failed})
                      (describe-instance-status :filters {:system-reachability :failed})
                      (describe-instance-status :filters {:instance-status :impaired})
                      (describe-instance-status :filters {:system-status :impaired})))]
    (report-instance-status instances)))


;;;
;;; EC2 - instance queries
;;;
(declare describe-instances)

(defmulti  instance-state
    "Retrieve instance state for an EC2 instance as a keyword, e.g. :running.
     Note that an instance-id will cause a refetch of state, while an Instance
     object merely decodes the state already in memory (which will not change
     across successfive calls)."
    class)
(defmethod instance-state String [instance-id]
  (instance-state (first (describe-instances :ids instance-id))))
(defmethod instance-state Instance [instance]
  (get instance-state-code-map (.getCode (.getState instance)) :unknown-state-code))

(defmulti  wait-for-instance-state
  "Wait for an instance to reach the designated instance state.

   Instance may be an instance or instance ID.
   State should be one of :running :terminated or :stopped
    (and not one of the transient states).

   Note that state is re-fetched for the instance call until the target
   state is reached.

   Optional keyword args include:
   :verbose - print a 'waiting for <id> to enter the <y> state' message with a dot
              every 5 seconds.
   Returns nil."
  (fn [& args] (class (first args))))
(defmethod wait-for-instance-state Instance [instance state & args]
  (wait-for-instance-state (.getInstanceId instance) state))
(defmethod wait-for-instance-state String [instance-id state & {:keys [verbose]}]
  {:pre [(get #{:running :terminated :stopped} state)]}
  (when verbose
    (let [initial-state (instance-state instance-id)]
      (if-not (= initial-state state)
        (println "Waiting for" initial-state "instance" instance-id "to enter the" state "state"))))
  (while (not= (instance-state instance-id) state)
    (Thread/sleep 5000)
    (if verbose
      (do (print ".") (flush))))
  (if verbose
    (println)))
  
(defmulti  instance-id
  "Retrieve the instance id of an instance (or, if the argument is already an ID, return the identity."
  class)
(defmethod instance-id String [instance-id] instance-id)
(defmethod instance-id Instance [instance] (.getInstanceId instance))

(defmulti  instance-public-dns-name
  "Retrieve the public dns name for an instance or instance id,
   return nil if there isn't one.  Note that this information isn't available at all
   until the instance is in the :running state, and maybe not even then for VPC instances."
  class)
(defmethod instance-public-dns-name String [instance-id]
  (instance-public-dns-name (first (describe-instances :ids instance-id))))
(defmethod instance-public-dns-name Instance [instance]
  (let [dns-name (.getPublicDnsName instance)]
    (and (> (count dns-name) 0)
         dns-name)))

(defmulti  instance-public-ip-address
  "Retrieve the public IP address for an instance or instance id,
   return nil if there isn't one."
  class)
(defmethod instance-public-ip-address String [instance-id]
  (instance-public-ip-address (first (describe-instances :ids instance-id))))
(defmethod instance-public-ip-address Instance [instance]
  (let [ip-address (.getPublicIpAddress instance)]
    (and (> (count ip-address) 0)
         ip-address)))

(defn instance-volume-ids
  "Return a collection of ebs volume IDs attached to an Instance object.
   Often called implicitly via:
   (report-instances :instances (describe-instances :tag-regex #\"(?i)created\")
                                :fields #{:VolumeIds})"
  [instance]
  (->> (.getBlockDeviceMappings instance)
       (map (fn [mapping] (.getEbs mapping)))
       (map (fn [dev] (.getVolumeId dev)))))

(defn instance-availability-zone
  "Return the availability zone of an Instance"
  [instance]
  (.getAvailabilityZone (.getPlacement instance)))

(defn describeInstancesResult->instances
  "Convert DescribeInsancesResult objects to a sequence of instances.
   The argument may be a singleton DescribeInstancesResult or a collection of them."
  [results]
  (->> (seqify results)
       flatten
       (map (fn [describeInstancesResult]
              (seq (.getReservations describeInstancesResult))))
       ;; Sometimes there are no reservations ina DescribeInstancesResult (get null)
       ;; E.g. on filtered requests.
       (filter identity)
       flatten
       (map (fn [reservation] (seq (.getInstances reservation))))
       flatten))

;; Some stupid report printing functions & macros
(defn- pu "print unquoted/friendly, ie. ~a" [x] (print x) (print " "))
(defn- pq "print quoted/readable, ie. ~s" [x] (pr x) (print " "))
(defmacro pif
  "print val using print-fn if test is true, avoid computing val more than once"
  [test val print-fn]
  `(if ~test
     (let [val# ~val]
       (~print-fn val#))))

;; *TBD*: might like to know what AutoScalingLaunchConfig was used to launch an instance, 
;; but this is only available via an DescribeAutoScalingInstancesResult.
;; *TBD*: List valid keywords for fields if an improper one is given, right now we silently ignore it.
;; *TBD*: Consider implicit merging of :instances and :instance-ids as we do in {start,stop,terminate}-instances.
;; and eliminate one or the other of those keywords.
;; *TBD*: consider DescribeInstanceStatus merging with this function, so we can report
;; unreachable systems, etc, on the instance report.
(defn report-instances 
  "Print a information about instances.
   The default is to print one line of information per instance, unless options
   are specified for other details.

   Options:
   :indent all lines with the indicated (minimum) number of leading spaces
           indentation desired (default zero).  note that secondary lines (if
           more than one line per instance is printed) are indented an
           additional indent-incr spaces.
   :indent-incr amount to additionally indent secondary data lines (for
                options where more than one line per instance is printed. Default 2.
   :data A DescribeInstancesResult object or collection of those objects to
         be reported upon.  If neither this nor :instances is specified,
         (describe-instances) is called to retrieve data.
   :instances An Instance collection of instances.  If neither this nor :data
              is speciied, (describe-instances is called to retrieve data.
              If both are specified, the resulting instances from each field are used
              (all together).  Note that you can turn instance IDs to instances
              via 'describe-instances'.
   :ids An instance ID or collection thereof, passed to 'describe-instances'.
   :region a region keyword from 'region-map', or :all, in which case
           iff :data is unspecified, data will be fetched from all regions.
           :region is ignored if :data is specified.
   :fields Set of fields (information) to display in addition to instance id.
           Defaults to: #{:ImageId :VpcId :SubnetId :PublicDnsName :KeyName :State :InstanceType :SecurityGroups :Tags}
           Additional fields include: :VolumeIds, :InstanceProfile, :LaunchTime, :StoreType
           :PrivateIpAddress :PrivateDnsName :PublicIpAddress.
   :include Set of additional fields to display, defaults to #{}
   :exclude Set of fields to exclude from the display, defaults to #{}.
   :split-after A field keyword, or collection of field keywords, after which a 'println' and indent
                will occur to break the report into multiple lines per instance.
                By default there is only one line per instance for easier output grepping.
                Rather pointless if you use the last field as a split field, unless you want a blank line
                between each instance' report.  JDT likes :InstanceType for this keyword.
   Note that presently you can't specify the order of fields."
  [& {:keys [data instances ids vpc-mode region indent indent-incr fields include exclude split-after]
      :or {indent *indent* indent-incr 2
           fields #{:ImageId :VpcId :SubnetId :PublicDnsName :KeyName :State :InstanceType :SecurityGroups :Tags}
           include #{} exclude #{} }}]
  {:pre [(set? include) (set? exclude) (set? fields)]}
  (let [instances1 (and data (describeInstancesResult->instances data))
        instances2 (and instances (seqify instances))
        instances2a (and ids (describe-instances :ids ids))
        instances3 (concat instances1 instances2 instances2a)
        instances4 (if (empty? instances3)
                       (describeInstancesResult->instances
                        (map #(.describeInstances (ec2 %))
                             (regions-for-key region)))
                       instances3)
        fields (difference (union fields include) exclude)
        split-after (into #{} (seqify split-after))
        sp (fn [x] (when (split-after x)
                     (println)
                     (do-indent(+ indent indent-incr))))     ;split if necessary
        xpr (fn [key val printfn]         ;print and maybe split, use 'pif' or similar?
              (when (get fields key)
                (printfn val)
                (sp key)))]
    (doseq [instance instances4]
      (do-indent indent)
      (pu (.getInstanceId instance))
      ;; Convert to pure iteration on fields and reflection call? 
      ;; Also note that xpr as function forces value valuation where as
      ;; xpr as macro could avoid evaluating all these reflective calls
      ;; even if we don't print them.
      (xpr :ImageId (.getImageId instance) pu)
      (xpr :VpcId (or (.getVpcId instance) "<noVpc>") pu)
      (xpr :SubnetId (or (.getSubnetId instance) "<noSubnet>") pu)
      (xpr :PublicDnsName (empty-string-alternative (.getPublicDnsName instance) "<noPublicDns>") pu)
      (xpr :PublicIpAddress (.getPublicIpAddress instance) pu)
      (xpr :PrivateDnsName (empty-string-alternative (.getPrivateDnsName instance) "<noPrivateDns>") pu)
      (xpr :PrivateIpAddress (.getPrivateIpAddress instance) pu)
      (xpr :KeyName (.getKeyName instance) pu)
      (xpr :State (.getName (.getState instance)) pu)
      (xpr :LaunchTime (str (.getLaunchTime instance)) pu)
      (xpr :InstanceType (.getInstanceType instance) pu)
      (xpr :StoreType (.getRootDeviceType instance) pu) ; "ebs" or "instance-store"
      (xpr :InstanceProfile
           (if-let [ip (.getIamInstanceProfile instance)]
             (.getArn ip)
             "<noInstanceProfile>")
           pu)
      (xpr :SecurityGroups (map #(.getGroupName %) (.getSecurityGroups instance)) pu)
      (xpr :Tags (squish-tags (.getTags instance)) pq)
      (xpr :VolumeIds (instance-volume-ids instance) pu)
      (println))))

(defn- tag-regex-find-fn 
  "Return a function of one argument that takes calls .getTags on the argument
   the result of re-find if (re-find regex <x>) is true for either the tag key
   or the tag value for any tag returned.  re-find is called on the key first, then the
   value, it is not called on the value if the key test returns a logically
   true value."
  [regex]
  {:pre [(instance? java.util.regex.Pattern regex)]}
  (fn [taggable]
    (some (fn [tag]
            (or (re-find regex (.getKey tag))
                (re-find regex (.getValue tag))))
          (seq (.getTags taggable)))))

;; *TODO*: note that Filter _values_ can have '*' (zero or more chars) and '?' (one or more chars), as per
;; http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Filtering.html#Filtering_Resources_CLI
;; Filter value matching is case sensitive (hence pretty limited, particularly since there's no disjunction).
;; Note: wildcard and baskslash chars must be escaped with backslashes.
;; *TBD*: Whether to change tag-regex behavior to re-match instead of re-find
;; *TBD*: need filters of some kind (pre or post) that match any interesting field,
;; not just tags. (userdata, description, instance name, sg names, etc)
(defn describe-instances
  "Retrieve zero or more Instances with various filters and regions applied.
   Returns a collection that can be fed as :data to 'report-instances', e.g.
   (report-instances :instances (describe-instances :tag-regex #\"(?i)created\"))
   Options:
   :region a region keyword from 'region-map', or :all to operate on all regions.
   :ids a string instance ID, or collection/sequence of same, specifying specific instances
        whose data should be retrieved.
   :tag-regex a regular expression (java.util.regex.Pattern) applied to tag names and
              values as a filter.  Instances lacking the regex will not be returned.
              Instances are only returned if the regex passes a 'find', not a
              'matches' operation. '(?i)' may be useful in your regex to ignore case.
              Note that tag regexes must filter tags after retrieval from amazon."
  [& {:keys [region tag-regex ids]}]
  (let [regions (regions-for-key region)
        fetch-fn (if ids
                   (if (> (count ids) 0)
                     (fn [region] (.describeInstances (ec2 region)
                                                      (doto (DescribeInstancesRequest.)
                                                        (.setInstanceIds (seqify ids)))))
                     (constantly nil))
                   (fn [region] (.describeInstances (ec2 region))))
        tag-regex-fn (if tag-regex (tag-regex-find-fn tag-regex) identity)]
    (->> (filter identity (map fetch-fn regions)) ;filter nils
         flatten
         (map (fn [descInsRes] (seq (.getReservations descInsRes))))
         flatten
         (map (fn [reservation] (seq (.getInstances reservation))))
         flatten
         (filter tag-regex-fn)
         )))

;; *TODO*: move to jdt.core
(defn exception-retry
  "Call function f with exception handler fe.  If an
   exception is thrown by f, call fe on the exception, and then call f again
   if the result of calling fe is logically true or unless fe throws.

   If f completes execution without throwing we return the return value of f.
   If f throws and fe returns logical false, return nil.

   f must not return a function, this is prohibited and will result in an exception.

   This function is a non-recursive workaround for situations for where
   you want to recurse in a catch/finally statement (i.e. retry a try block in the face of
   exceptions thrown from the try block).  You can't use 'recur' in catch/finally.
   This works around it.

   E.g. (loop [] (try (f) (catch Exception e (recur)))) ; WILL NOT WORK
   but  (exception-retry f (fn [] true)) ; WILL WORK

   In practice you want fe to examine the exception raised
   and probably sleep before returning to try f again.  Maybe print a message
   that this a retry is happening."
  [f fe]
  (let [tryfn
        (fn [] (try (let [result (f)]
                      (assert (not (fn? result)))
                      result)
                    (catch Exception e (if (fe e) f nil))))]
    (trampoline tryfn)))

(defn run-instances
  "Start new instances from a specificed AMI.  *FINISH*: this is a work in progress.
   Returns a sequence of instance ids created.
   
   Arguments:
   ami-id  The image id to use.
   :keyname the name of the key pair to use.
   :type the instance type to use ({m1,m3,c1}.{small,medium,[x]large}, etc)
         *TODO* online help to list options for this please.
   :group-ids security group id or collection of ids to use for secrity groups
   :group-names security group name or collection of names to use for secrity groups
                (ec2-classic, default-vpc only, can use with group-ids as well)
   :min    minimum number of instances to run
   :max    maximum number of instances to run
   :private-ip-address A specific IP address in dotted IPV4 notation to be assigned to the instance
           (vpc instances only).
   :subnet A specific subnet ID for instances started in a VPC.
   :retry-if If specified is a string corresponding to an one of error codes as documented
             in http://docs.aws.amazon.com/AWSEC2/latest/APIReference/api-error-codes.html.
             If an AmazonServiceException is thrown with code 400 and
             AWS Error Code matching the parameter, we will retry the run-instances value.
             Known useful codes: 'InvalidIPAddress.InUse' if you're retrying a specific
             ip address assignment to a recently disassociated EIP or private IP address in a VPC.
   :wait   true if this function should not exit until all instances have started.
           Note that they instances may not yet be responsive just because they're 'running'
           and have a DNS address.  YMMV.
   :region a region keyword from 'region-map' to override *region*."
  [ami-id & {:keys [keyname type group-ids group-names min max private-ip-address subnet
                    retry-if wait region]
             :or {region *region* type "t1.micro" min 1 max 1}}]
  {:pre [(not (= region :all))]}
  (let [min (int min)
        max (int max)
        request (RunInstancesRequest. ami-id min max)]
    (.setInstanceType request type)
    (if keyname (.setKeyName request keyname))
    (if group-ids (.setSecurityGroupIds request (listify-safe group-ids)))
    (if group-names (.setSecurityGroups request (listify-safe group-names)))
    (if private-ip-address (.setPrivateIpAddress request private-ip-address))
    (if subnet (.setSubnetId request subnet))
    (let [run-fn (fn [] (->> (.runInstances (ec2 region) request)
                             (.getReservation)))
          handler-fn (fn [e]   ; return true if we should retry on exception e
                       (if (and retry-if
                                (instance? AmazonServiceException e)
                                (= (.getStatusCode e) 400)
                                (= (.getErrorCode e) retry-if))
                         (do (println e)
                             (println "Retrying the run-instances operation again after a 15 second sleep.")
                             (Thread/sleep 15000)
                             true)      ;true => please retry the run-fn in exception-retry
                         (throw e)))
          reservation (exception-retry run-fn handler-fn)
          instances (seq (.getInstances reservation))
          instance-ids (map #(.getInstanceId %) instances)
          user-name (iam-get-user-name)]
      (cl-format true "Instance~p created: ~s~%" (count instances) instance-ids)
      (doseq [id instance-ids]
        (create-tags id {:created-by user-name})) ; *TBD*: let caller pass additional tags
      (if wait
        (doseq [id instance-ids]
          (wait-for-instance-state id :running :verbose true)))
      instance-ids)))

(defn start-instances
  "Start one or more stopped instances.
   ids     an  instance or instance ID, or collection/sequence of same,
           specifying specific instances to be started.
   :wait   true if this function should not exit until all instances have started.
           Note that they instances may not yet be responsive just because they're 'running'
           and have a DNS address.  YMMV.
   :region a region keyword from 'region-map' to override *region*."
  [ids & {:keys [region wait]
          :or {region *region*}}]
  {:pre [(not (= region :all))]}
  (let [ids (map instance-id (listify-safe ids))]
    (doseq [instanceStateChange 
            (->> (.startInstances (ec2 region) (StartInstancesRequest. ids))
                 (.getStartingInstances))]
      (println (.getInstanceId instanceStateChange)
               (.getName (.getPreviousState instanceStateChange))
               "=>"
               (.getName (.getCurrentState instanceStateChange))))
    (if wait
      (doseq [id ids]
        (wait-for-instance-state id :running :verbose true)))))


(defn stop-instances
  "Stop one or more instances, waiting if requested.  Return value unspecified.
   ids     an  instance or instance ID, or collection/sequence of same,
           specifying specific instances to be stopped.
   :wait   true if this function should not exit until all instances have stopped.
   :region a region keyword from 'region-map' to override *region*."
  [ids & {:keys [region wait]
          :or {region *region*}}]
  {:pre [(not (= region :all))]}
  (let [ids (map instance-id (listify-safe ids))]
    (doseq [instanceStateChange 
            (->> (.stopInstances (ec2 region) (StopInstancesRequest. ids))
                 (.getStoppingInstances))]
      (println (.getInstanceId instanceStateChange)
               (.getName (.getPreviousState instanceStateChange))
               "=>"
               (.getName (.getCurrentState instanceStateChange))))
    (if wait
      (doseq [id ids]
        (wait-for-instance-state id :stopped :verbose true)))))

(defn terminate-instances
  "Terminate one or more instances.  Return value unspecified.
   ids     an  instance or instance ID, or collection/sequence of same,
           specifying specific instances to be deleted.
   :region a region keyword from 'region-map' to override *region*.
   :wait   if true, wait until the instance reaches state :terminated.
   :force  if true, ensure that we can disable the instance via termination APIs
           (i.e cancel 'DisableApiTermination' status)."
  [ids & {:keys [region force wait]
          :or {region *region*}}]
  {:pre [(not (= region :all))]}
  (let [ids (map instance-id (listify-safe ids))]
    (if force
      (doseq [id ids]
        (.modifyInstanceAttribute (ec2 region)
         (doto (ModifyInstanceAttributeRequest.
                id InstanceAttributeName/DisableApiTermination)
           (.setValue "false")))))
    (doseq [instanceStateChange 
            (->> (.terminateInstances (ec2 region) (TerminateInstancesRequest. ids))
                 (.getTerminatingInstances))]
      (println (.getInstanceId instanceStateChange)
               (.getName (.getPreviousState instanceStateChange))
               "=>"
               (.getName (.getCurrentState instanceStateChange))))
    (if wait
      (doseq [id ids]
        (wait-for-instance-state id :terminated :verbose true)))))

(defn instance-console-output
  "Retrieve the console output of an instance given an instance ID"
  [instance-id]
  (->> (.getConsoleOutput (ec2) (GetConsoleOutputRequest. instance-id))
       (.getDecodedOutput)))

;;;
;;; EC2 Security groups
;;; 

(defn report-sgs
  "Print a one line summary (unless options specify otherwise)
   of security groups for one or more DescribeSecurityGroupsResults instances."
;; *TODO*: options for region(? - and including :all) and and for :ingress :egress
;; :region may be a standard option for all things that roll an ec2
;; maybe also some :regex filtering options, though if we just return tuples
;; caller can do that other ways
  ([] (report-sgs [(.describeSecurityGroups (ec2))]))
  ([describeSecurityGroupsResults] (report-sgs describeSecurityGroupsResults {}))
  ([describeSecurityGroupsResults opts]
     (doseq [describeSecurityGroupsResult describeSecurityGroupsResults]
       (doseq [sg (.getSecurityGroups describeSecurityGroupsResult)]
         (cl-format true "~a ~a ~a ~a ~a ~s~%"
                    (.getGroupId sg)
                    (.getGroupName sg)
                    (.getOwnerId sg)
                    (or (.getVpcId sg) "<novpc>")
                    (squish-tags (.getTags sg))
                    (.getDescription sg))))))


;;;
;;; EC2 VPC
;;;

(defn print-ip-permission [ip-permission]
  (println "from port" (.getFromPort ip-permission)
           "protocol" (.getIpProtocol ip-permission)
           "ranges" (seq (.getIpRanges ip-permission))
           "to port" (.getToPort ip-permission)
           "id grps" (seq (.getUserIdGroupPairs ip-permission))))

(defn report-vpc-sg-permissions
  []
  (let [ec2 (ec2)
        describeVpcResult (.describeVpcs ec2)]
    (doseq [vpc (.getVpcs describeVpcResult)]
      (println (.getVpcId vpc)
               (.getCidrBlock vpc)
               (.getState vpc)
               (str "dflt=" (.isDefault vpc))
               (squish-tags (.getTags vpc)))
      (let [describeSecurityGroupsResult (.describeSecurityGroups
                                          ec2 (doto (DescribeSecurityGroupsRequest.)
                                                (.setFilters
                                                 [(Filter. "vpc-id" [(.getVpcId vpc)])])))]
        (doseq [sg (.getSecurityGroups describeSecurityGroupsResult)]
          (do-indent 2)
          (println (.getGroupId sg)
                   (.getGroupName sg)
                   (.getDescription sg)
                   (squish-tags (.getTags sg)))
          (when-let [perms (seq (.getIpPermissions sg))]
            (println "    Ingress:")
            (doseq [ipPermission perms]
              (do-indent 6)
              (print-ip-permission ipPermission)))
          (when-let [perms (seq (.getIpPermissionsEgress sg))]
            (println "    Egress:")
            (doseq [ipPermission perms]
              (do-indent 6)
              (print-ip-permission ipPermission))))))))
                     
(defn vpc-instances
  "Return a (possibly empty) sequence of Instances in the specified VPC."
  [vpc-id]
  (describeInstancesResult->instances 
   (.describeInstances
    (ec2) (doto (DescribeInstancesRequest.)
            (.setFilters [(Filter. "vpc-id" [vpc-id])])))))

(defn report-vpc-instances
  "Print summary of instances in vpcs, grouped by vpc."
  []
  (let [ec2 (ec2)
        describeVpcResult (.describeVpcs ec2)]
    (doseq [vpc (.getVpcs describeVpcResult)]
      (println)
      (println (.getVpcId vpc)
               (.getCidrBlock vpc)
               (.getState vpc)
               (str "dflt=" (.isDefault vpc))
               (squish-tags (.getTags vpc)))
      ;; Instances in the vpc
      (if-let [instances (not-empty? (vpc-instances (.getVpcId vpc)))]
        (binding [*indent* (+ *indent* 4)]
          (report-instances :instances instances
                            :exclude #{:VpcId} :include #{:PrivateIpAddress}))))))

(defn vpc-instance-at-address
  "Return the Instance of an existing EC2 instance assigned the indicated address
   in the indicated VPC, or nil if there is no such instance.

   vpc-id should be a string id similar to 'vpc-b60efed3'.
   ip-address should be a dotted ip V4 address as a string.

   Note that the instance could be in a number of non-terminated states.  We
   don't return an instance if for terminated (but information-available)
   instances.

   Right now this is overly general and could theoretically (but not in practice)
   return a match because a public ip address matched a private ip address, etc.
   So we ought to specify which type of address we're trying to match, but for now
   we don't."
  [vpc-id ip-address]
  {:pre [(string? ip-address)]}
  ;; Terminated instances won't have ip addresses, no need
  ;; for further filtering.
  (find-if (fn [instance]
             (or (= (.getPrivateIpAddress instance) ip-address)
                 (= (.getPublicIpAddress instance) ip-address)))
           (vpc-instances vpc-id)))


;;;
;;; Auto-scaling stuff
;;;

;;; NOTE: while an auto-scaling-group has one currently associated launch config,
;;; it may have instances running associated with "old" launch configs that are not longer the current one for the
;;; ASG (look at the ASG instances, and the launch configs of those instances, and you'll see the launch configs that aren't the
;;; current ASG LC.)

(defn ^AmazonAutoScalingClient asc
  "Return an AmazonAutoScalingCLient instance ready for calls for a single (optional) region.
   'region' is a keyword defaulting to *region*."
  ([] (asc *region*))
  ([region]
     (let [asc (AmazonAutoScalingClient. (make-aws-creds))
           region (if (instance? Region region) region (get-valid region-map region))]
       (.setRegion asc region)
       asc)))

(defn describe-auto-scaling-groups []
  "Return a list of AutoScalingGroup instances.  *TBD* Not sure what to do with tokens. and possibly incomplete results."
  (.getAutoScalingGroups (.describeAutoScalingGroups (asc))))
  
(defn report-auto-scaling-groups []
  "Print one line summary of AutoScalingGroup instances.
   *TODO*: There's a lot of useful data here we don't report on right now."
  (doseq [group (describe-auto-scaling-groups)]
    (println (.getAutoScalingGroupName group)
             "LC:" (.getLaunchConfigurationName group)
             "LBs:" (seq (.getLoadBalancerNames group))
             "VpcZid:" (.getVPCZoneIdentifier group)
             "Status:" (.getStatus group)
             (map #(.getInstanceId %) (.getInstances group))
             "Susp:" (map #(.getProcessName %) (.getSuspendedProcesses group))
             (squish-tags (.getTags group)))))

(defn dump-auto-scaling-groups []
  "Print a hierarchical report of auto-scaling groups, their instances, launch configurations, etc."
  ;; Get a map of instance->launch config data
  (let [autoScalingInstanceDetails (.getAutoScalingInstances (.describeAutoScalingInstances (asc)))
        asgroupnames->lc-names
        (apply (partial merge-with union)
               (map (fn [asid] {(.getAutoScalingGroupName asid) #{(.getLaunchConfigurationName asid)}})
                    autoScalingInstanceDetails))
        lc-names->as-group-names
        (apply (partial merge-with union)
               (map (fn [asid] {(.getLaunchConfigurationName asid) #{(.getAutoScalingGroupName asid)}})
                    autoScalingInstanceDetails))
        lc-names->instance-ids
        (apply (partial merge-with union)
               (map (fn [asid] {(.getLaunchConfigurationName asid) #{(.getInstanceId asid)}})
                    autoScalingInstanceDetails))
        instance-ids->lc-names
        (apply (partial merge-with union)
               (map (fn [asid] {(.getInstanceId asid) #{(.getLaunchConfigurationName asid)}})
                    autoScalingInstanceDetails))
        ri (fn [ids]
             (report-instances :ids ids :indent 4 :include #{:PrivateIpAddress}
                               :split-after :InstanceType))
        auto-scaling-groups (describe-auto-scaling-groups)]
    (doseq [group auto-scaling-groups]
      (let [as-group-name (.getAutoScalingGroupName group)]
        (println "AutoScalingGroup:" as-group-name)
        (doseq [launch-config-name (get asgroupnames->lc-names as-group-name)]
          (print "  Launch Configuration:" launch-config-name)
          (if (= launch-config-name (.getLaunchConfigurationName group))
            (println "  [Active]")
            (println "  [INACTIVE]"))
          ;; Intersect LC->instances with ASG->instances in case they don't map 1:1
          (ri (intersection
               (into #{} (get lc-names->instance-ids launch-config-name))
               (into #{} (map #(.getInstanceId %) (.getInstances group))))))
        ;; Paranoid: check for asg reported instances not in above launch configurations
        (let [asg-instances (.getInstances group)
              instance-ids (map #(.getInstanceId %) asg-instances)
              ids-without-lc-key (filter (fn [id] (not (get instance-ids->lc-names id)))
                                         instance-ids)]
          (when (not-empty? ids-without-lc-key)
            (println)
            (println "  ** AutoScalingGroup instances not in the above Launch Configurations. **")
            (ri ids-without-lc-key)))))

    ;; Print out any launch configs not mentioned as part of auto scaling groups above
    (let [all-launch-configurations (.getLaunchConfigurations (.describeLaunchConfigurations (asc)))
          lc-names-not-in-as-groups
          (filter (fn [lcname] (not (get lc-names->as-group-names lcname)))
                  (map #(.getLaunchConfigurationName %) all-launch-configurations))]
      (unless (empty? lc-names-not-in-as-groups)
              (println)
              ;; Unless the LC was created after we queried the ASG's above, a timing hole
              (println "** Unused Launch Configurations **")
              (let [lc-name->launch-configurations
                    ;; This is in case there are multiple orphaned launch configurations with the same name,
                    ;; hopefully that's not possible, but only Amazon knows.
                    (apply (partial merge-with concat)
                           (map (fn [lc] {(.getLaunchConfigurationName lc) [lc]})
                                all-launch-configurations))]
                (doseq [lc-name lc-names-not-in-as-groups]
                  (doseq [lc (get lc-name->launch-configurations lc-name)]
                    (println " " lc-name " created:" (str (.getCreatedTime lc)))
                    (println "   " (.getLaunchConfigurationARN lc))
                    (println "    ImageId:" (.getImageId lc) " HasPublicIP:" (.getAssociatePublicIpAddress lc))
                    (println "    InstanceProfile:" (.getIamInstanceProfile lc) " KeyPairName:" (.getKeyName lc)
                             " InstanceType:" (.getInstanceType lc))
                    (println "    SecurityGroups:" (seq (.getSecurityGroups lc))))))))))


                     
;;;
;;; EC2 Images
;;;

(defn image-state
  "Fetch image state for an image id.
   Returns one of :available, :deregistered, or :pending."
  [image-id]
  (->> (.describeImages
        (ec2) 
        (doto (DescribeImagesRequest.)
          (.setImageIds (list image-id))))
       .getImages
       first
       .getState
       keyword))

(defmulti  wait-for-image-state
  "Wait for an image (AMI) to reach the designated state.

   Image may be an Image or Image ID.
   State should be one of :available or :deregistered.

   Note that state is re-fetched for the image call until the target
   state is reached, this doesn't just check image state on a previously fetched Image.

   Optional keyword args include:
   :verbose - print a 'waiting for <id> to enter the <y> state' message with a dot
              every 5 seconds.
   Returns nil."
  (fn [& args] (class (first args))))
(defmethod wait-for-image-state Image [image state & args]
  (wait-for-image-state (.getImageId image) state))
(defmethod wait-for-image-state String [image-id state & {:keys [verbose]}]
  {:pre [(get #{:available :deregistered} state)]}
  (when verbose
    (let [initial-state (image-state image-id)]
      (if-not (= initial-state state)
        (println "Waiting for" initial-state "image" image-id
                 "to enter the" state "state"))))
  (while (not= (image-state image-id) state)
    (Thread/sleep 5000)
    (if verbose
      (do (print ".") (flush))))
  (if verbose
    (println)))


;; Early Testing
#_
(defn ec2-describe-all-images
  []
  (let [ec2 (ec2)]
    (let [describe-images-result (.describeImages ec2)
          images (.getImages describe-images-result)]
      ;; For 27,900 images on bis account
      ;; This took 70 seconds.
      (println (count images) "images")
      ;; This took 74 secs.
      #_ (printlines (map #(.getImageId %) images)) ; /tmp/native-images-no-str
      ;; This took 223 secs.
      #_ (doseq [image images] (println (str image))) ; /tmp/native-images
      )))

;; Early testing
#_
(defn ec2-describe-some-images
  []
  (let [ec2 (ec2)
        request (DescribeImagesRequest.)]
    ;; Of 27,900+ BIS images
    (doto request                       ;set{ExecutableUsers,Filters,ImageIds,Owners}
      ;; 360 images for executable users "self"
      (.setExecutableUsers ["self"]) ; account, self, all
      ;; 7 images for owner self
      ;;(.setOwners ["self"]) ; account, amazon, aws-marketplace, self, all
      )
    (let [describe-images-result (.describeImages ec2 request)
          images (.getImages describe-images-result)]
      ;; This took 70 seconds.
      (println (count images) "images")
      ;; This took 74 secs.
      #_ (printlines (map #(.getImageId %) images)) ; /tmp/native-images-no-str
      ;; This took 223 secs.
      #_ (doseq [image images] (println (str image))) ; /tmp/native-images
      )))
          
(defn keys-n-stuff->strings [seq]
  (map (fn [thing]
         (cond (keyword? thing) (name thing)
               (string? thing) thing
               :else (str thing)))
       seq))

(defn describe-images
  "Return a list of Image objects.  Beware calling this without IDs or other filters.
   Options:
   :ids - an image id or seq of image ids.
   :owned-by - Can be one of the following, or a list of the following:
               :self or \"self\", return only images owned by self, where self is the sender of the request,
               :all or \"all\",
               a string or number specifying an aws account ID.
   :exec-by - Return only images executable by the value of this arg because of explicit launch permissions
              Can be one of the following, or a list of the following:
              :self or \"self\", where self is the sender of the request,
              :all or \"all\",
              or a string or numeric AWS account ID.
   :filters - map of attributes/values to filter on.  Key (k/v can be keyword, string, or other for vals).
      architecture - The image architecture (i386 | x86_64).
      block-device-mapping.delete-on-termination - A Boolean value that indicates whether the Amazon EBS volume is deleted on instance termination.
      block-device-mapping.device-name - The device name for the Amazon EBS volume (for example, /dev/sdh).
      block-device-mapping.snapshot-id - The ID of the snapshot used for the Amazon EBS volume.
      block-device-mapping.volume-size - The volume size of the Amazon EBS volume, in GiB.
      block-device-mapping.volume-type - The volume type of the Amazon EBS volume (standard | io1).
      description - The description of the image (provided during image creation).
      hypervisor - The hypervisor type (ovm | xen).
      image-id - The ID of the image.
      image-type - The image type (machine | kernel | ramdisk).
      is-public - A Boolean that indicates whether the image is public.
      kernel-id - The kernel ID.
      manifest-location - The location of the image manifest.
      name - The name of the AMI (provided during image creation).
      owner-alias - The AWS account alias (for example, amazon).
      owner-id - The AWS account ID of the image owner.
      platform - The platform. To only list Windows-based AMIs, use windows.
      product-code - The product code.
      product-code.type - The type of the product code (devpay | marketplace).
      ramdisk-id - The RAM disk ID.
      root-device-name - The name of the root device volume (for example, /dev/sda1).
      root-device-type - The type of the root device volume (ebs | instance-store).
      state - The state of the image (available | pending | failed).
      state-reason-code - The reason code for the state change.
      state-reason-message - The message for the state change.
      tag:key=value - The key/value combination of a tag assigned to the resource.
      tag-key - The key of a tag assigned to the resource.
      tag-value - The value of a tag assigned to the resource.
      virtualization-type - The virtualization type (paravirtual | hvm). "
  [& {:keys [ids owned-by exec-by filters]}]
  (let [request (DescribeImagesRequest.)]
    (if ids (.setImageIds request (listify-safe ids)))
    (if owned-by (.setOwners request (keys-n-stuff->strings (listify-safe owned-by))))
    (if exec-by (.setExecutableUsers request (keys-n-stuff->strings (listify-safe exec-by))))
    (if filters (.setFilters request (map->ec2-filters filters)))
    (seq (.getImages (.describeImages (ec2) request)))))

(defn report-images
  "Report on zero or more Image instances,
   fetch them if none are specified as with 'describe-images'.

   CAUTION: without filters, this call returns a lot of data and can take a long time.
   :owned-by :self and/or :exec-by :self is recommended to do some basic filtering if
   you don't specify specific images/ids.

   :images - an Image or collection of Image instances, optional.

   :fields - set of fields (information) to display in addition to image id.
             Defaults to: #{:ImageLocation :Architecture :ImageType :StoreType
                      :Platform :State :Description :Tags}
             Additional fields include: :Name, :Owner :Devices
   :include Set of additional fields to display, defaults to #{}
   :exclude Set of fields to exclude from the display, defaults to #{}.

   The following filtering keywords are as documented in 'describe-images':
   :ids, :owned-by, :exec-by.

   Returns nil."
  [& {:keys [images ids owned-by exec-by fields include exclude]
      :or {fields #{:ImageLocation :Architecture :ImageType :StoreType :Platform :State
                    :Description :Tags}
           include #{} exclude #{}}}]
  {:pre [(set? include) (set? exclude) (set? fields)]}
   
  (let [fetched-images (if (or (not images) ids)
                         (describe-images :ids ids :owned-by owned-by :exec-by exec-by))
        images (concat (listify-safe images) fetched-images)
        fields (difference (union fields include) exclude)]
    (doseq [image images]
      (pu (.getImageId image))
      ;; image location contains account (owner id) and name
      ;; making Name and OwnerId info redundant ... ?  Seems like it
      (pif (:ImageLocation fields) (.getImageLocation image) pq)
      (pif (:Name fields) (.getName image) pq)
      (pif (:Owner fields) (.getOwnerId image) pu)
      (pif (:Architecture fields) (.getArchitecture image) pu)
      (pif (:ImageType fields) (.getImageType image) pu)
      (pif (:Platform fields) 
           (empty-string-alternative (.getPlatform image) "sane") pu)
      ;; Note that .getRootDeviceName seems to be nil for instance stores
      (pif (:StoreType fields) (.getRootDeviceType image) pu) ; "ebs" or "instance-store"
      (pif (:State fields) (.getState image) pu)
      (pif (:Description fields) (.getDescription image) pq)
      (pif (:Tags fields) (squish-tags (.getTags image)) pq)
      (println)
      (when (:Devices fields)
        (doseq [blockDeviceMapping (.getBlockDeviceMappings image)]
          (print " " (.getDeviceName blockDeviceMapping)
                 (.getVirtualName blockDeviceMapping)
                 (.getNoDevice blockDeviceMapping))
          (if-let [ebsBlockDevice (.getEbs blockDeviceMapping)] ; m/b null
            (do
              (print " ")
              (println (.getSnapshotId ebsBlockDevice)
                       (.getVolumeType ebsBlockDevice)
                       (.getVolumeSize ebsBlockDevice)
                       (.getIops ebsBlockDevice)
                       (.getDeleteOnTermination ebsBlockDevice)))
            (println)))))))
      

(defn create-image
  "Create an EBS backed AMI from a running or stopped EBS-backed instance.
   Name is 3-128 alphanumeric characters and any of [-()./_].
   Returns the resulting image-id.
   Options:
   :quiet     - if true, do not print the resulting image ID to *out*.
   :no-reboot - if true do not stop and reboot the instance. By default
                instances are stopped for the image creation, then restarted.
                TBD: What happens if the instance is already stopped?  Is it restarted?
                I usually specify :no-reboot true on a stopped instance to be sure.
   :description - a description of the instance."
  [instance-id name
   & {:keys [description no-reboot quiet]}]
  (let [request (CreateImageRequest. instance-id name)]
    (if no-reboot (.setNoReboot request true))
    (if description (.setDescription request description))
    (let [result (.createImage (ec2) request)]
      (unless quiet (println "Image created is" (.getImageId result)))
      (.getImageId result))))

(defn image-add-launch-permission
  "Add accounts to an image' launch permissions.  Returns nil.
   Accounts should be AWS account numbers (as strings or numbers).
   This function is a currently a shortcut bandaid for a more
   flexible interface to the modifyImageAttribute API."
  [image-id & accounts]
  {:pre [(not (empty? accounts)) (string? image-id)]}
  ;; See "DescribeImageAttributeRequest" docs for valid attributes, presently
  ;; description, kernel, ramdisk, launchPermission, productCodes, blockDeviceMapping
  (let [request (ModifyImageAttributeRequest.)
        launch-mods (LaunchPermissionModifications.)]
    (doto launch-mods
      (.setAdd (map (fn [account]
                      (doto (LaunchPermission.)
                        (.setUserId (str account))))
                    accounts)))
    (doto request
      (.setImageId image-id)
      (.setLaunchPermission launch-mods))
    (.modifyImageAttribute (ec2) request)))

;; *TBD* How does one delete an instance store AMI?
;; Answer here: http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/deregister-ami.html
;; (Good link to have for delete-image logic, fyi).
;; See also: https://aws.amazon.com/articles/Amazon-EC2/637
;; Note that multiple AMIs can be registered from a single bundle in S3.
;; In short: deregister, then  deleteBundle.  *TODO*
;; *HELP*: There is no deleteBundle API or ec2-delete-bundle operation as referenced in the page.  Hmmm
;; (may be under "AMI tools", not the EC2 CLI tools).  Or it's basically just S3 file deletion.
;; Ruby code. Gets list of files to delete from the manifest file, then deletes them.
;;
;; *TODO*: there's some additional smarts we can put in here below (things we don't deal
;; with, see function code).
;;
;; Also, it would be nice to warn and require a :force if the image to be deleted
;; is associated with EC2 instances on the account (running or not).
(defn delete-image
  "To delete an image, you need to deregister the image and delete the snapshot
   behind it. The snapshot is found in the BlockDeviceMappings for the image.
   This function provides that capability.
   *TODO*: Doesn't presently support instance-stores, needs a deleteBundle for those."
  [image-id]
  {:pre [image-id]}
  (let [images (describe-images :ids image-id)]
    (if (empty? images)
      (throw (Exception. (str "Image " image-id " does not appear to exist"))))
    (let [image (first images)
          blockDeviceMappings (.getBlockDeviceMappings image)]
      (if (empty? blockDeviceMappings)
        (throw (Exception. (str "Image " image-id " does not appear to have block device mappings."
                                " I am unsure of how to delete it."))))
      (let [ebsBlockDevices (filter identity (map #(.getEbs %) blockDeviceMappings))]
        (if (> (count ebsBlockDevices) 1)
          (throw (Exception. (str "Image " image-id " has more than one EBS block device mapping."
                                  " I don't deal with that right now, perhaps I should report on them and ignore them.  *TBD*"))))
        (if (= (count ebsBlockDevices) 0)
          (throw (Exception. (str "Image " image-id " has no EBS block device mappings"
                                  " I don't know how to delete such an image."))))
        (let [snapshot-id (.getSnapshotId (first ebsBlockDevices))]
          (println)
          (println "The following image will be deregistered, and the associated EBS snapshot deleted.")
          (report-images :images images :include #{:Devices})
          (.deregisterImage (ec2) (DeregisterImageRequest. image-id))
          (println "... image" image-id "deregistered")
          (.deleteSnapshot (ec2) (DeleteSnapshotRequest. snapshot-id))
          (println "... snapshot" snapshot-id "deleted")
          (println "Image deletion complete."))))))

(defn image-exists?
  "Return true if the specified security image ID exists, false if it does not."
  [image-id]
  ;; Throws if the image ID does not exist.
  (try 
    (let [result (describe-images :ids image-id)]
      (= (count result) 1))
    (catch Exception e false)))



;;;
;;; ELB
;;;

(defn ^AmazonElasticLoadBalancingClient elb
  "Return an AmazonElasticLoadBalancingClient ready for calls for a single (optional) region.
  'region' is a keyword defaulting to *region*."
  ([] (elb *region*))
  ([region]
     (let [elb (AmazonElasticLoadBalancingClient. (make-aws-creds))
           region (if (instance? Region region) region (get-valid region-map region))]
       (.setRegion elb region)
       elb)))

(defn describe-elbs
  "Return LoadBalancerDescription objects for ELB's.  If one or more names are specified, describe only those ELB's."
  [& elb-names]
  (.getLoadBalancerDescriptions
   (if elb-names
     (.describeLoadBalancers (elb) (DescribeLoadBalancersRequest. elb-names))
     (.describeLoadBalancers (elb)))))

(defn report-elbs
  "Print information about elastic load balancers.  Returns nil.
   :descs -if specified, one or a collection of LoadBalancerDescription objects as if from 'describe-elbs'.
   :names -if specified, one or a colelction of ELB names, passed to 'describe-elbs'.
           If neither :names nor :descs is specified, we call (describe-elbs) for descriptions.
   :fields - A set that defaults to the following:
           #{:Name :DnsName :Vpc :Scheme :Subnets :Sgs :SourceSg}
           and may also include: :HostedZoneName :HostedZoneId :Azs :Ctime :Backends :Instances :Listeners :Policies.
   :include - A set of additional fields to include as described with :fields.
   :exclude - A set of fields to exclude as described with :fields."
  [& {:keys [descs names fields include exclude]
      :or {fields #{:Name :Vpc :DnsName :Scheme :Subnets :Sgs :SourceSg}
           include #{} exclude #{}}}]
  {:pre [(set? include) (set? exclude) (set? fields)]}
  (let [names (listify-safe names)
        descs (listify-safe descs)
        descs (or (not-empty?
                   (concat (and names (apply describe-elbs names)) descs))
                  (describe-elbs))
        fields (difference (union fields include) exclude)]
    (doseq [desc descs]
      (pq (.getLoadBalancerName desc))
      (pif (:Vpc fields) (empty-string-alternative (.getVPCId desc) "<noVpc>") pu)
      (pif (:DnsName fields) (.getDNSName desc) pu)
      ;; Note that the zone name is often the same as dns name.
      (pif (:HostedZoneName fields) (.getCanonicalHostedZoneName desc) pq)
      (pif (:HostedZoneId fields) (.getCanonicalHostedZoneNameID desc) pu)
      (pif (:Scheme fields) (.getScheme desc) pu)
      (pif (:Azs fields) (seq (.getAvailabilityZones desc)) pu)
      (pif (:Subnets fields) (or (seq (.getSubnets desc)) "<noSubnets>") pu)
      (pif (:Sgs fields) (or (seq (.getSecurityGroups desc)) "<noSGs>") pu)
      (pif (:SourceSg fields) (.getGroupName (.getSourceSecurityGroup desc)) pu)
      (pif (:Ctime fields) (str (.getCreatedTime desc)) pu)
      (println)
      (when (:Backends fields)
        (doseq [bsd (seq (.getBackendServerDescriptions desc))]
          (cl-format true "~2@TBackend Server: Port ~d, Policy Names: ~s~%"
                     (.getInstancePort bsd) (.getPolicyNames bsd))))
      (when (:Listeners fields)
        (doseq [listener (map #(.getListener %) (.getListenerDescriptions desc))]
          (cl-format true "~2@TListener: Instance Port ~d, Instance Protocol ~a, ELB Port ~d, ELB Protocl ~a, SSL Cert: ~a~%"
                     (.getInstancePort listener)
                     (.getInstanceProtocol listener)
                     (.getLoadBalancerPort listener)
                     (.getProtocol listener)
                     (.getSSLCertificateId listener))))
      (when (:Policies fields)
        ;; Not sure this is working...
        (let [policies (.getPolicies desc)]
          (cl-format true "~2@TAppCookieStickinessPolicies:~%~{~4@T~s~^~%~}"
                     (map (fn [p] [(.getCookieName p) (.getPolicyName p)]) (.getAppCookieStickinessPolicies policies)))
          (cl-format true "~2@TLBCookieStickinessPolicies:~%~{~4@T~s~^~%~}"
                     (map #(.getPolicyName %) (.getLBCookieStickinessPolicies policies)))
          (cl-format true "~2@TOther Policies: ~s~%" (seq (.getOtherPolicies policies)))))
      ;; These are just instance stubs, not the same as .ec2.model.Instance
      ;; *TODO*/*TBD*: These instances can refer to non-existent instances!
      ;; Might be useful to look up the instance and report whether or not it actually exists.
      ;; A certain scribe relay ELB I know of had an invalid instance reference.
      (when-let [instances (and (:Instances fields)
                               (not-empty? (seq (.getInstances desc))))]
        (cl-format true "~2@TInstances: ~a~%" (map #(.getInstanceId %) instances))))))
        

;;;
;;; EC2 Misc
;;;

(defn ec2-describe-account-attributes
  []
  (let [ec2 (ec2)
        result (.describeAccountAttributes ec2)]
    (into {}
          (map (fn [accountAttribute]
                 [(keyword (.getAttributeName accountAttribute))
                  (let [v (map (fn [attributeValue]
                                 (.getAttributeValue attributeValue))
                               (.getAttributeValues accountAttribute))]
                    (if (= (count v) 1)
                      (first v)
                      v))])
               (.getAccountAttributes result)))))


(defn report-key-pairs
  []
  (doseq [keyPairInfo (.getKeyPairs (.describeKeyPairs (ec2)))]
    (println (.getKeyName keyPairInfo)
             (.getKeyFingerprint keyPairInfo))))


;;;
;;; Cloudwatch
;;;

(defn ^AmazonCloudWatchClient cw
  "Return an AmazonCloudWatchClient instance ready for calls for a single (optional) region.
   'region' is a keyword defaulting to *region*."
  ([] (cw *region*))
  ([region]
     (let [cw (AmazonCloudWatchClient. (make-aws-creds))
           region (if (instance? Region region) region (get-valid region-map region))]
       (.setRegion cw region)
       cw)))

;; (take 125 (describe-alarms-nonlazy)) - verify # batches fetched
(defn- get-alarms-nonlazy
  "Fetch all alarms in paged fashion, as a non-lazy sequence.
   'cw' is an AmazonCloudWatchClient instance."
  [cw]
  (let [alarm-result (.describeAlarms cw (doto (DescribeAlarmsRequest.)
                                          (.setMaxRecords (int 100))))];defaults to 50
    (loop [result (.getMetricAlarms alarm-result) nt (.getNextToken alarm-result)]
      ;;(println "nt=" (str "'" nt "'") "cnt=" (count result))
      (if (and nt (> (count nt) 0))
        (let [alarm-result (.describeAlarms
                            cw (doto (DescribeAlarmsRequest.)
                                 (.setMaxRecords (int 100))
                                 (.setNextToken nt)))]
          (recur (concat result (.getMetricAlarms alarm-result))
                 (.getNextToken alarm-result)))
        result))))
                                                    
;; (take 125 (describe-alarms-lazy)), verify # batches fetched
(defn- get-alarms-lazy
  "Fetch all alarms in paged fashion, as a lazy sequence.
   'cw' is an AmazonCloudWatchClient instance.
   'result' is the seq of MetricAlarms gathered so far.
   'nt' is the nextToken to fetch."
  [cw result nt]
  ;;(println "nt=" (str "'" nt "'") "cnt=" (count result))
  (if (and nt (> (count nt) 0))
    (concat result
            (lazy-seq 
             (let [alarm-result (.describeAlarms
                                 cw (doto (DescribeAlarmsRequest.)
                                      (.setMaxRecords (int 100))
                                      (.setNextToken nt)))]
               (get-alarms-lazy cw (.getMetricAlarms alarm-result)
                                (.getNextToken alarm-result)))))
    result))

(defn describe-alarms-nonlazy
  "Retrieve a non-lazy sequence of zero or more MetricAlarm instances.
   i.e. (take 10 (describe-alarms-nonlazy)) will still fetch all alarms."
  []
  (get-alarms-nonlazy (cw)))

(defn describe-alarms-lazy
  "Retrieve a lazy sequence of zero or more MetricAlarm instances.
   i.e. (take 10 (describe-alarms-nonlazy)) will NOT fetch all alarms, just the first
   'batch' (whose size may wish to optimize but is limited to 100 max)."
  []
  (let [cw (cw)
        alarm-result (.describeAlarms cw (doto (DescribeAlarmsRequest.)
                                           (.setMaxRecords (int 100))))]; defaults to 50
    (get-alarms-lazy cw (.getMetricAlarms alarm-result) (.getNextToken alarm-result))))

(defn report-alarms
  "Report on zero or more MetricAlarm instances, fetch them if none are specified as with 'describe-alarms'.
  :instances A collectionof MetricAlarm instances, optional."
  [& {:keys [instances]}]
  ;; Note: non-lazy took 17.4 secs, lazy took 18.3 secs, for 1761 alarms
  ;; in 50 record batches (the default).  Could be normal statistical/network variance.
  ;; With 100 record batches: non-lazy 14.47 secs, lazy 14.74 secs
  (let [instances (or instances (describe-alarms-nonlazy))]
    (doseq [ma instances]               ;ma == metricAlarm
      (println (.getAlarmName ma)
               (.getMetricName ma)
               (.getAlarmDescription ma)))))
      

  
  
