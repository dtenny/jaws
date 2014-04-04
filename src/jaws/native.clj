(ns jaws.native
  (:use clojure.repl)
  (:use clojure.set)
  (:use [jdt core cl shell easyfs])
  (:use [clojure.java.io])
  (:use [clojure.pprint :only [cl-format]])
  (:use [clojure.tools.logging :exclude [trace]])
  (:import [com.amazonaws.auth BasicAWSCredentials])
  (:import [com.amazonaws.regions Regions Region])
  (:import [com.amazonaws.services.ec2 AmazonEC2Client AmazonEC2])
  (:import [com.amazonaws.services.ec2.model
            CreateTagsRequest
            DescribeInstancesResult
            DescribeImagesRequest DescribeInstancesRequest DescribeSecurityGroupsRequest
            DescribeTagsRequest
            Filter Instance Tag TerminateInstancesRequest])
  (:import [com.amazonaws.services.identitymanagement AmazonIdentityManagementClient])
  (:import java.io.File))

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

(defn prompt-for-credentials
  "Prompt user for keyword into cred-map for credential set to use.
  Return the (validated) keyword."
  []
  (println "The following credential files are known:")
  (let [cred-seq (seq @cred-map)
        max-key-length (reduce max (map (fn [e] (count (str (key e)))) cred-seq))]
    (doseq [entry cred-seq]
      (let [[access-key secret-key cred-file-path] (val entry)]
        (cl-format true "  ~vs  (~12a)  maps to ~a~%"
                   max-key-length
                   (key entry)
                   (get-user-account-number-for-prompt access-key secret-key)
                   (str cred-file-path)))))
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
  ^{:private true :doc
    "Key in cred-map whose credentials we're using.
    A nil key means we're using whatever is in the calling process environment."}
  current-cred-key (atom nil))

(defn current-cred-map-entry
  "Return the map entry in cred-map indicating current credentials in use
   or nil if there aren't any except those imposed by the process' calling environment
  (Which you can get with environment-creds)."
  []
  (if-let [key (deref current-cred-key)]
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
    (reset! current-cred-key key)
    (throw (Exception. (str "Invalid cred-map key: " key)))))
  
(defn choose-creds
  "Interactive selectiobn and activataion of credentials for future AWS interaction."
  []
  (defcred (prompt-for-credentials))
  (println "Current creds:" (current-cred-map-entry)))

(defn make-aws-creds
  "Make some flavor of aws credentials such as BasicAWSCredentials from previously selected credentials
   and return them. Complain if credentials haven't been set with (choose-creds) or similar mechanism."
  []
  (if-not @current-cred-key
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
        (when (= credkey @current-cred-key)
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

(defn iam-get-user
  "Get a com.amazonaws.services.identitymanagement.model.User"
  []
  (.getUser (.getUser (iam))))

(defn iam-get-user-account-number
  "Return the account number as a string from a User"
  []
  (second (re-find #".*::(\d+):" (.getArn (iam-get-user)))))

(defn report-roles
  []
  (let [result (.listRoles (iam))
        dateFormatter (java.text.SimpleDateFormat. "yyyyMMdd-HHmmssZ")
        dateFormat (fn [date] (.format dateFormatter date))]
    (if (.getIsTruncated result)
      (println "** TRUNCATED **"))
    (doseq [role (.getRoles result)]
      (println (.getRoleId role)
               ;;(.getRoleName role)
               ;;(.getPath role)
               (dateFormat (.getCreateDate role))
               (.getArn role))
      ;;(println "   " (.getAssumeRolePolicyDocument role))
      )))
        

;;;
;;; EC2 - General
;;;

;;; *TODO*: move to jdt.core
(defn get-valid
  "Return the value of (get map key). If key is not in map,
   throw an IllegalArgumentException."
  [map key]
  (let [result (get map key get-valid)]
    (if (= result get-valid)
      (throw (IllegalArgumentException. (str "No such key " key " in map.")))
      result)))

(defn ^AmazonEC2Client ec2
  "Return an AmazonEC2Client instance ready for calls for a single (optional) region.
   'region' is a keyword defaulting to *region*."
  ([] (ec2 *region*))
  ([region]
     (let [ec2 (AmazonEC2Client. (make-aws-creds))
           region (if (instance? Region region) region (get-valid region-map region))]
       (.setRegion ec2 region)
       ec2)))


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
   Specify the entity ID and a map of tag key/value pairs.
   Strings and vals are assumed strings, however keywords are acceptable
   in which case their names will be used.
   Returns nil."
  [entity tag-map]
  {:pre [(map? tag-map)]}
  (let [strify (fn [x] (if (keyword? x) (name x) (str x)))
        tags (map (fn [e] (Tag. (strify (key e)) (strify (val e)))) tag-map)]
    (.createTags (ec2) (CreateTagsRequest. (list entity) tags))))
    

;;;
;;; EC2 - instance queries
;;;

(def instance-state-code-map "Map of InstanceState codes to keywords"
  {0 :pending, 16 :running, 32 :shutting-down, 48 :terminated, 64 :stopping, 80 :stopped})

(defmulti  instance-state
    "Retrieve instance state for an EC2 instance as a keyword, e.g. :running"
    class)
(defmethod instance-state String [instance-id]
  (instance-state (first (describe-instances :ids instance-id))))
(defmethod instance-state Instance [instance]
  (get instance-state-code-map (.getCode (.getState instance)) :unknown-state-code))

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
  (mapv (fn [tag] (str (.getKey tag) "='" (.getValue tag) "'"))
        (sort-aws-tags tag-list ["Name" "aws:autoscaling:groupName"])))

;; *TODO*: put this in jdt.core
(defn seqify
  "If x is a singleton datum, return some kind of sequence of one element, x.
   If x is a collection return a sequence for it.
   If x is a sequence, return it as is.
   Nil is given special treatment and is turned into an empty sequence,
   however false is nto converted into an empty sequence."
  [x]
  (cond (seq? x) x
        (coll? x) (seq x)
        (nil? x) ()
        :else (list x)))

;; *TODO*: put this in jdt.core
(defn listify
  "Similar to seqify, but ensures that the returned collection type is a List.
   If x is a singleton datum, return a list of one element, x.
   If x is a non-list collection return a list for it.
   If x is a sequence, return it as a list.
   Nil is given special treatment and is turned into an empty list
   however false is not converted into an empty sequence."
  [x]
  (cond (list? x) x
        (seq? x) (into () x)
        (coll? x) (into () x)
        (nil? x) ()
        :else (list x)))

(defn instance-volume-ids
  "Return a collection of ebs volume IDs attached to an Instance object.
   Often called implicitly via:
   (report-instances :instances (describe-instances :tag-regex #\"(?i)created\")
                                :fields #{:VolumeIds})"
  [instance]
  (->> (.getBlockDeviceMappings instance)
       (map (fn [mapping] (.getEbs mapping)))
       (map (fn [dev] (.getVolumeId dev)))))

(defn- describeInstancesResult->instances
  "Convert DescribeInsancesResult objects to a sequence of instances.
   The argument may be a singleton DescribeInstancesResult or a collection of them."
  [results]
  (->> (seqify results)
       flatten
       (map (fn [describeInstancesResult] (seq (.getReservations describeInstancesResult))))
       flatten
       (map (fn [reservation] (seq (.getInstances reservation))))
       flatten))

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
   :region a region keyword from 'region-map', or :all, in which case
           iff :data is unspecified, data will be fetched from all regions.
           :region is ignored if :data is specified.
   :fields Set of fields (information) to display in addition to instance id.
           Defaults to: #{:ImageId :SubnetId :PublicDnsName :State :InstanceType :Tags}
           Additional options include: :VolumeIds
   :include Set of additional fields to display, defaults to #{}
   :exclude Set of fields to exclude from the display, defaults to #{}.
   Note that presently you can't specify the order of fields."
  [& {:keys [data instances vpc-mode region indent indent-incr fields include exclude]
      :or {indent *indent* indent-incr 2
           fields #{:ImageId :VpcId :SubnetId :PublicDnsName :State :InstanceType :Tags}
           include #{} exclude #{} }}]
  {:pre [(set? include) (set? exclude) (set? fields)]}
  (let [instances1 (and data (describeInstancesResult->instances data))
        instances2 (and instances (seqify instances))
        instances3 (concat instances1 instances2)
        instances4 (if (empty? instances3)
                       (describeInstancesResult->instances
                        (map #(.describeInstances (ec2 %))
                             (regions-for-key region)))
                       instances3)
        fields (difference (union fields include) exclude)
        ps (fn [x] (print x) (print " "))
        pa (fn [x] (pr x) (print " "))]
    (doseq [instance instances4]
      (do-indent)
      (ps (.getInstanceId instance))
      ;; Macro anyone, for the following?
      (if (:ImageId fields) (ps (.getImageId instance)))
      (if (:VpcId fields) (ps (or (.getVpcId instance) "<noVpc>")))
      (if (:SubnetId fields) (ps (or (.getSubnetId instance) "<noSubnet>")))
      (if (:PublicDnsName fields)
        (let [name (.getPublicDnsName instance)]
          (ps (or (and name (> (count name) 0) name)
                  "<noPublicDns>"))))
      (if (:State fields) (ps (.getName (.getState instance))))
      (if (:InstanceType fields) (ps (.getInstanceType instance)))
      (if (:Tags fields) (pa (squish-tags (.getTags instance))))
      (if (:VolumeIds fields) (ps (instance-volume-ids instance)))
      (println))))

;;; *TODO*: put this in jdt.core
(defn always-nil "A function that always returns nil."
  [& args]
  nil)

;; *TODO*: note that Filter values can have '*' and '?', as per
;; http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Filtering.html#Filtering_Resources_CLI

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

;; *TBD*: Whether to change tag-regex behavior to re-match instead of re-find
(defn describe-instances
  "Retrieve one or more Instances with various filters and regions applied.
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
                   (fn [region] (.describeInstances (ec2 region)
                                                    (doto (DescribeInstancesRequest.)
                                                      (.setInstanceIds (seqify ids)))))
                   (fn [region] (.describeInstances (ec2 region))))
        tag-regex-fn (if tag-regex (tag-regex-find-fn tag-regex) identity)]
    (->> (map fetch-fn regions)
         flatten
         (map (fn [descInsRes] (seq (.getReservations descInsRes))))
         flatten
         (map (fn [reservation] (seq (.getInstances reservation))))
         flatten
         (filter tag-regex-fn)
         )))

(defn terminate-instances
  "Terminate one or more instances.
   :region a region keyword from 'region-map' to override *region*.
   ids a string instance ID or collection/sequence of same specifying specific instances
        to be deleted."
  [ids & {:keys [region]
          :or {region *region*}}]
  {:pre [(not (= region :all))]}
  (doseq [instanceStateChange 
          (->> (.terminateInstances (ec2 region)
                                    (TerminateInstancesRequest. (listify ids)))
               (.getTerminatingInstances))]
    (println (.getInstanceId instanceStateChange)
             (.getName (.getPreviousState instanceStateChange))
             "=>"
             (.getName (.getCurrentState instanceStateChange)))))

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
      (let [describeInstancesResult
            (.describeInstances
             ec2 (doto (DescribeInstancesRequest.)
                   (.setFilters [(Filter. "vpc-id" [(.getVpcId vpc)])])))]
        (binding [*indent* (+ *indent* 4)]
          (report-instances :data describeInstancesResult :exclude #{:VpcId}))))))

                     
;;;
;;; EC2 Scribe account specific
;;;

(defonce scribe-production-regions [:us-east-1 :eu-west-1 :us-west-2 :ap-southeast-1])
(defonce scribe-preproduction-regions [:us-east-1 :eu-west-1])

(defn scribe-production-instances
  "Return a single DescribeInstanceResult for all production scribe servers in *region*."
  []
  (.describeInstances
   (ec2)
   (doto (DescribeInstancesRequest.)
     (.setFilters 
      [(Filter. "tag-value" (for [i (range 3)] (str "scribe-relay-" i)))]))))

(defn scribe-all-production-instances
  "Return a single DescribeInstanceResult for all production scribe servers in all regions."
  []
  (for [region scribe-production-regions]
    (binding [*region* region] (scribe-production-instances))))

(defn scribe-preproduction-instances
  "Return a single DescribeInstanceResult for all pre-production scribe servers in *region*."
  []
  (.describeInstances
   (ec2)
   (doto (DescribeInstancesRequest.)
     (.setFilters
      [(Filter. "tag-value" (for [i (range 3)] (str "scribe-relay-preprod-" i)))]))))

(defn scribe-all-preproduction-instances
  "Return a collection of DescribeInstanceResults for all pre-production scribe servers in all regions."
  []
  (for [region scribe-preproduction-regions]
    (binding [*region* region] (scribe-preproduction-instances))))

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
          
(defn report-key-pairs
  []
  (doseq [keyPairInfo (.getKeyPairs (.describeKeyPairs (ec2)))]
    (println (.getKeyName keyPairInfo)
             (.getKeyFingerprint keyPairInfo))))
