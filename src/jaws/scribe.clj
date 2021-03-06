(ns jaws.scribe
  (:require [clojure.java.io :as io])
  (:use clojure.repl)
  (:use clojure.set)
  (:use [jdt core cl shell easyfs ssh])
  (:use jaws.native)                    ;you may need to load this file first
  (:use [clojure.pprint :only [cl-format]])
  (:import [com.amazonaws.services.ec2.model
            DescribeInstancesRequest Filter]))

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
  "Return a Instances for all production scribe servers in all regions."
  []
  (describeInstancesResult->instances
   (for [region scribe-production-regions]
     (binding [*region* region] (scribe-production-instances)))))

(defn scribe-preproduction-instances
  "Return a single DescribeInstanceResult for all pre-production scribe servers in *region*."
  []
  (.describeInstances
   (ec2)
   (doto (DescribeInstancesRequest.)
     (.setFilters
      [(Filter. "tag-value" (for [i (range 3)] (str "scribe-relay-preprod-" i)))]))))

(defn scribe-all-preproduction-instances
  "Return a collection of Instances for all pre-production scribe servers in all regions."
  []
  (describeInstancesResult->instances
   (for [region scribe-preproduction-regions]
     (binding [*region* region] (scribe-preproduction-instances)))))

(def scribe-private-key
  (str (probe-file "~/SECURE-NO-POSTING/deployScribeRelay-aws-analytics-pr.ssh-key")))
(def scribe-user "deployScribeRelay")

(comment
  (defprogram ssh "/usr/bin/ssh")

  (defn scribe-ssh-term
    "Start an interactive ssh session with the indicated scribe relay dns name."
    [dnsname]
    ;; Consider calling .waitFor on the result
    (.exec (Runtime/getRuntime)
           (into-array
            ["xterm" "-fn" "*liberation mono-bold-r-normal*" "-e"
             ;; If your terminal exits prematurely because of some error,
             ;; append a "; read" to the string you invole with -e so it'll wait before
             ;; exiting. That might be useful in general too, for that matter.
             (str "ssh -i " scribe-private-key " -l " scribe-user
                  " -o " "StrictHostKeyChecking=false " dnsname
                  " ; echo 'hit enter to quit' ; read")])))

  (defn scribe-ssh
    "Perform an ssh command to a scribe host indicated by public dns name.
   E.g. (scribe-ssp \"ec2-23-23-83-179.compute-1.amazonaws.com\" \"ls\")
   Return a sequence of strings, one string for each line of output."
    [dnsname command]
    (ssh "-i" scribe-private-key "-l" scribe-user "-o" "StrictHostKeyChecking=false"
         dnsname command))
  )

(def proxy-host (atom nil))             ;set in scribe-private.clj
(def proxy-port (atom nil))             ;set in scribe-private.clj
(defn scribe-ssh [dnsname command & {:keys [tty]}]
  (ssh command :private-key scribe-private-key
       :target-user scribe-user :target-host dnsname
       :proxy-host @proxy-host :proxy-port @proxy-port :tty tty))
  
;; Common remote dirs/hosts I need to examine.
(def stunnel-conf "/etc/stunnel/stunnel.conf")
(def scribe-conf "/etc/scribe/conf/scribe.conf")
(def scribe-log-dir "/media/scribe/log")
(def scribe-store-dir "/media/scribe/store") ; (find . -type f | wc -l) useful
(def prod-intake-host (atom nil)) ; set in scribe-private
(def preprod-intake-host (atom nil)) ; set in scribe-private

;; Common commands I use
(def scribe-counters "scribe_ctrl counters")
(def ping-slough (str "ping -c 1 " @prod-intake-host))

;; Common working sets I generate
;; (def preprod-instances (scribe-all-preproduction-instances))
;; (def ip (.getPublicDnsName (first instances)))
;; (def prod-instances (scribe-all-production-instances))
;; (def running-prod-instances (filter #(= (instance-state %) :running) (scribe-all-production-instances)))

(defn ping-prod
  "Ping the production IP address from all production scribe relays"
  []
  (let [instances
        (filter #(= (instance-state %) :running) (scribe-all-production-instances))]
    (with-output ["/tmp/ping-prod.out"]
      (doseq [instance instances]
        (let [dnsname (.getPublicDnsName instance)]
          (println "Pinging slough from " dnsname)
          (printlines (scribe-ssh dnsname (str "echo $(hostname) ; " ping-slough)))
          (flush))))
    (println "SSH output for" (count instances) "instances in /tmp/ping-prod.out")))

(defn get-autoscaling-groupname [instance]
  (.getValue
   (first (filter #(= (.getKey %) "aws:autoscaling:groupName") (.getTags instance)))))

(defn ssh-parallel
  "Invoke 'ssh-command' from all scribe relays in 'instances', typically obtained via a call
   to 'scribe-all-production-instances' or 'scribe-all-preproduction-instances'.
   Return a collection of file names containing the results."
  [instances ssh-command]
  (let [instances
        (filter #(= (instance-state %) :running) instances)
        file-timestamp (date->utc)
        fetcher-fn
        (fn [instance]
          (let [relay-name (get-autoscaling-groupname instance)
                file-name (str "/tmp/" file-timestamp "-" 
                               (instance-availability-zone instance) "-"
                               relay-name)
                dns-name (.getPublicDnsName instance)]
            (with-open [out (io/writer file-name)]
              (binding [*out* out]
                (let [[rc stdout err] (scribe-ssh dns-name ssh-command)]
                  (if-not (= rc 0)
                    (cl-format *err* "** ERROR invoking ~s from ~a~%~a~%"
                               ssh-command dns-name err))
                  (printlines stdout))
                (flush)))
            file-name))
        start-time (System/currentTimeMillis)
        result (map deref
                    (doall
                     (map #(future (fetcher-fn %))
                          instances)))]
    (println (count result) "instances queried in"
             (- (System/currentTimeMillis) start-time) "ms")
    result))

;; *TODO*: eliminate counters-parallel as calls to (ssh-parallel instances scribe-counterss)
(defn counters-parallel
  "Get scribe_ctrl countesr from all scribe relays in 'instances', typically obtained via a call
   to 'scribe-all-production-instances' or 'scribe-all-preproduction-instances'.
   Return a collection of file names containing the results."
  [instances]
  (let [instances
        (filter #(= (instance-state %) :running) instances)
        file-timestamp (date->utc)
        fetcher-fn
        (fn [instance]
          (let [relay-name (get-autoscaling-groupname instance)
                file-name (str "/tmp/" file-timestamp "-" 
                               (instance-availability-zone instance) "-"
                               relay-name)
                dns-name (.getPublicDnsName instance)]
            (with-open [out (io/writer file-name)]
              (binding [*out* out]
                (let [[rc stdout err] (scribe-ssh dns-name scribe-counters)]
                  (if-not (= rc 0)
                    (cl-format *err* "** ERROR collecting counters from ~a~%~a~%"
                               dns-name err))
                  (printlines stdout))
                (flush)))
            file-name))
        start-time (System/currentTimeMillis)
        result (map deref
                    (doall
                     (map #(future (fetcher-fn %))
                          instances)))]
    (println (count result) "instances queried in"
             (- (System/currentTimeMillis) start-time) "ms")
    result))

;; TODO: need to save the reference to the ScheduledExecutorService so we can
;; invoke shutdown on it.  May want to return vector of both that and the ScheduledFuture,
;; since right now we'll be leaking a (single) thread pool on every call.
(defn every-n-minutes
  "Run fn asynchronously every n minutes.
   Returns the ScheduledFuture on which you can call (.cancel <result> true).

   Recommend 'fn' have *out* and *err* bound to some well known location.
   Also recommend you save the returned ScheduledFuture so you don't have un-reclaimable
   daemon threads running."
  [fn n]
  (let [scheduled-executor-service
        (java.util.concurrent.Executors/newSingleThreadScheduledExecutor)]
    (.scheduleAtFixedRate scheduled-executor-service
                          fn 0 n java.util.concurrent.TimeUnit/MINUTES)))

(defn counters-prod
  "Get scribe_ctrl counters from all production scribe relays"
  []
  (let [instances
        (filter #(= (instance-state %) :running) (scribe-all-production-instances))]
    (counters-parallel instances)))

(defn counters-preprod
  "Get scribe_ctrl counters from all preproduction scribe relays"
  []
  (let [instances
        (filter #(= (instance-state %) :running) (scribe-all-preproduction-instances))]
    (counters-parallel instances)))

(defn ssh-prod
  "Invoke the indicated ssh command on all produciton scribe relays"
  [ssh-command]
  (let [instances
        (filter #(= (instance-state %) :running) (scribe-all-production-instances))]
    (ssh-parallel instances ssh-command)))

(defn ssh-preprod
  "Invoke the indicated ssh command on all produciton scribe relays"
  [ssh-command]
  (let [instances
        (filter #(= (instance-state %) :running) (scribe-all-preproduction-instances))]
    (ssh-parallel instances ssh-command)))

(defn repeat-counters-prod-parallel
  "Retrieve production scribe counters every n-minutes minutes.
   Save the ScheduledFuture result of this function so you can
   (.cancel <sf> true) when you're done, or you'll have to exit the REPL to
   stop collecting."
  [n-minutes]
  (every-n-minutes
   (fn []
     (println (date->utc) "collecting counters.")
     (println (counters-prod))
     (println))
   n-minutes))

;; Note that we can derive regions for instances from availability zones, which is in the Placement object from instance.getPlacement()

(defn parse-scribe-counter-line [line]
  "Return a [counter-name counter-value] vector, or nil if the line isn't a
   scribe_ctrl output line with a counter."
  ;; Category name, category type (received good, retries), count
  ;; E.g. ovisearch.recommendations-servlet.recommendations:received good: 3
  (if-let [[match category type count]
           (re-matches #"([^:]+):([^:]+): (\d+)\s*" line)]
    [(str category ":" type) (Long/parseLong count)]))

(defn aggregate-counters
  "Return a map of counters aggregated scribe_ctrl output for multpile servers
   contained in one file."
  [file]
  (loop [aggregate-map (transient {})
         parse-coll (filter identity
                            (map parse-scribe-counter-line (readlines file)))]
    (if (empty? parse-coll)
      (persistent! aggregate-map)
      (let [[category count] (first parse-coll)]
        (if-let [old-count (get aggregate-map category)]
          (recur (assoc! aggregate-map category (+ count old-count))
                 (rest parse-coll))
          (recur (assoc! aggregate-map category count)
                 (rest parse-coll)))))))

(defn print-aggregate-counters
  "Print a map of scribe counters, sorted by category (key) name."
  [file]
  (let [aggregate-map (aggregate-counters file)]
    (doseq [e (sort (fn [e1 e2] (compare (key e1) (key e2))) (seq aggregate-map))]
      (println (str (key e) ": " (val e))))))

(load-file "src/jaws/scribe-private.clj")
