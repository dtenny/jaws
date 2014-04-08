(ns jaws.scribe
  (:use clojure.repl)
  (:use clojure.set)
  (:use [jdt core cl shell easyfs])
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
  
;; Common remote dirs/hosts I need to examine.
(def stunnel-conf "/etc/stunnel/stunnel.conf")
(def scribe-conf "/etc/scribe/conf/scribe.conf")
(def scribe-log-dir "/media/scribe/log")
(def scribe-store-dir "/media/scribe/store") ; (find . -type f | wc -l) useful
(def prod-intake-host "scribe-slough-integration.pr.analytics.nokia.com")
(def preprod-intake-host "scribe-noklab-integration.preprod.analytics.nokia.com")

;; Common commands I use
(def scribe-counters "scribe_ctrl counters")
(def ping-slough (str "ping -c 1 " prod-intake-host))

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

(defn counters-prod
  "Get scribe_ctrl countesr from all production scribe relays"
  []
  (let [instances
        (filter #(= (instance-state %) :running) (scribe-all-production-instances))]
    (with-output ["/tmp/counters-prod.out"]
      (doseq [instance instances]
        (let [dnsname (.getPublicDnsName instance)]
          (println "scribe_ctrl counters for " (get-autoscaling-groupname instance) dnsname)
          (printlines (scribe-ssh dnsname (str "echo $(hostname) ; " scribe-counters)))
          (flush))))
    (println "SSH output for" (count instances) "instances in /tmp/counters-prod.out")))

;; Note that we can derive regions for instances from availability zones, which is in the Placement object from instance.getPlacement()
