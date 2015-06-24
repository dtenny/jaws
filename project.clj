(defproject jaws "0.2.2-SNAPSHOT"
  :description "Simple tools/wrapper for Amazon AWS JDK API use.
                Unlikely to be of use to anybody but the author."
  :url "https://github.com/dtenny/jaws"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.6.0"]
                 [com.amazonaws/aws-java-sdk "1.10.1"] ; for native.clj
                 [jdt "0.2.0-SNAPSHOT"] ; jdt.{core,cl,shell,java,easyfs,ssh}
                 ])
