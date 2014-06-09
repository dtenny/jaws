(defproject jaws "0.1.1"
  :description "Simple tools/wrapper for Amazon AWS JDK API use.
                Unlikely to be of use to anybody but the author."
  :url "https://github.com/dtenny/jaws"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.6.0"]
                 [com.amazonaws/aws-java-sdk "1.7.3"] ; for native.clj
                 [jdt "0.1.2"] ; jdt.{core,cl,shell,java,easyfs,ssh}
                 ])
