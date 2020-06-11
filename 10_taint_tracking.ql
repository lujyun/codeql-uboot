import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph
 
class NetworkByteSwap extends Expr {
    NetworkByteSwap () {
      // TODO: replace <class> and <var>
      exists(MacroInvocation m| 
        m.getMacro().getName().regexpMatch("ntoh(s|l|ll)")
        and
        this = m.getExpr()
      )
    } 
  }
 
class Config extends TaintTracking::Configuration {
  Config() { this = "NetworkToMemFuncLength" }

  override predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof NetworkByteSwap
  }
  override predicate isSink(DataFlow::Node sink) {
    exists(FunctionCall f | sink.asExpr() = f.getArgument(2)
    and
    f.getTarget().getName()="memcpy"
    and not
    f.getArgument(1).isConstant())
  }
}

from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Network byte swap flows to memcpy"