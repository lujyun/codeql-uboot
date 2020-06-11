import cpp
// from FunctionCall c, Function f
// where c.getTarget() = f and f.getName()="memcpy"
from FunctionCall c
where c.getTarget().getName()="memcpy"
select c
