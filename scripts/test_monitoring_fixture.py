# SPDX-License-Identifier: Apache-2.0
"""Host boundary controls; native SQL behavior is qualified separately."""
import importlib.util,json,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
SPEC=importlib.util.spec_from_file_location('monitor_fixture',Path(__file__).with_name('runtime-monitoring-fixture.py'))
m=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(m)
class MonitoringFixtureTests(unittest.TestCase):
 def invoke(self,step='read',output=None,code=0):
  result=subprocess.CompletedProcess([],code,json.dumps({'result':'READY','rows':6,'nullRows':1}).encode() if output is None else output,b'')
  with patch.object(m.runtime,'require_local'),patch.object(m.runtime,'require_bootstrap'),patch.object(m.subprocess,'run',return_value=result) as call:
   value=m.run_step(step);return value,call.call_args
 def test_invalid_step_never_reaches_guards_or_execution(self):
  for step in [None,1,True,{},'replace','repair; DROP TABLE x','REPAIR']:
   with patch.object(m.runtime,'require_local') as guard,patch.object(m.subprocess,'run') as run:
    with self.assertRaises(ValueError):m.run_step(step)
    guard.assert_not_called();run.assert_not_called()
 def test_local_and_bootstrap_guards_precede_command(self):
  for guard in ['require_local','require_bootstrap']:
   with patch.object(m.runtime,'require_local'),patch.object(m.runtime,'require_bootstrap'),patch.object(m.runtime,guard,side_effect=RuntimeError('refused')),patch.object(m.subprocess,'run') as run:
    with self.assertRaises(RuntimeError):m.run_step('repair')
    run.assert_not_called()
 def test_closed_request_uses_sql_stdin_and_finite_step_argument(self):
  value,call=self.invoke('fail');self.assertEqual(value['nullRows'],1)
  self.assertIn('fixture_step=fail',call.args[0]);self.assertEqual(call.kwargs['input'],m.SOURCE.read_bytes())
  self.assertEqual(call.kwargs['timeout'],45);self.assertNotIn('shell',call.kwargs)
 def test_output_requires_exact_finite_result(self):
  for output in [b'',b'{}',b'[]',b'{"result":"READY","rows":true,"nullRows":1}',b'{"result":"READY","rows":6,"nullRows":2}',b'{"result":"READY","rows":6,"nullRows":1,"secret":"x"}',b'{"result":"READY","rows":6,"rows":6,"nullRows":1}',b' '*257,b'\xff']:
   with self.assertRaises(RuntimeError):self.invoke(output=output)
  with self.assertRaises(RuntimeError):self.invoke(code=1)
 def test_steps_require_observed_matching_null_count(self):
  repaired=json.dumps({'result':'READY','rows':6,'nullRows':0}).encode()
  self.assertEqual(self.invoke('repair',repaired)[0]['nullRows'],0)
  with self.assertRaises(RuntimeError):self.invoke('repair')
  for step in ['prepare','fail']:
   with self.assertRaises(RuntimeError):self.invoke(step,repaired)
 def test_source_symlink_is_refused_before_command(self):
  with tempfile.TemporaryDirectory() as folder:
   path=Path(folder)/'fixture.sql';path.symlink_to(m.SOURCE)
   with patch.object(m,'SOURCE',path),patch.object(m.runtime,'require_local'),patch.object(m.runtime,'require_bootstrap'),patch.object(m.subprocess,'run') as run:
    with self.assertRaises(ValueError):m.run_step('repair')
    run.assert_not_called()
if __name__=='__main__':unittest.main()
