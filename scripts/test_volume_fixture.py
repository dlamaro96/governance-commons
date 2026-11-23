# SPDX-License-Identifier: Apache-2.0
"""Host controls for finite synthetic volume operations; no source execution."""
import importlib.util,json,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
SPEC=importlib.util.spec_from_file_location('volume_fixture',Path(__file__).with_name('runtime-volume-fixture.py'))
m=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(m)
class VolumeFixtureTests(unittest.TestCase):
 def invoke(self,step='read',output=b'{"result":"READY","rows":6}',code=0):
  with patch.object(m.runtime,'require_local'),patch.object(m.runtime,'require_bootstrap'),patch.object(m.subprocess,'run',return_value=subprocess.CompletedProcess([],code,output,b'')) as call:
   return m.run_step(step),call.call_args
 def test_closed_steps_refuse_before_execution(self):
  for step in [None,1,True,{},'replace','repair; DROP TABLE x','REPAIR']:
   with patch.object(m.runtime,'require_local') as guard,patch.object(m.subprocess,'run') as run:
    with self.assertRaises(ValueError):m.run_step(step)
    guard.assert_not_called();run.assert_not_called()
 def test_guard_refusal_precedes_source_access(self):
  for guard in ('require_local','require_bootstrap'):
   with patch.object(m.runtime,'require_local'),patch.object(m.runtime,'require_bootstrap'),patch.object(m.runtime,guard,side_effect=RuntimeError('refused')),patch.object(m.subprocess,'run') as run:
    with self.assertRaises(RuntimeError):m.run_step('repair')
    run.assert_not_called()
 def test_only_fixed_sql_stdin_and_bounded_finite_argument(self):
  value,call=self.invoke('fail',b'{"result":"READY","rows":5}')
  self.assertEqual(value['rows'],5);self.assertEqual(value['fixture'],'public.volume_quality_fixture')
  self.assertEqual(call.kwargs['input'],m.SOURCE.read_bytes());self.assertIn('fixture_step=fail',call.args[0]);self.assertEqual(call.kwargs['timeout'],45);self.assertNotIn('shell',call.kwargs)
 def test_exact_finite_shape_no_extra_keys_or_duplicate_fields(self):
  for output in [b'',b'{}',b'[]',b'{"result":"READY","rows":true}',b'{"result":"READY","rows":7}',b'{"result":"READY","rows":6,"nullRows":6}',b'{"result":"READY","rows":6,"rows":6}',b' '*257,b'\xff']:
   with self.assertRaises(RuntimeError):self.invoke(output=output)
  with self.assertRaises(RuntimeError):self.invoke(code=1)
 def test_every_mutation_requires_its_observed_postcondition(self):
  for step in ('prepare','repair'):
   self.assertEqual(self.invoke(step)[0]['rows'],6)
   with self.assertRaises(RuntimeError):self.invoke(step,b'{"result":"READY","rows":5}')
  self.assertEqual(self.invoke('fail',b'{"result":"READY","rows":5}')[0]['rows'],5)
  with self.assertRaises(RuntimeError):self.invoke('fail')
 def test_source_symlink_and_byte_cap_refuse_before_command(self):
  with tempfile.TemporaryDirectory() as folder:
   link=Path(folder)/'fixture.sql';link.symlink_to(m.SOURCE)
   huge=Path(folder)/'huge.sql';huge.write_bytes(b'x'*65537)
   for path in (link,huge):
    with patch.object(m,'SOURCE',path),patch.object(m.runtime,'require_local'),patch.object(m.runtime,'require_bootstrap'),patch.object(m.subprocess,'run') as run:
     with self.assertRaises(ValueError):m.run_step('read')
     run.assert_not_called()
if __name__=='__main__':unittest.main()
