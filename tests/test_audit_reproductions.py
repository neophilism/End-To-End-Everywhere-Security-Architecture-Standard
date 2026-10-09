import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import reproduce_audit_baseline as audit
class AuditReproductionTests(unittest.TestCase):
    def test_historical_and_corrected_outcomes(self):
        result=audit.reproduce();self.assertTrue(result['regression_verified'])
        self.assertEqual(len(result['baseline']['dependency_cases']),7)
        self.assertEqual(len(result['corrected']['dependency_cases']),7)
