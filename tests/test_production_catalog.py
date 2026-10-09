import sys, unittest, json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import profile_engine

class ProductionCatalogTests(unittest.TestCase):
    def test_production_catalog_contains_no_illustrative_providers(self):
        catalog=json.loads((ROOT/'profiles/catalog.json').read_text())
        self.assertFalse({'foundation','example-architecture','example-addons'} & {x['family_id'] for x in catalog['families']})
        self.assertEqual(profile_engine.validate_catalog(catalog),[])
        config={'schema_version':'0.1','configuration_id':'bad','standard_version':catalog['standard_version'],'selected_profiles':['foundation-baseline@0.1.0'],'accepted_nondefault_statuses':[]}
        self.assertFalse(profile_engine.resolve_configuration(catalog,config).valid)
    def test_fixture_denominator_is_production_catalog_exactly(self):
        load=lambda p:json.loads((ROOT/p).read_text())
        catalog=load('profiles/catalog.json');manifest=load('fixtures/reference-architectures/manifest.json')
        self.assertEqual({profile_engine.profile_ref(p) for p in catalog['profiles']},{x['profile_ref'] for x in manifest['entries']})
    def test_real_many_valued_families_remain_many(self):
        catalog=json.loads((ROOT/'profiles/catalog.json').read_text())
        families={x['family_id']:x['cardinality'] for x in catalog['families']}
        self.assertEqual(families['formal-verification'],'many')
        self.assertEqual(families['advisory-interoperability'],'many')
