-- E2EESA PR 35 Observatory reference PostgreSQL schema.
-- Canonical evidence tables are append-only. Graph/search/RDF projections are external derived stores.

CREATE SCHEMA IF NOT EXISTS e2eesa_observatory;

CREATE OR REPLACE FUNCTION e2eesa_observatory.reject_canonical_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'E2EESA canonical evidence is append-only: % on %.%', TG_OP, TG_TABLE_SCHEMA, TG_TABLE_NAME;
END;
$$;

CREATE TABLE IF NOT EXISTS e2eesa_observatory.evidence_bundles (
  bundle_digest text PRIMARY KEY CHECK (bundle_digest ~ '^sha256:[0-9a-f]{64}$'),
  manifest_digest text NOT NULL CHECK (manifest_digest ~ '^sha256:[0-9a-f]{64}$'),
  bundle_id text NOT NULL,
  revision integer NOT NULL CHECK (revision > 0),
  previous_bundle_digest text NULL REFERENCES e2eesa_observatory.evidence_bundles(bundle_digest),
  created_at timestamptz NOT NULL,
  schema_version text NOT NULL,
  UNIQUE (bundle_id, revision),
  CHECK (
    (revision = 1 AND previous_bundle_digest IS NULL)
    OR
    (revision > 1 AND previous_bundle_digest IS NOT NULL)
  )
);

CREATE TABLE IF NOT EXISTS e2eesa_observatory.content_objects (
  content_digest text PRIMARY KEY CHECK (content_digest ~ '^sha256:[0-9a-f]{64}$'),
  byte_length bigint NULL CHECK (byte_length IS NULL OR byte_length >= 0)
);

CREATE TABLE IF NOT EXISTS e2eesa_observatory.agents (
  bundle_digest text NOT NULL REFERENCES e2eesa_observatory.evidence_bundles(bundle_digest),
  agent_id text NOT NULL,
  agent_type text NOT NULL CHECK (agent_type IN ('person','organization','software','service')),
  name text NOT NULL,
  version text NULL,
  identity_ref text NULL,
  PRIMARY KEY (bundle_digest, agent_id)
);

CREATE TABLE IF NOT EXISTS e2eesa_observatory.entities (
  bundle_digest text NOT NULL REFERENCES e2eesa_observatory.evidence_bundles(bundle_digest),
  entity_id text NOT NULL,
  entity_type text NOT NULL,
  content_digest text NOT NULL REFERENCES e2eesa_observatory.content_objects(content_digest),
  media_type text NOT NULL,
  byte_length bigint NULL CHECK (byte_length IS NULL OR byte_length >= 0),
  content_uri text NULL,
  source_uri text NULL,
  source_identifier text NULL,
  acquired_at timestamptz NULL,
  revision_of text NULL,
  PRIMARY KEY (bundle_digest, entity_id),
  FOREIGN KEY (bundle_digest, revision_of)
    REFERENCES e2eesa_observatory.entities(bundle_digest, entity_id)
);

CREATE TABLE IF NOT EXISTS e2eesa_observatory.activities (
  bundle_digest text NOT NULL REFERENCES e2eesa_observatory.evidence_bundles(bundle_digest),
  activity_id text NOT NULL,
  activity_type text NOT NULL,
  started_at timestamptz NOT NULL,
  ended_at timestamptz NOT NULL,
  method_ref text NOT NULL,
  parameters_digest text NULL CHECK (parameters_digest IS NULL OR parameters_digest ~ '^sha256:[0-9a-f]{64}$'),
  PRIMARY KEY (bundle_digest, activity_id),
  CHECK (ended_at >= started_at)
);

CREATE TABLE IF NOT EXISTS e2eesa_observatory.activity_acquisitions (
  bundle_digest text NOT NULL,
  activity_id text NOT NULL,
  transport text NOT NULL,
  source_uri text NOT NULL,
  retrieved_at timestamptz NOT NULL,
  response_status integer NULL CHECK (response_status IS NULL OR response_status BETWEEN 100 AND 599),
  etag text NULL,
  last_modified text NULL,
  headers_digest text NULL CHECK (headers_digest IS NULL OR headers_digest ~ '^sha256:[0-9a-f]{64}$'),
  request_ref text NULL,
  PRIMARY KEY (bundle_digest, activity_id),
  FOREIGN KEY (bundle_digest, activity_id)
    REFERENCES e2eesa_observatory.activities(bundle_digest, activity_id)
);

CREATE TABLE IF NOT EXISTS e2eesa_observatory.activity_agents (
  bundle_digest text NOT NULL,
  activity_id text NOT NULL,
  agent_id text NOT NULL,
  PRIMARY KEY (bundle_digest, activity_id, agent_id),
  FOREIGN KEY (bundle_digest, activity_id)
    REFERENCES e2eesa_observatory.activities(bundle_digest, activity_id),
  FOREIGN KEY (bundle_digest, agent_id)
    REFERENCES e2eesa_observatory.agents(bundle_digest, agent_id)
);

CREATE TABLE IF NOT EXISTS e2eesa_observatory.activity_used_entities (
  bundle_digest text NOT NULL,
  activity_id text NOT NULL,
  entity_id text NOT NULL,
  PRIMARY KEY (bundle_digest, activity_id, entity_id),
  FOREIGN KEY (bundle_digest, activity_id)
    REFERENCES e2eesa_observatory.activities(bundle_digest, activity_id),
  FOREIGN KEY (bundle_digest, entity_id)
    REFERENCES e2eesa_observatory.entities(bundle_digest, entity_id)
);

CREATE TABLE IF NOT EXISTS e2eesa_observatory.activity_generated_entities (
  bundle_digest text NOT NULL,
  activity_id text NOT NULL,
  entity_id text NOT NULL,
  PRIMARY KEY (bundle_digest, activity_id, entity_id),
  UNIQUE (bundle_digest, entity_id),
  FOREIGN KEY (bundle_digest, activity_id)
    REFERENCES e2eesa_observatory.activities(bundle_digest, activity_id),
  FOREIGN KEY (bundle_digest, entity_id)
    REFERENCES e2eesa_observatory.entities(bundle_digest, entity_id)
);

CREATE TABLE IF NOT EXISTS e2eesa_observatory.events (
  bundle_digest text NOT NULL REFERENCES e2eesa_observatory.evidence_bundles(bundle_digest),
  event_id text NOT NULL,
  event_type text NOT NULL,
  occurred_start timestamptz NOT NULL,
  occurred_end timestamptz NULL,
  PRIMARY KEY (bundle_digest, event_id),
  CHECK (occurred_end IS NULL OR occurred_end >= occurred_start)
);

CREATE TABLE IF NOT EXISTS e2eesa_observatory.event_subjects (
  bundle_digest text NOT NULL,
  event_id text NOT NULL,
  subject_id text NOT NULL,
  subject_kind text NOT NULL CHECK (subject_kind IN ('entity','agent')),
  PRIMARY KEY (bundle_digest, event_id, subject_id),
  FOREIGN KEY (bundle_digest, event_id)
    REFERENCES e2eesa_observatory.events(bundle_digest, event_id)
);

CREATE TABLE IF NOT EXISTS e2eesa_observatory.event_attributes (
  bundle_digest text NOT NULL,
  event_id text NOT NULL,
  attribute_name text NOT NULL,
  value_json jsonb NOT NULL,
  PRIMARY KEY (bundle_digest, event_id, attribute_name),
  FOREIGN KEY (bundle_digest, event_id)
    REFERENCES e2eesa_observatory.events(bundle_digest, event_id)
);

CREATE TABLE IF NOT EXISTS e2eesa_observatory.citations (
  bundle_digest text NOT NULL,
  citation_id text NOT NULL,
  entity_id text NOT NULL,
  locator_kind text NOT NULL,
  locator_value text NOT NULL,
  excerpt_digest text NULL CHECK (excerpt_digest IS NULL OR excerpt_digest ~ '^sha256:[0-9a-f]{64}$'),
  note text NULL,
  PRIMARY KEY (bundle_digest, citation_id),
  FOREIGN KEY (bundle_digest, entity_id)
    REFERENCES e2eesa_observatory.entities(bundle_digest, entity_id)
);

CREATE TABLE IF NOT EXISTS e2eesa_observatory.event_citations (
  bundle_digest text NOT NULL,
  event_id text NOT NULL,
  citation_id text NOT NULL,
  PRIMARY KEY (bundle_digest, event_id, citation_id),
  FOREIGN KEY (bundle_digest, event_id)
    REFERENCES e2eesa_observatory.events(bundle_digest, event_id),
  FOREIGN KEY (bundle_digest, citation_id)
    REFERENCES e2eesa_observatory.citations(bundle_digest, citation_id)
);

CREATE TABLE IF NOT EXISTS e2eesa_observatory.integrity_anchors (
  bundle_digest text NOT NULL REFERENCES e2eesa_observatory.evidence_bundles(bundle_digest),
  anchor_id text NOT NULL,
  anchor_type text NOT NULL CHECK (anchor_type IN ('detached-signature','rfc3161-timestamp','transparency-log')),
  subject_digest text NOT NULL CHECK (subject_digest ~ '^sha256:[0-9a-f]{64}$'),
  proof_digest text NOT NULL CHECK (proof_digest ~ '^sha256:[0-9a-f]{64}$'),
  observed_at timestamptz NOT NULL,
  provider text NOT NULL,
  reference text NOT NULL,
  PRIMARY KEY (bundle_digest, anchor_id)
);

CREATE TABLE IF NOT EXISTS e2eesa_observatory.anchor_verification (
  bundle_digest text NOT NULL,
  anchor_id text NOT NULL,
  status text NOT NULL CHECK (status IN ('unverified','verified')),
  verifier_name text NULL,
  verifier_version text NULL,
  verified_at timestamptz NULL,
  result_digest text NULL CHECK (result_digest IS NULL OR result_digest ~ '^sha256:[0-9a-f]{64}$'),
  result_ref text NULL,
  PRIMARY KEY (bundle_digest, anchor_id),
  FOREIGN KEY (bundle_digest, anchor_id)
    REFERENCES e2eesa_observatory.integrity_anchors(bundle_digest, anchor_id),
  CHECK (
    (status = 'unverified' AND verifier_name IS NULL AND verifier_version IS NULL AND verified_at IS NULL AND result_digest IS NULL AND result_ref IS NULL)
    OR
    (status = 'verified' AND verifier_name IS NOT NULL AND verifier_version IS NOT NULL AND verified_at IS NOT NULL AND result_digest IS NOT NULL AND result_ref IS NOT NULL)
  )
);

CREATE TABLE IF NOT EXISTS e2eesa_observatory.projection_checkpoints (
  checkpoint_id bigserial PRIMARY KEY,
  source_bundle_digest text NOT NULL REFERENCES e2eesa_observatory.evidence_bundles(bundle_digest),
  projection_id text NOT NULL,
  projection_version text NOT NULL,
  relational_rowset_digest text NOT NULL CHECK (relational_rowset_digest ~ '^sha256:[0-9a-f]{64}$'),
  projection_digest text NOT NULL CHECK (projection_digest ~ '^sha256:[0-9a-f]{64}$'),
  generated_at timestamptz NOT NULL,
  UNIQUE (source_bundle_digest, projection_id, projection_version, projection_digest)
);

DO $$
DECLARE
  table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'evidence_bundles',
    'content_objects',
    'agents',
    'entities',
    'activities',
    'activity_acquisitions',
    'activity_agents',
    'activity_used_entities',
    'activity_generated_entities',
    'events',
    'event_subjects',
    'event_attributes',
    'citations',
    'event_citations',
    'integrity_anchors',
    'anchor_verification'
  ]
  LOOP
    EXECUTE format(
      'DROP TRIGGER IF EXISTS reject_mutation ON e2eesa_observatory.%I',
      table_name
    );
    EXECUTE format(
      'CREATE TRIGGER reject_mutation BEFORE UPDATE OR DELETE ON e2eesa_observatory.%I FOR EACH ROW EXECUTE FUNCTION e2eesa_observatory.reject_canonical_mutation()',
      table_name
    );
  END LOOP;
END;
$$;
