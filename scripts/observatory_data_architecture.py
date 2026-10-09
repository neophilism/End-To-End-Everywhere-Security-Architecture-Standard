#!/usr/bin/env python3
"""Deterministic Observatory canonical rows and derived projections for E2EESA PR 35."""

from __future__ import annotations

import canonical_serialization

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

import observatory_evidence

RELATIONAL_MODEL_VERSION = "0.1.0"
PROJECTION_VERSION = "0.1.0"

TABLES = (
    "evidence_bundles",
    "content_objects",
    "agents",
    "entities",
    "activities",
    "activity_acquisitions",
    "activity_agents",
    "activity_used_entities",
    "activity_generated_entities",
    "events",
    "event_subjects",
    "event_attributes",
    "citations",
    "event_citations",
    "integrity_anchors",
    "anchor_verification",
)

PROV = "http://www.w3.org/ns/prov#"
RDF = "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
E2EESA = "https://endtoendeverywhere.org/ns/observatory#"


def canonical_bytes(value: object) -> bytes:
    return canonical_serialization.canonical_bytes(value)


def canonical_digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def _sort_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(rows, key=canonical_bytes)


def validate_registry(registry: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if registry.get("schema_version") != "0.1":
        errors.append("observatory data registry schema_version must be 0.1")
    if registry.get("relational_model_version") != RELATIONAL_MODEL_VERSION:
        errors.append(
            f"observatory relational_model_version must be {RELATIONAL_MODEL_VERSION}"
        )

    projections = registry.get("projections")
    if not isinstance(projections, list) or not projections:
        return errors + ["observatory data registry projections must be non-empty"]

    expected = {
        "property-graph": "graph",
        "prov-rdf": "rdf",
        "search-documents": "search",
    }
    seen: set[str] = set()
    for index, item in enumerate(projections):
        prefix = f"observatory data registry projections[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be an object")
            continue
        projection_id = item.get("projection_id")
        if projection_id not in expected:
            errors.append(f"{prefix} unknown projection_id {projection_id}")
            continue
        if projection_id in seen:
            errors.append(f"{prefix} duplicate projection_id {projection_id}")
        seen.add(projection_id)
        if item.get("projection_version") != PROJECTION_VERSION:
            errors.append(
                f"{prefix} projection_version must be {PROJECTION_VERSION}"
            )
        if item.get("projection_kind") != expected[projection_id]:
            errors.append(
                f"{prefix} projection_kind does not match {projection_id}"
            )
        if item.get("authoritative") is not False:
            errors.append(f"{prefix} derived projection must not be authoritative")
        if item.get("rebuildable") is not True:
            errors.append(f"{prefix} derived projection must be rebuildable")

    if seen != set(expected):
        missing = sorted(set(expected) - seen)
        errors.append(
            "observatory data registry missing projections: " + ", ".join(missing)
        )
    return sorted(set(errors))


def relational_rows(bundle: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    evidence_errors = observatory_evidence.validate_bundle(bundle)
    if evidence_errors:
        raise ValueError("invalid evidence bundle: " + "; ".join(evidence_errors))

    bundle_digest = bundle["bundle_digest"]
    rows: dict[str, list[dict[str, Any]]] = {table: [] for table in TABLES}

    rows["evidence_bundles"].append({
        "bundle_digest": bundle_digest,
        "manifest_digest": bundle["manifest_digest"],
        "bundle_id": bundle["bundle_id"],
        "revision": bundle["revision"],
        "previous_bundle_digest": bundle["previous_bundle_digest"],
        "created_at": bundle["created_at"],
        "schema_version": bundle["schema_version"],
    })

    content_lengths: dict[str, int | None] = {}
    for entity in bundle["entities"]:
        digest = entity["content_digest"]
        length = entity["byte_length"]
        prior = content_lengths.get(digest)
        if digest in content_lengths and prior is not None and length is not None and prior != length:
            raise ValueError(
                f"content digest {digest} has conflicting byte lengths {prior} and {length}"
            )
        if digest not in content_lengths or prior is None:
            content_lengths[digest] = length

        rows["entities"].append({
            "bundle_digest": bundle_digest,
            "entity_id": entity["entity_id"],
            "entity_type": entity["entity_type"],
            "content_digest": digest,
            "media_type": entity["media_type"],
            "byte_length": length,
            "content_uri": entity["content_uri"],
            "source_uri": entity["source_uri"],
            "source_identifier": entity["source_identifier"],
            "acquired_at": entity["acquired_at"],
            "revision_of": entity["revision_of"],
        })

    for digest, length in content_lengths.items():
        rows["content_objects"].append({
            "content_digest": digest,
            "byte_length": length,
        })

    agent_ids = {agent["agent_id"] for agent in bundle["agents"]}
    entity_ids = {entity["entity_id"] for entity in bundle["entities"]}

    for agent in bundle["agents"]:
        rows["agents"].append({
            "bundle_digest": bundle_digest,
            "agent_id": agent["agent_id"],
            "agent_type": agent["agent_type"],
            "name": agent["name"],
            "version": agent["version"],
            "identity_ref": agent["identity_ref"],
        })

    for activity in bundle["activities"]:
        activity_id = activity["activity_id"]
        rows["activities"].append({
            "bundle_digest": bundle_digest,
            "activity_id": activity_id,
            "activity_type": activity["activity_type"],
            "started_at": activity["started_at"],
            "ended_at": activity["ended_at"],
            "method_ref": activity["method_ref"],
            "parameters_digest": activity["parameters_digest"],
        })
        acquisition = activity["acquisition"]
        if acquisition is not None:
            rows["activity_acquisitions"].append({
                "bundle_digest": bundle_digest,
                "activity_id": activity_id,
                **acquisition,
            })
        for agent_id in activity["agent_ids"]:
            rows["activity_agents"].append({
                "bundle_digest": bundle_digest,
                "activity_id": activity_id,
                "agent_id": agent_id,
            })
        for entity_id in activity["used_entity_ids"]:
            rows["activity_used_entities"].append({
                "bundle_digest": bundle_digest,
                "activity_id": activity_id,
                "entity_id": entity_id,
            })
        for entity_id in activity["generated_entity_ids"]:
            rows["activity_generated_entities"].append({
                "bundle_digest": bundle_digest,
                "activity_id": activity_id,
                "entity_id": entity_id,
            })

    for event in bundle["events"]:
        event_id = event["event_id"]
        rows["events"].append({
            "bundle_digest": bundle_digest,
            "event_id": event_id,
            "event_type": event["event_type"],
            "occurred_start": event["occurred_start"],
            "occurred_end": event["occurred_end"],
        })
        for subject_id in event["subject_ids"]:
            if subject_id in agent_ids:
                subject_kind = "agent"
            elif subject_id in entity_ids:
                subject_kind = "entity"
            else:
                raise ValueError(f"event subject {subject_id} is neither agent nor entity")
            rows["event_subjects"].append({
                "bundle_digest": bundle_digest,
                "event_id": event_id,
                "subject_id": subject_id,
                "subject_kind": subject_kind,
            })
        for attribute in event["attributes"]:
            rows["event_attributes"].append({
                "bundle_digest": bundle_digest,
                "event_id": event_id,
                "attribute_name": attribute["name"],
                "value_json": attribute["value"],
            })
        for citation_id in event["citation_ids"]:
            rows["event_citations"].append({
                "bundle_digest": bundle_digest,
                "event_id": event_id,
                "citation_id": citation_id,
            })

    for citation in bundle["citations"]:
        rows["citations"].append({
            "bundle_digest": bundle_digest,
            **citation,
        })

    for anchor in bundle["integrity_anchors"]:
        rows["integrity_anchors"].append({
            "bundle_digest": bundle_digest,
            "anchor_id": anchor["anchor_id"],
            "anchor_type": anchor["anchor_type"],
            "subject_digest": anchor["subject_digest"],
            "proof_digest": anchor["proof_digest"],
            "observed_at": anchor["observed_at"],
            "provider": anchor["provider"],
            "reference": anchor["reference"],
        })
        rows["anchor_verification"].append({
            "bundle_digest": bundle_digest,
            "anchor_id": anchor["anchor_id"],
            **anchor["verification"],
        })

    return {
        table: _sort_rows(rows[table])
        for table in sorted(rows)
    }


def relational_rowset_digest(rows: dict[str, list[dict[str, Any]]]) -> str:
    normalized = {
        table: _sort_rows(list(rows.get(table, [])))
        for table in sorted(TABLES)
    }
    return canonical_digest(normalized)


def _node_id(kind: str, bundle_digest: str, source_id: str) -> str:
    return f"{kind.lower()}:{bundle_digest}:{source_id}"


def _properties(**values: object) -> list[dict[str, Any]]:
    return [
        {"name": key, "value": value}
        for key, value in sorted(values.items())
        if isinstance(value, (str, int, bool)) or value is None
    ]


def _edge(
    edge_type: str,
    from_node_id: str,
    to_node_id: str,
) -> dict[str, str]:
    digest = hashlib.sha256(
        f"{edge_type}\x00{from_node_id}\x00{to_node_id}".encode("utf-8")
    ).hexdigest()
    return {
        "edge_id": f"edge:{digest}",
        "edge_type": edge_type,
        "from_node_id": from_node_id,
        "to_node_id": to_node_id,
    }


def property_graph_projection(
    bundle: dict[str, Any],
    registry: dict[str, Any],
) -> dict[str, Any]:
    registry_errors = validate_registry(registry)
    if registry_errors:
        raise ValueError("invalid observatory data registry: " + "; ".join(registry_errors))
    evidence_errors = observatory_evidence.validate_bundle(bundle)
    if evidence_errors:
        raise ValueError("invalid evidence bundle: " + "; ".join(evidence_errors))

    bundle_digest = bundle["bundle_digest"]
    bundle_node = f"bundle:{bundle_digest}"
    nodes: list[dict[str, Any]] = [{
        "node_id": bundle_node,
        "node_type": "Bundle",
        "source_id": bundle_digest,
        "properties": _properties(
            bundle_id=bundle["bundle_id"],
            revision=bundle["revision"],
            manifest_digest=bundle["manifest_digest"],
            created_at=bundle["created_at"],
        ),
    }]
    edges: list[dict[str, str]] = []

    if bundle["previous_bundle_digest"] is not None:
        previous_node = f"bundle:{bundle['previous_bundle_digest']}"
        nodes.append({
            "node_id": previous_node,
            "node_type": "Bundle",
            "source_id": bundle["previous_bundle_digest"],
            "properties": _properties(external=True),
        })
        edges.append(_edge("PREVIOUS_BUNDLE", bundle_node, previous_node))

    node_by_source: dict[tuple[str, str], str] = {}
    entity_nodes_by_digest: dict[str, list[str]] = {}

    for agent in bundle["agents"]:
        node_id = _node_id("agent", bundle_digest, agent["agent_id"])
        node_by_source[("Agent", agent["agent_id"])] = node_id
        nodes.append({
            "node_id": node_id,
            "node_type": "Agent",
            "source_id": agent["agent_id"],
            "properties": _properties(
                agent_type=agent["agent_type"],
                name=agent["name"],
                version=agent["version"],
                identity_ref=agent["identity_ref"],
            ),
        })
        edges.append(_edge("CONTAINS", bundle_node, node_id))

    for entity in bundle["entities"]:
        node_id = _node_id("entity", bundle_digest, entity["entity_id"])
        node_by_source[("Entity", entity["entity_id"])] = node_id
        entity_nodes_by_digest.setdefault(entity["content_digest"], []).append(node_id)
        nodes.append({
            "node_id": node_id,
            "node_type": "Entity",
            "source_id": entity["entity_id"],
            "properties": _properties(
                entity_type=entity["entity_type"],
                content_digest=entity["content_digest"],
                media_type=entity["media_type"],
                source_uri=entity["source_uri"],
                source_identifier=entity["source_identifier"],
                acquired_at=entity["acquired_at"],
            ),
        })
        edges.append(_edge("CONTAINS", bundle_node, node_id))

    for activity in bundle["activities"]:
        node_id = _node_id("activity", bundle_digest, activity["activity_id"])
        node_by_source[("Activity", activity["activity_id"])] = node_id
        nodes.append({
            "node_id": node_id,
            "node_type": "Activity",
            "source_id": activity["activity_id"],
            "properties": _properties(
                activity_type=activity["activity_type"],
                started_at=activity["started_at"],
                ended_at=activity["ended_at"],
                method_ref=activity["method_ref"],
                parameters_digest=activity["parameters_digest"],
            ),
        })
        edges.append(_edge("CONTAINS", bundle_node, node_id))

    for event in bundle["events"]:
        node_id = _node_id("event", bundle_digest, event["event_id"])
        node_by_source[("Event", event["event_id"])] = node_id
        nodes.append({
            "node_id": node_id,
            "node_type": "Event",
            "source_id": event["event_id"],
            "properties": _properties(
                event_type=event["event_type"],
                occurred_start=event["occurred_start"],
                occurred_end=event["occurred_end"],
            ),
        })
        edges.append(_edge("CONTAINS", bundle_node, node_id))

    for citation in bundle["citations"]:
        node_id = _node_id("citation", bundle_digest, citation["citation_id"])
        node_by_source[("Citation", citation["citation_id"])] = node_id
        nodes.append({
            "node_id": node_id,
            "node_type": "Citation",
            "source_id": citation["citation_id"],
            "properties": _properties(
                locator_kind=citation["locator_kind"],
                locator_value=citation["locator_value"],
                excerpt_digest=citation["excerpt_digest"],
                note=citation["note"],
            ),
        })
        edges.append(_edge("CONTAINS", bundle_node, node_id))

    for anchor in bundle["integrity_anchors"]:
        node_id = _node_id("anchor", bundle_digest, anchor["anchor_id"])
        node_by_source[("IntegrityAnchor", anchor["anchor_id"])] = node_id
        nodes.append({
            "node_id": node_id,
            "node_type": "IntegrityAnchor",
            "source_id": anchor["anchor_id"],
            "properties": _properties(
                anchor_type=anchor["anchor_type"],
                subject_digest=anchor["subject_digest"],
                proof_digest=anchor["proof_digest"],
                observed_at=anchor["observed_at"],
                provider=anchor["provider"],
                reference=anchor["reference"],
                verification_status=anchor["verification"]["status"],
            ),
        })
        edges.append(_edge("CONTAINS", bundle_node, node_id))

    for activity in bundle["activities"]:
        activity_node = node_by_source[("Activity", activity["activity_id"])]
        for entity_id in activity["used_entity_ids"]:
            edges.append(_edge(
                "USED",
                activity_node,
                node_by_source[("Entity", entity_id)],
            ))
        for entity_id in activity["generated_entity_ids"]:
            edges.append(_edge(
                "WAS_GENERATED_BY",
                node_by_source[("Entity", entity_id)],
                activity_node,
            ))
        for agent_id in activity["agent_ids"]:
            edges.append(_edge(
                "WAS_ASSOCIATED_WITH",
                activity_node,
                node_by_source[("Agent", agent_id)],
            ))

    for entity in bundle["entities"]:
        previous = entity["revision_of"]
        if previous is not None:
            edges.append(_edge(
                "WAS_DERIVED_FROM",
                node_by_source[("Entity", entity["entity_id"])],
                node_by_source[("Entity", previous)],
            ))

    agent_ids = {agent["agent_id"] for agent in bundle["agents"]}
    for event in bundle["events"]:
        event_node = node_by_source[("Event", event["event_id"])]
        for citation_id in event["citation_ids"]:
            edges.append(_edge(
                "CITES",
                event_node,
                node_by_source[("Citation", citation_id)],
            ))
        for subject_id in event["subject_ids"]:
            kind = "Agent" if subject_id in agent_ids else "Entity"
            edges.append(_edge(
                "HAS_SUBJECT",
                event_node,
                node_by_source[(kind, subject_id)],
            ))

    for citation in bundle["citations"]:
        edges.append(_edge(
            "CITATION_SOURCE",
            node_by_source[("Citation", citation["citation_id"])],
            node_by_source[("Entity", citation["entity_id"])],
        ))

    for anchor in bundle["integrity_anchors"]:
        anchor_node = node_by_source[("IntegrityAnchor", anchor["anchor_id"])]
        if anchor["subject_digest"] == bundle["manifest_digest"]:
            edges.append(_edge("ANCHORS", anchor_node, bundle_node))
        for entity_node in entity_nodes_by_digest.get(anchor["subject_digest"], []):
            edges.append(_edge("ANCHORS", anchor_node, entity_node))

    unique_nodes = {node["node_id"]: node for node in nodes}
    unique_edges = {edge["edge_id"]: edge for edge in edges}
    return {
        "schema_version": "0.1",
        "projection_version": PROJECTION_VERSION,
        "source_bundle_digest": bundle_digest,
        "nodes": sorted(unique_nodes.values(), key=canonical_bytes),
        "edges": sorted(unique_edges.values(), key=canonical_bytes),
    }


def _uri(kind: str, bundle_digest: str, source_id: str) -> str:
    safe_bundle = bundle_digest.replace(":", "-")
    return f"urn:e2eesa:{kind}:{safe_bundle}:{source_id}"


def prov_rdf_projection(
    bundle: dict[str, Any],
    registry: dict[str, Any],
) -> dict[str, Any]:
    registry_errors = validate_registry(registry)
    if registry_errors:
        raise ValueError("invalid observatory data registry: " + "; ".join(registry_errors))
    evidence_errors = observatory_evidence.validate_bundle(bundle)
    if evidence_errors:
        raise ValueError("invalid evidence bundle: " + "; ".join(evidence_errors))

    digest = bundle["bundle_digest"]
    triples: set[tuple[str, str, str]] = set()

    agent_uri = {
        agent["agent_id"]: _uri("agent", digest, agent["agent_id"])
        for agent in bundle["agents"]
    }
    entity_uri = {
        entity["entity_id"]: _uri("entity", digest, entity["entity_id"])
        for entity in bundle["entities"]
    }
    activity_uri = {
        activity["activity_id"]: _uri("activity", digest, activity["activity_id"])
        for activity in bundle["activities"]
    }
    event_uri = {
        event["event_id"]: _uri("event", digest, event["event_id"])
        for event in bundle["events"]
    }
    citation_uri = {
        citation["citation_id"]: _uri("citation", digest, citation["citation_id"])
        for citation in bundle["citations"]
    }

    for uri in agent_uri.values():
        triples.add((uri, RDF + "type", PROV + "Agent"))
    for uri in entity_uri.values():
        triples.add((uri, RDF + "type", PROV + "Entity"))
    for uri in activity_uri.values():
        triples.add((uri, RDF + "type", PROV + "Activity"))
    for uri in event_uri.values():
        triples.add((uri, RDF + "type", E2EESA + "Event"))
    for uri in citation_uri.values():
        triples.add((uri, RDF + "type", E2EESA + "Citation"))

    for activity in bundle["activities"]:
        a_uri = activity_uri[activity["activity_id"]]
        for entity_id in activity["used_entity_ids"]:
            triples.add((a_uri, PROV + "used", entity_uri[entity_id]))
        for entity_id in activity["generated_entity_ids"]:
            triples.add((entity_uri[entity_id], PROV + "wasGeneratedBy", a_uri))
        for agent_id in activity["agent_ids"]:
            triples.add((a_uri, PROV + "wasAssociatedWith", agent_uri[agent_id]))

    for entity in bundle["entities"]:
        if entity["revision_of"] is not None:
            triples.add((
                entity_uri[entity["entity_id"]],
                PROV + "wasDerivedFrom",
                entity_uri[entity["revision_of"]],
            ))

    agent_ids = set(agent_uri)
    for event in bundle["events"]:
        e_uri = event_uri[event["event_id"]]
        for citation_id in event["citation_ids"]:
            triples.add((e_uri, E2EESA + "cites", citation_uri[citation_id]))
        for subject_id in event["subject_ids"]:
            object_uri = (
                agent_uri[subject_id] if subject_id in agent_ids else entity_uri[subject_id]
            )
            triples.add((e_uri, E2EESA + "hasSubject", object_uri))

    for citation in bundle["citations"]:
        triples.add((
            citation_uri[citation["citation_id"]],
            E2EESA + "citationSource",
            entity_uri[citation["entity_id"]],
        ))

    return {
        "schema_version": "0.1",
        "projection_version": PROJECTION_VERSION,
        "source_bundle_digest": digest,
        "triples": [
            {"subject": subject, "predicate": predicate, "object": obj}
            for subject, predicate, obj in sorted(triples)
        ],
    }


def _facets(**values: object) -> list[dict[str, Any]]:
    return [
        {"name": key, "value": value}
        for key, value in sorted(values.items())
        if isinstance(value, (str, int, bool)) or value is None
    ]


def search_projection(
    bundle: dict[str, Any],
    registry: dict[str, Any],
) -> dict[str, Any]:
    registry_errors = validate_registry(registry)
    if registry_errors:
        raise ValueError("invalid observatory data registry: " + "; ".join(registry_errors))
    evidence_errors = observatory_evidence.validate_bundle(bundle)
    if evidence_errors:
        raise ValueError("invalid evidence bundle: " + "; ".join(evidence_errors))

    digest = bundle["bundle_digest"]
    entity_by_id = {entity["entity_id"]: entity for entity in bundle["entities"]}
    documents: list[dict[str, Any]] = []

    for agent in bundle["agents"]:
        body = " ".join(
            value
            for value in (
                agent["name"],
                agent["version"],
                agent["identity_ref"],
            )
            if isinstance(value, str)
        )
        documents.append({
            "document_id": _node_id("search-agent", digest, agent["agent_id"]),
            "record_type": "agent",
            "source_id": agent["agent_id"],
            "title": agent["name"],
            "body": body,
            "facets": _facets(agent_type=agent["agent_type"]),
            "digests": [],
        })

    for entity in bundle["entities"]:
        title = entity["source_identifier"] or entity["entity_id"]
        body = " ".join(
            value
            for value in (
                entity["entity_type"],
                entity["media_type"],
                entity["source_identifier"],
                entity["source_uri"],
                entity["content_uri"],
            )
            if isinstance(value, str)
        )
        documents.append({
            "document_id": _node_id("search-entity", digest, entity["entity_id"]),
            "record_type": "entity",
            "source_id": entity["entity_id"],
            "title": title,
            "body": body,
            "facets": _facets(
                entity_type=entity["entity_type"],
                media_type=entity["media_type"],
            ),
            "digests": [entity["content_digest"]],
        })

    for event in bundle["events"]:
        attribute_text = " ".join(
            f"{item['name']}={item['value']}"
            for item in sorted(event["attributes"], key=canonical_bytes)
        )
        body = " ".join(
            value
            for value in (
                event["event_type"],
                event["occurred_start"],
                event["occurred_end"],
                attribute_text or None,
            )
            if isinstance(value, str)
        )
        documents.append({
            "document_id": _node_id("search-event", digest, event["event_id"]),
            "record_type": "event",
            "source_id": event["event_id"],
            "title": event["event_type"],
            "body": body,
            "facets": _facets(event_type=event["event_type"]),
            "digests": [],
        })

    for citation in bundle["citations"]:
        entity = entity_by_id[citation["entity_id"]]
        body = " ".join(
            value
            for value in (
                citation["locator_kind"],
                citation["locator_value"],
                citation["note"],
                entity["source_identifier"],
                entity["source_uri"],
            )
            if isinstance(value, str)
        )
        digests = [entity["content_digest"]]
        if citation["excerpt_digest"] is not None:
            digests.append(citation["excerpt_digest"])
        documents.append({
            "document_id": _node_id("search-citation", digest, citation["citation_id"]),
            "record_type": "citation",
            "source_id": citation["citation_id"],
            "title": f"Citation {citation['locator_value']}",
            "body": body,
            "facets": _facets(locator_kind=citation["locator_kind"]),
            "digests": sorted(set(digests)),
        })

    return {
        "schema_version": "0.1",
        "projection_version": PROJECTION_VERSION,
        "source_bundle_digest": digest,
        "documents": sorted(documents, key=canonical_bytes),
    }


def projection_manifest_core(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        key: manifest.get(key)
        for key in (
            "schema_version",
            "source_bundle_digest",
            "relational_model_version",
            "relational_rowset_digest",
            "row_counts",
            "projections",
        )
    }


def projection_manifest_digest(manifest: dict[str, Any]) -> str:
    return canonical_digest(projection_manifest_core(manifest))


def build_projection_manifest(
    bundle: dict[str, Any],
    registry: dict[str, Any],
    generated_at: str,
) -> dict[str, Any]:
    datetime.strptime(generated_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)

    rows = relational_rows(bundle)
    graph = property_graph_projection(bundle, registry)
    rdf = prov_rdf_projection(bundle, registry)
    search = search_projection(bundle, registry)

    manifest = {
        "schema_version": "0.1",
        "source_bundle_digest": bundle["bundle_digest"],
        "relational_model_version": RELATIONAL_MODEL_VERSION,
        "relational_rowset_digest": relational_rowset_digest(rows),
        "row_counts": [
            {"table": table, "count": len(rows[table])}
            for table in sorted(rows)
        ],
        "projections": [
            {
                "projection_id": "property-graph",
                "projection_version": PROJECTION_VERSION,
                "projection_digest": canonical_digest(graph),
                "item_count": len(graph["nodes"]) + len(graph["edges"]),
            },
            {
                "projection_id": "prov-rdf",
                "projection_version": PROJECTION_VERSION,
                "projection_digest": canonical_digest(rdf),
                "item_count": len(rdf["triples"]),
            },
            {
                "projection_id": "search-documents",
                "projection_version": PROJECTION_VERSION,
                "projection_digest": canonical_digest(search),
                "item_count": len(search["documents"]),
            },
        ],
        "generated_at": generated_at,
        "manifest_digest": "",
    }
    manifest["projections"] = sorted(
        manifest["projections"], key=lambda item: item["projection_id"]
    )
    manifest["manifest_digest"] = projection_manifest_digest(manifest)
    return manifest


def validate_projection_set(
    bundle: dict[str, Any],
    registry: dict[str, Any],
    rows: dict[str, list[dict[str, Any]]],
    graph: dict[str, Any],
    rdf: dict[str, Any],
    search: dict[str, Any],
    manifest: dict[str, Any],
) -> list[str]:
    errors = validate_registry(registry)
    evidence_errors = observatory_evidence.validate_bundle(bundle)
    errors.extend("evidence bundle: " + error for error in evidence_errors)
    if errors:
        return sorted(set(errors))

    expected_rows = relational_rows(bundle)
    if canonical_bytes(rows) != canonical_bytes(expected_rows):
        errors.append("relational projection differs from canonical bundle")

    expected_graph = property_graph_projection(bundle, registry)
    if canonical_bytes(graph) != canonical_bytes(expected_graph):
        errors.append("property graph projection differs from canonical bundle")

    expected_rdf = prov_rdf_projection(bundle, registry)
    if canonical_bytes(rdf) != canonical_bytes(expected_rdf):
        errors.append("PROV RDF projection differs from canonical bundle")

    expected_search = search_projection(bundle, registry)
    if canonical_bytes(search) != canonical_bytes(expected_search):
        errors.append("search projection differs from canonical bundle")

    if manifest.get("source_bundle_digest") != bundle["bundle_digest"]:
        errors.append("projection manifest source_bundle_digest mismatch")
    if manifest.get("relational_model_version") != RELATIONAL_MODEL_VERSION:
        errors.append("projection manifest relational_model_version mismatch")
    if manifest.get("relational_rowset_digest") != relational_rowset_digest(expected_rows):
        errors.append("projection manifest relational_rowset_digest mismatch")

    expected_counts = [
        {"table": table, "count": len(expected_rows[table])}
        for table in sorted(expected_rows)
    ]
    if manifest.get("row_counts") != expected_counts:
        errors.append("projection manifest row_counts mismatch")

    expected_projection_items = {
        "property-graph": (
            canonical_digest(expected_graph),
            len(expected_graph["nodes"]) + len(expected_graph["edges"]),
        ),
        "prov-rdf": (
            canonical_digest(expected_rdf),
            len(expected_rdf["triples"]),
        ),
        "search-documents": (
            canonical_digest(expected_search),
            len(expected_search["documents"]),
        ),
    }
    projections = manifest.get("projections")
    if not isinstance(projections, list):
        errors.append("projection manifest projections must be an array")
    else:
        seen: set[str] = set()
        for item in projections:
            if not isinstance(item, dict):
                errors.append("projection manifest entry must be an object")
                continue
            projection_id = item.get("projection_id")
            if projection_id in seen:
                errors.append(f"projection manifest duplicate projection {projection_id}")
            seen.add(str(projection_id))
            expected = expected_projection_items.get(projection_id)
            if expected is None:
                errors.append(f"projection manifest unknown projection {projection_id}")
                continue
            expected_digest, expected_count = expected
            if item.get("projection_version") != PROJECTION_VERSION:
                errors.append(f"projection manifest {projection_id} version mismatch")
            if item.get("projection_digest") != expected_digest:
                errors.append(f"projection manifest {projection_id} digest mismatch")
            if item.get("item_count") != expected_count:
                errors.append(f"projection manifest {projection_id} item_count mismatch")
        if seen != set(expected_projection_items):
            errors.append("projection manifest projection set mismatch")

    generated_at = manifest.get("generated_at")
    if not isinstance(generated_at, str):
        errors.append("projection manifest generated_at must be a UTC timestamp")
    else:
        try:
            datetime.strptime(generated_at, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            errors.append("projection manifest generated_at must use YYYY-MM-DDTHH:MM:SSZ")

    if manifest.get("manifest_digest") != projection_manifest_digest(manifest):
        errors.append("projection manifest digest mismatch")

    return sorted(set(errors))
