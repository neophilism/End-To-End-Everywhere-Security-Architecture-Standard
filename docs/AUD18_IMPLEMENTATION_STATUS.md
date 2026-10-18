# AUD-18.1 — Construction-specific hybrid claims and lifecycle

The new reference evaluator checks the three RFC 10024 TLS group selections against exact traditional/PQ algorithms, the RFC 9954 combiner identity, allowed component lifecycles, downgrade rejection, and a separately supplied authenticated transcript/group anchor.

Component lifecycle status and hybrid combiner security are **different questions**. A construction-specific confidentiality claim is not automatically a claim about authentication, group message protection, arbitrary KEM pairs, or every attack model. A mathematically robust construction does not override a prohibited component's lifecycle status.

The evaluator returns `consistent` only, **never cryptographically verified or certified**. Real combiner/side-channel security, authenticated transcript-provider evidence, exact external standard pins, signing profiles, SBOM compatibility, fuzzing and cross-implementation tests remain unfinished AUD-18 work.
