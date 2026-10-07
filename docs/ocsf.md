# OCSF event schema

blakSOC's canonical event schema is [OCSF](https://schema.ocsf.io) (Open Cybersecurity Schema Framework). The code is in `src/lib/ocsf`:

| File | Purpose |
| --- | --- |
| `schema.ts` | Typed subset of OCSF 1.9.0: class ids, enums, and the objects blakSOC writes |
| `map.ts` | Mappers from blakSOC's provider-neutral records to OCSF events |
| `validate.ts` | Checks required attributes, object constraints and derived ids before anything is stored |

Class ids, enums and required attributes were checked against the OCSF schema server (`https://schema.ocsf.io/api`, version 1.9.0, no profiles).

## Classes

| OCSF class | `class_uid` | Written from | Stored in |
| --- | --- | --- | --- |
| Detection Finding | 2004 | Every alert that goes through `ingestAlert`, from any provider | `alerts.ocsf` |
| Network Activity | 4001 | Firewall syslog lines (FortiGate, Sophos, DrayTek, MikroTik, UniFi) | `alerts.ocsf_source_event` |
| Authentication | 3002 | Microsoft Entra sign-in records behind an alert | `alerts.ocsf_source_event` |
| Vulnerability Finding | 2002 | `NormalisedVulnerability` (`toVulnerabilityFinding`) | Mapper only; not stored yet |
| Base Event | 0 | Records read in place that have no activity mapper (`toBaseEvent`), e.g. a Wazuh archive record without a rule | Not stored; search results only |

`ocsf_source_event` holds the record an alert was raised from, in its own activity class, when blakSOC understands that record. Other alerts have only the Detection Finding.

Event search (`SecurityDataProvider`, see [ARCHITECTURE.md](ARCHITECTURE.md#query-in-place-search)) returns the same OCSF shapes for records it reads in place, built by the same mappers: Wazuh records as Detection Findings, syslog lines as Network Activity. For those results `metadata.logged_time` is the source's own receive time (indexer `timestamp`, syslog receive time), since blakSOC did not ingest them.

Process Activity (1007) is declared in `OCSF_CLASSES` but has no mapper yet.

## Provenance

Every event carries where it came from and when blakSOC received it, in OCSF `metadata`:

| Provenance | OCSF attribute | Alert column |
| --- | --- | --- |
| source | `metadata.log_name`, `metadata.product` | `source` |
| source event id | `metadata.original_event_uid` | `external_id` |
| tenant | `metadata.tenant_uid` | `tenant_id` |
| event time | `time` | `occurred_at` |
| ingestion time | `metadata.logged_time` | `ingested_at` |
| normalisation version | `metadata.transformation_info_list[0].uid` | `normalization_version` |
| raw reference | not copied into the event | `raw` |

The vendor payload stays in `alerts.raw`. OCSF `raw_data` is not filled, so the raw record is stored once and stays subject to the existing raw-payload rules (for example, it is stripped before AI unless the tenant allows it).

## Versions

- `OCSF_VERSION` is the OCSF schema version written to `metadata.version`.
- `NORMALIZATION_VERSION` (`blaksoc-ocsf/1`) identifies the mapper. Bump it when a mapper changes what it writes, so stored events can be told apart and re-normalised from `raw`.

## Failure handling

Ingest validates each event before storing it. A Detection Finding that fails validation is logged and not stored, and `normalization_version` stays null. The alert itself is never blocked by OCSF mapping. A source event that fails validation is dropped on its own.

Alerts ingested before migration `0024_alert_ocsf`, and alerts written outside `ingestAlert` (health and backup alerts), have no OCSF record yet.

## Adding a mapper

1. Add the class and any new objects or enums to `schema.ts`, checked against the OCSF schema server.
2. Add its required attributes and constraints to `validate.ts`.
3. Write the mapper in `map.ts`, taking a `Provenance` and building metadata with `ocsfMetadata()`.
4. Test it against a real fixture in `tests/unit/ocsf.test.ts`, including `validateOcsf`.
5. Bump `NORMALIZATION_VERSION` if existing output changes.
