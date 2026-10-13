/** Fictional data only; matches Wedgetail's documented summary and generic webhook. */
export const WEDGETAIL_V1 = {
  schema: "wedgetail.alert.v1",
  alert: {
    id: "wt-fictional-root-activity", title: "Root user activity", ruleId: "WT-AWS-001", severity: "high",
    description: "Root activity in account 111122223333. MITRE T1078.004. ISM ISM-1509. Essential Eight multi-factor authentication.",
    classification: "T1078.004", detectedAt: "2026-09-01T01:02:03.000Z", url: "https://wedgetail.example.com/alerts/wt-fictional-root-activity",
  },
  tenant: { id: "111122223333" }, product: { vendor: "Yuma IT", name: "Wedgetail" },
  entities: { principal: "arn:aws:iam::111122223333:root", ip: "203.0.113.10", resource: "arn:aws:s3:::fictional-example", account: "111122223333", model: null, domain: "example.com", host: "aws-example" },
};

export const WEDGETAIL_CREATED = {
  type: "wedgetail.alert.created",
  alert: {
    id: WEDGETAIL_V1.alert.id, ruleId: "WT-AWS-001", ruleTitle: "Root user activity", severity: "high", status: "new",
    firstSeen: WEDGETAIL_V1.alert.detectedAt, updatedAt: "2026-09-01T01:03:03.000Z", accountId: "111122223333", region: "ap-southeast-2", eventCount: 1,
    entities: [{ type: "principal", value: WEDGETAIL_V1.entities.principal }, { type: "ip", value: "198.51.100.10" }, { type: "resource", value: WEDGETAIL_V1.entities.resource }, { type: "host", value: "aws-example" }],
    mitre: ["T1078.004"], ism: ["ISM-1509"], essentialEight: ["multi-factor-authentication"],
  },
  url: WEDGETAIL_V1.alert.url,
};
