{{- define "blaksoc.fullname" -}}{{ .Release.Name }}-blaksoc{{- end -}}
{{- define "blaksoc.labels" -}}
app.kubernetes.io/name: blaksoc
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
{{- define "blaksoc.image" -}}{{ .root.Values.image.repository }}-{{ .target }}:{{ .root.Values.image.tag | default .root.Chart.AppVersion }}{{- end -}}
{{- define "blaksoc.env" -}}
- name: NODE_ENV
  value: production
- name: APP_URL
  value: {{ .Values.appUrl | quote }}
{{- range $k, $v := .Values.config }}
- name: {{ $k }}
  value: {{ $v | quote }}
{{- end }}
- name: LOG_LEVEL
  value: {{ .Values.observability.logLevel | quote }}
{{- if .Values.observability.metrics.enabled }}
- name: METRICS_PORT
  value: {{ .Values.observability.metrics.port | quote }}
{{- end }}
{{- with .Values.observability.otlpEndpoint }}
- name: OTEL_EXPORTER_OTLP_ENDPOINT
  value: {{ . | quote }}
{{- end }}
{{- end -}}

{{/* Metrics container port for web and worker. */}}
{{- define "blaksoc.metricsPort" -}}
{{- if .Values.observability.metrics.enabled }}, { name: metrics, containerPort: {{ .Values.observability.metrics.port }} }{{ end -}}
{{- end -}}

{{/* NetworkPolicy ingress rule admitting the scraper to the metrics port. */}}
{{- define "blaksoc.metricsIngress" -}}
{{- if .Values.observability.metrics.enabled }}
    - from:
        - namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: {{ .Values.observability.metrics.scrapeNamespace }} } }
      ports: [{ port: {{ .Values.observability.metrics.port }} }]
{{- end }}
{{- end -}}

{{/* Secret keys for web and worker. The migration job uses envFrom with the whole Secret. */}}
{{- define "blaksoc.secretEnv" -}}
{{- $secret := .Values.existingSecret }}
{{- range .Values.runtimeSecretKeys.required }}
- name: {{ . }}
  valueFrom: { secretKeyRef: { name: {{ $secret }}, key: {{ . }} } }
{{- end }}
{{- range .Values.runtimeSecretKeys.optional }}
- name: {{ . }}
  valueFrom: { secretKeyRef: { name: {{ $secret }}, key: {{ . }}, optional: true } }
{{- end }}
{{- end -}}

{{/* Egress shared by the web and worker NetworkPolicies. See networkpolicy.yaml. */}}
{{- define "blaksoc.egress" }}
  egress:
    - to: [{ namespaceSelector: {} }]
    {{- if .Values.networkPolicy.publicHttps }}
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10, 127.0.0.0/8]
        - ipBlock:
            cidr: ::/0
            except: ["fc00::/7", "fe80::/10", "::1/128", "fd00:ec2::/32"]
      ports: [{ protocol: TCP, port: 443 }]
    {{- end }}
    {{- if .Values.networkPolicy.egressCidrs }}
    - to:
      {{- range .Values.networkPolicy.egressCidrs }}
        - ipBlock: { cidr: {{ . | quote }} }
      {{- end }}
    {{- end }}
{{- end }}

{{/* Archive and backup regions must be Australian (src/lib/syslog/retain.ts AU_ARCHIVE_REGIONS). */}}
{{- define "blaksoc.assertAuRegion" -}}
{{- if not (has .region (list "ap-southeast-2" "ap-southeast-4")) }}
{{- fail (printf "%s must be ap-southeast-2 or ap-southeast-4, got %q" .what .region) }}
{{- end }}
{{- end -}}

{{/* Durable archive env, worker only. No buckets: the file store on the /tmp emptyDir (dev only). */}}
{{- define "blaksoc.archiveEnv" -}}
{{- $s3 := .Values.archive.s3 }}
{{- if $s3.buckets }}
{{- $pairs := list }}
{{- range $region, $bucket := $s3.buckets }}
{{- include "blaksoc.assertAuRegion" (dict "what" "archive.s3.buckets key" "region" $region) }}
{{- $pairs = append $pairs (printf "%s=%s" $region $bucket) }}
{{- end }}
- name: BLAKSOC_ARCHIVE_S3_BUCKETS
  value: {{ join "," $pairs | quote }}
- name: BLAKSOC_ARCHIVE_S3_SSE
  value: {{ $s3.sse | default "AES256" | quote }}
{{- with $s3.kmsKeyId }}
- name: BLAKSOC_ARCHIVE_S3_KMS_KEY_ID
  value: {{ . | quote }}
{{- end }}
{{- with $s3.endpoint }}
- name: BLAKSOC_ARCHIVE_S3_ENDPOINT
  value: {{ . | quote }}
{{- end }}
{{- if ne (toString $s3.forcePathStyle) "" }}
- name: BLAKSOC_ARCHIVE_S3_FORCE_PATH_STYLE
  value: {{ toString $s3.forcePathStyle | quote }}
{{- end }}
- name: BLAKSOC_ARCHIVE_S3_ACCESS_KEY_ID
  valueFrom: { secretKeyRef: { name: {{ .Values.existingSecret }}, key: BLAKSOC_ARCHIVE_S3_ACCESS_KEY_ID, optional: true } }
- name: BLAKSOC_ARCHIVE_S3_SECRET_ACCESS_KEY
  valueFrom: { secretKeyRef: { name: {{ .Values.existingSecret }}, key: BLAKSOC_ARCHIVE_S3_SECRET_ACCESS_KEY, optional: true } }
{{- end }}
{{- end -}}

{{- define "blaksoc.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}{{ .Values.serviceAccount.name | default (include "blaksoc.fullname" .) }}{{ else }}{{ .Values.serviceAccount.name | default "default" }}{{ end }}
{{- end -}}
