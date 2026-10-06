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
