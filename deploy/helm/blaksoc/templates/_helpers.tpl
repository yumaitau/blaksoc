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
