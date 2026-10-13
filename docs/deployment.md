# Production deployment from GitHub

Pushing to `main` starts `ci`, `security` and `codeql`. When `ci` completes successfully,
`.github/workflows/deploy.yml` checks all three workflows on that exact commit. It accepts only
push runs from this repository's `main` branch; PR, fork and scheduled checks cannot authorize a
release. A newer `main` commit supersedes an older pending release.

After the gate passes, GitHub builds and publishes `blaksoc-web`, `blaksoc-worker` and `blaksoc-hermes`
to account `959038055523` in `ap-southeast-2`, using the first 12 characters of the commit SHA.
The ECR repositories enforce immutable tags. A retry reuses images already published under that
tag, then repeats the release gate before deployment. Helm runs the database migration/seed hook,
upgrades `blaksoc` in the `blaksoc` namespace of `yumait-prod`, waits for readiness and rolls back
on upgrade failure. The workflow then checks the public health endpoint. Hermes uses the new image
on its next scheduled run.

Deployments are serialized and an in-progress Helm upgrade is never cancelled by a new push.
The Actions workflow can also be dispatched manually on `main` to retry the current release;
manual runs have the same checks and cannot deploy arbitrary refs. The existing version-tagged
GHCR release workflow is independent.

## Authentication and bootstrap

Stack `blaksoc-github` is defined in `deploy/aws/github-deploy.yaml`. It reuses the account's GitHub
OIDC provider and creates two roles:

- `blaksoc-github-publish`: ECR authentication plus push/read of only the three blakSOC repositories.
- `blaksoc-github-deploy`: describe only `yumait-prod`, with an EKS access entry mapped to
  `blaksoc:github-deploy`. Its Kubernetes Role/RoleBinding are in `deploy/aws/github-deploy-rbac.yaml`.

The namespace role manages the resource kinds used by the production chart and reads Helm release
secrets. This necessarily grants access to application secrets in that namespace. It cannot change
RBAC, exec into pods, or access other namespaces. Infrastructure, Cognito, IAM, cluster configuration
and the bootstrap Role/RoleBinding stay outside the app deployment workflow.

Both IAM roles require audience `sts.amazonaws.com` and the exact immutable GitHub subject
`repo:yumaitau@165281358/blaksoc@1393930999:environment:production`. The GitHub `production`
environment permits only the `main` branch, with no manual approval gate. Verify the subject using
`gh api repos/yumaitau/blaksoc/actions/oidc/customization/sub` if the repository moves or is renamed.

Repository variables `AWS_PUBLISH_ROLE_ARN` and `AWS_DEPLOY_ROLE_ARN` hold the corresponding stack
outputs. They are identifiers, not secrets. GitHub exchanges its OIDC token for short-lived AWS
sessions; never add administrator keys, runtime secrets, or a static kubeconfig to the repository.

For a new cluster/account, an administrator must first review and deploy the CloudFormation stack,
apply the RBAC manifest, configure the environment's branch policy and set the two variables.
Creating the workflow alone does not provision this access.

## Recovery and verification

Check the `deploy production` run and step summary for the deployed SHA, and `helm history blaksoc
-n blaksoc --kube-context yumait-prod` for the release result. Failed gates never obtain AWS
credentials. Partial image builds can be retried. An upgrade failure triggers Helm rollback, but
database migrations are not undone; use backward-compatible migrations and a reviewed recovery
plan for destructive schema changes. A failed public health check after Helm succeeds fails the
workflow and needs investigation; it does not blindly revert a healthy Kubernetes rollout.

For a deliberate code rollback, revert the bad commit on `main` and push the revert through the same
checks. An administrator can use Helm's history for urgent recovery. Disabling the workflow pauses
automatic deployment without changing the running release.

Local checks: `actionlint .github/workflows/deploy.yml .github/workflows/ci.yml`,
`python3 -m unittest discover -s tests/deploy -v`, CloudFormation validation and change-set review,
and Kubernetes server-side RBAC dry run. The first successful GitHub deployment is the integration
check for OIDC trust, ECR permissions, cluster access and production readiness.

References: [GitHub OIDC on AWS](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-aws),
[ECR publishing permissions](https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-push-iam.html),
[EKS access entries](https://docs.aws.amazon.com/eks/latest/userguide/access-entries.html).
