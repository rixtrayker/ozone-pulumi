# Ozone HIS — Pulumi Infrastructure

AWS ECS Fargate + RDS + ALB deployment of Ozone HIS for Sijilati.

## Stack

| Resource | Detail |
|---|---|
| ECS Cluster | `ozone-dev` (Fargate) |
| VPC | `10.10.0.0/16`, 2 public + 2 private subnets, us-east-2 |
| ALB | Internet-facing, ports 80/443 |
| RDS PostgreSQL | `db.t3.micro`, Postgres 15 — Odoo DB |
| Aurora MySQL | Serverless v2 (`0.5–4 ACU`) — OpenMRS DB |
| EFS | Encrypted, shared volume for modules |
| Cloud Map | `ozone-dev.local` private DNS namespace |

## Services

| ECS Service | Image | Port |
|---|---|---|
| `ozone-dev-proxy` | `nginx:1.25-alpine` | 80 |
| `ozone-dev-openmrs` | `openmrs/openmrs-core:2.7.7` | 8080 |
| `ozone-dev-odoo` | `mekomsolutions/odoo:16.0` | 8069 |
| `ozone-dev-eip-odoo` | `mekomsolutions/eip-client:1.5.0` | — |

## DNS records to add (all CNAME -> ALB)

```
ozone.amrx.xyz      CNAME  <alb_dns_name>
openmrs.amrx.xyz    CNAME  <alb_dns_name>
odoo.amrx.xyz       CNAME  <alb_dns_name>
```

Get `alb_dns_name` from: `pulumi stack output alb_dns_name`

## Prerequisites

```bash
pip install -r requirements.txt
pulumi login   # uses Pulumi Cloud
```

## Deploy

```bash
pulumi stack select dev
AWS_PROFILE=Sij pulumi up
```

## Access containers (no bastion needed)

```bash
aws ecs execute-command \
  --cluster ozone-dev \
  --task <task-id> \
  --container openmrs \
  --interactive \
  --command /bin/bash
```

## Tags

All resources tagged `Project=ozone-dev`, `ManagedBy=pulumi`, `Environment=dev`.
