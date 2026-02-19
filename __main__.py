"""
Ozone HIS Infrastructure
========================
ECS Fargate + RDS PostgreSQL + ALB + VPC
Region  : us-east-2 (Ohio)
Profile : Sij
Tags    : Project=ozone-dev

Services deployed on ECS Fargate:
  - proxy          (nginx, ALB-fronted, ports 80 + 443)
  - openmrs        (OpenMRS O3 backend)
  - openmrs-spa    (O3 frontend SPA)
  - odoo           (ERP, port 8069)
  - eip-odoo       (Camel EIP bridge OpenMRS <-> Odoo)

RDS PostgreSQL  : shared cluster for Odoo + OpenMRS (separate DBs)
MySQL Aurora    : OpenMRS MySQL (Aurora Serverless v2 - stays cost-free when idle)

Subdomain routing (all -> ALB):
  ozone.amrx.xyz        -> proxy -> O3 frontend   /openmrs/spa
  openmrs.amrx.xyz      -> proxy -> OpenMRS REST   /openmrs
  odoo.amrx.xyz         -> odoo  :8069
"""

import json
import pulumi
import pulumi_aws as aws

# -- Tags applied to every resource --------------------------------------------
TAGS = {
    "Project":     "ozone-dev",
    "ManagedBy":   "pulumi",
    "Environment": "dev",
}

# -- Key pair (reuse existing amr-sij or set to None for Fargate-only) ---------
KEY_NAME = "amr-sij"

# -- Image versions (Docker Hub) ------------------------------------------------
OPENMRS_BACKEND_IMAGE  = "openmrs/openmrs-core:2.7.7-amazoncorretto-17"
OPENMRS_FRONTEND_IMAGE = "openmrs/openmrs-reference-application-3-frontend:nightly"
ODOO_IMAGE             = "mekomsolutions/odoo:16.0-3.0.0"
EIP_ODOO_IMAGE         = "mekomsolutions/eip-client:1.5.0"
NGINX_PROXY_IMAGE      = "nginx:1.25-alpine"

# -- Networking -----------------------------------------------------------------

vpc = aws.ec2.Vpc(
    "ozone-vpc",
    cidr_block="10.10.0.0/16",
    enable_dns_hostnames=True,
    enable_dns_support=True,
    tags={**TAGS, "Name": "ozone-dev-vpc"},
)

igw = aws.ec2.InternetGateway(
    "ozone-igw",
    vpc_id=vpc.id,
    tags={**TAGS, "Name": "ozone-dev-igw"},
)

# Two public subnets (ALB needs >=2 AZs)
pub_a = aws.ec2.Subnet(
    "ozone-pub-a",
    vpc_id=vpc.id,
    cidr_block="10.10.1.0/24",
    availability_zone="us-east-2a",
    map_public_ip_on_launch=True,
    tags={**TAGS, "Name": "ozone-dev-pub-a"},
)

pub_b = aws.ec2.Subnet(
    "ozone-pub-b",
    vpc_id=vpc.id,
    cidr_block="10.10.2.0/24",
    availability_zone="us-east-2b",
    map_public_ip_on_launch=True,
    tags={**TAGS, "Name": "ozone-dev-pub-b"},
)

# Two private subnets (ECS tasks + RDS)
priv_a = aws.ec2.Subnet(
    "ozone-priv-a",
    vpc_id=vpc.id,
    cidr_block="10.10.11.0/24",
    availability_zone="us-east-2a",
    tags={**TAGS, "Name": "ozone-dev-priv-a"},
)

priv_b = aws.ec2.Subnet(
    "ozone-priv-b",
    vpc_id=vpc.id,
    cidr_block="10.10.12.0/24",
    availability_zone="us-east-2b",
    tags={**TAGS, "Name": "ozone-dev-priv-b"},
)

# NAT Gateway so private subnets can pull Docker images
eip = aws.ec2.Eip(
    "ozone-nat-eip",
    domain="vpc",
    tags={**TAGS, "Name": "ozone-dev-nat-eip"},
)

nat_gw = aws.ec2.NatGateway(
    "ozone-nat",
    subnet_id=pub_a.id,
    allocation_id=eip.id,
    tags={**TAGS, "Name": "ozone-dev-nat"},
)

# Route tables
pub_rt = aws.ec2.RouteTable(
    "ozone-pub-rt",
    vpc_id=vpc.id,
    routes=[aws.ec2.RouteTableRouteArgs(cidr_block="0.0.0.0/0", gateway_id=igw.id)],
    tags={**TAGS, "Name": "ozone-dev-pub-rt"},
)

priv_rt = aws.ec2.RouteTable(
    "ozone-priv-rt",
    vpc_id=vpc.id,
    routes=[aws.ec2.RouteTableRouteArgs(cidr_block="0.0.0.0/0", nat_gateway_id=nat_gw.id)],
    tags={**TAGS, "Name": "ozone-dev-priv-rt"},
)

for name, subnet_id in [("pub-a", pub_a.id), ("pub-b", pub_b.id)]:
    aws.ec2.RouteTableAssociation(f"ozone-rta-{name}", subnet_id=subnet_id, route_table_id=pub_rt.id)

for name, subnet_id in [("priv-a", priv_a.id), ("priv-b", priv_b.id)]:
    aws.ec2.RouteTableAssociation(f"ozone-rta-{name}", subnet_id=subnet_id, route_table_id=priv_rt.id)

# -- Security Groups ------------------------------------------------------------

# ALB: accepts 80 + 443 from anywhere
alb_sg = aws.ec2.SecurityGroup(
    "ozone-alb-sg",
    vpc_id=vpc.id,
    description="Ozone ALB - HTTP/HTTPS from internet",
    ingress=[
        aws.ec2.SecurityGroupIngressArgs(protocol="tcp", from_port=80,  to_port=80,  cidr_blocks=["0.0.0.0/0"]),
        aws.ec2.SecurityGroupIngressArgs(protocol="tcp", from_port=443, to_port=443, cidr_blocks=["0.0.0.0/0"]),
    ],
    egress=[aws.ec2.SecurityGroupEgressArgs(protocol="-1", from_port=0, to_port=0, cidr_blocks=["0.0.0.0/0"])],
    tags={**TAGS, "Name": "ozone-dev-alb-sg"},
)

# ECS tasks: traffic from ALB only (+ internal service-to-service on VPC CIDR)
ecs_sg = aws.ec2.SecurityGroup(
    "ozone-ecs-sg",
    vpc_id=vpc.id,
    description="Ozone ECS tasks - from ALB + VPC-internal",
    ingress=[
        aws.ec2.SecurityGroupIngressArgs(protocol="tcp", from_port=80,   to_port=80,   security_groups=[alb_sg.id]),
        aws.ec2.SecurityGroupIngressArgs(protocol="tcp", from_port=443,  to_port=443,  security_groups=[alb_sg.id]),
        aws.ec2.SecurityGroupIngressArgs(protocol="tcp", from_port=8080, to_port=8080, security_groups=[alb_sg.id]),
        aws.ec2.SecurityGroupIngressArgs(protocol="tcp", from_port=8069, to_port=8069, security_groups=[alb_sg.id]),
        # internal VPC traffic (ECS -> ECS)
        aws.ec2.SecurityGroupIngressArgs(protocol="-1", from_port=0, to_port=0, cidr_blocks=["10.10.0.0/16"]),
    ],
    egress=[aws.ec2.SecurityGroupEgressArgs(protocol="-1", from_port=0, to_port=0, cidr_blocks=["0.0.0.0/0"])],
    tags={**TAGS, "Name": "ozone-dev-ecs-sg"},
)

# RDS: accepts from ECS SG only
rds_sg = aws.ec2.SecurityGroup(
    "ozone-rds-sg",
    vpc_id=vpc.id,
    description="Ozone RDS PostgreSQL - from ECS tasks only",
    ingress=[
        aws.ec2.SecurityGroupIngressArgs(protocol="tcp", from_port=5432, to_port=5432, security_groups=[ecs_sg.id]),
    ],
    egress=[aws.ec2.SecurityGroupEgressArgs(protocol="-1", from_port=0, to_port=0, cidr_blocks=["0.0.0.0/0"])],
    tags={**TAGS, "Name": "ozone-dev-rds-sg"},
)

# MySQL (Aurora Serverless v2) SG - for OpenMRS
mysql_sg = aws.ec2.SecurityGroup(
    "ozone-mysql-sg",
    vpc_id=vpc.id,
    description="Ozone Aurora MySQL - from ECS tasks only",
    ingress=[
        aws.ec2.SecurityGroupIngressArgs(protocol="tcp", from_port=3306, to_port=3306, security_groups=[ecs_sg.id]),
    ],
    egress=[aws.ec2.SecurityGroupEgressArgs(protocol="-1", from_port=0, to_port=0, cidr_blocks=["0.0.0.0/0"])],
    tags={**TAGS, "Name": "ozone-dev-mysql-sg"},
)

# -- RDS - PostgreSQL 15 (for Odoo) --------------------------------------------

rds_subnet_group = aws.rds.SubnetGroup(
    "ozone-rds-subnet-group",
    subnet_ids=[priv_a.id, priv_b.id],
    tags={**TAGS, "Name": "ozone-dev-rds-subnet-group"},
)

pg_db = aws.rds.Instance(
    "ozone-postgres",
    identifier="ozone-dev-postgres",
    engine="postgres",
    engine_version="15.16",
    instance_class="db.t3.micro",
    allocated_storage=20,
    storage_type="gp3",
    db_name="ozone",
    username="ozone",
    password="OzoneRDS!Pg2024",
    db_subnet_group_name=rds_subnet_group.name,
    vpc_security_group_ids=[rds_sg.id],
    skip_final_snapshot=True,
    deletion_protection=False,
    publicly_accessible=False,
    multi_az=False,
    tags={**TAGS, "Name": "ozone-dev-postgres"},
)

# -- RDS - Aurora MySQL Serverless v2 (for OpenMRS) ----------------------------

mysql_subnet_group = aws.rds.SubnetGroup(
    "ozone-mysql-subnet-group",
    subnet_ids=[priv_a.id, priv_b.id],
    tags={**TAGS, "Name": "ozone-dev-mysql-subnet-group"},
)

aurora_cluster = aws.rds.Cluster(
    "ozone-aurora-mysql",
    cluster_identifier="ozone-dev-mysql",
    engine="aurora-mysql",
    engine_version="8.0.mysql_aurora.3.12.0",
    engine_mode="provisioned",
    database_name="openmrs",
    master_username="openmrs",
    master_password="OzoneAurora!My2024",
    db_subnet_group_name=mysql_subnet_group.name,
    vpc_security_group_ids=[mysql_sg.id],
    skip_final_snapshot=True,
    deletion_protection=False,
    serverlessv2_scaling_configuration=aws.rds.ClusterServerlessv2ScalingConfigurationArgs(
        min_capacity=0.5,
        max_capacity=4.0,
    ),
    tags={**TAGS, "Name": "ozone-dev-aurora-mysql"},
)

aurora_instance = aws.rds.ClusterInstance(
    "ozone-aurora-mysql-instance",
    cluster_identifier=aurora_cluster.id,
    identifier="ozone-dev-mysql-1",
    instance_class="db.serverless",
    engine=aurora_cluster.engine,
    engine_version=aurora_cluster.engine_version,
    db_subnet_group_name=mysql_subnet_group.name,
    tags={**TAGS, "Name": "ozone-dev-aurora-mysql-1"},
)

# -- EFS - shared persistent volume for OpenMRS modules + Odoo addons ----------

efs = aws.efs.FileSystem(
    "ozone-efs",
    encrypted=True,
    tags={**TAGS, "Name": "ozone-dev-efs"},
)

efs_sg = aws.ec2.SecurityGroup(
    "ozone-efs-sg",
    vpc_id=vpc.id,
    description="Ozone EFS - NFS from ECS tasks",
    ingress=[
        aws.ec2.SecurityGroupIngressArgs(protocol="tcp", from_port=2049, to_port=2049, security_groups=[ecs_sg.id]),
    ],
    egress=[aws.ec2.SecurityGroupEgressArgs(protocol="-1", from_port=0, to_port=0, cidr_blocks=["0.0.0.0/0"])],
    tags={**TAGS, "Name": "ozone-dev-efs-sg"},
)

efs_mt_a = aws.efs.MountTarget("ozone-efs-mt-a", file_system_id=efs.id, subnet_id=priv_a.id, security_groups=[efs_sg.id])
efs_mt_b = aws.efs.MountTarget("ozone-efs-mt-b", file_system_id=efs.id, subnet_id=priv_b.id, security_groups=[efs_sg.id])

# -- ECS Cluster ----------------------------------------------------------------

cluster = aws.ecs.Cluster(
    "ozone-cluster",
    name="ozone-dev",
    settings=[aws.ecs.ClusterSettingArgs(name="containerInsights", value="enabled")],
    tags={**TAGS, "Name": "ozone-dev-cluster"},
)

# -- IAM - ECS Task Execution Role ---------------------------------------------

exec_role = aws.iam.Role(
    "ozone-ecs-exec-role",
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }),
    tags=TAGS,
)

aws.iam.RolePolicyAttachment(
    "ozone-ecs-exec-policy",
    role=exec_role.name,
    policy_arn="arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy",
)

# -- CloudWatch Log Groups ------------------------------------------------------

for svc in ["openmrs", "odoo", "eip-odoo", "proxy"]:
    aws.cloudwatch.LogGroup(f"ozone-lg-{svc}", name=f"/ozone-dev/{svc}", retention_in_days=7, tags=TAGS)

# -- ALB -----------------------------------------------------------------------

alb = aws.lb.LoadBalancer(
    "ozone-alb",
    name="ozone-dev-alb",
    internal=False,
    load_balancer_type="application",
    security_groups=[alb_sg.id],
    subnets=[pub_a.id, pub_b.id],
    tags={**TAGS, "Name": "ozone-dev-alb"},
)

# -- Target Groups -------------------------------------------------------------

tg_openmrs = aws.lb.TargetGroup(
    "ozone-tg-openmrs",
    name="ozone-dev-openmrs",
    port=8080,
    protocol="HTTP",
    target_type="ip",
    vpc_id=vpc.id,
    health_check=aws.lb.TargetGroupHealthCheckArgs(
        path="/openmrs/health",
        interval=60,
        timeout=30,
        healthy_threshold=2,
        unhealthy_threshold=5,
        matcher="200-302",
    ),
    tags={**TAGS, "Name": "ozone-dev-tg-openmrs"},
)

tg_odoo = aws.lb.TargetGroup(
    "ozone-tg-odoo",
    name="ozone-dev-odoo",
    port=8069,
    protocol="HTTP",
    target_type="ip",
    vpc_id=vpc.id,
    health_check=aws.lb.TargetGroupHealthCheckArgs(
        path="/web/health",
        interval=60,
        timeout=30,
        healthy_threshold=2,
        unhealthy_threshold=5,
        matcher="200",
    ),
    tags={**TAGS, "Name": "ozone-dev-tg-odoo"},
)

tg_proxy = aws.lb.TargetGroup(
    "ozone-tg-proxy",
    name="ozone-dev-proxy",
    port=80,
    protocol="HTTP",
    target_type="ip",
    vpc_id=vpc.id,
    health_check=aws.lb.TargetGroupHealthCheckArgs(
        path="/",
        interval=30,
        timeout=10,
        healthy_threshold=2,
        unhealthy_threshold=3,
        matcher="200-302",
    ),
    tags={**TAGS, "Name": "ozone-dev-tg-proxy"},
)

# -- ALB Listeners -------------------------------------------------------------
# HTTP :80 default -> proxy (O3 frontend); host-based rules forward to services

listener_http = aws.lb.Listener(
    "ozone-listener-http",
    load_balancer_arn=alb.arn,
    port=80,
    protocol="HTTP",
    default_actions=[aws.lb.ListenerDefaultActionArgs(type="forward", target_group_arn=tg_proxy.arn)],
)

# Host-based routing rules
aws.lb.ListenerRule(
    "ozone-rule-openmrs",
    listener_arn=listener_http.arn,
    priority=10,
    conditions=[aws.lb.ListenerRuleConditionArgs(
        host_header=aws.lb.ListenerRuleConditionHostHeaderArgs(values=["openmrs.amrx.xyz"]),
    )],
    actions=[aws.lb.ListenerRuleActionArgs(type="forward", target_group_arn=tg_openmrs.arn)],
)

aws.lb.ListenerRule(
    "ozone-rule-odoo",
    listener_arn=listener_http.arn,
    priority=20,
    conditions=[aws.lb.ListenerRuleConditionArgs(
        host_header=aws.lb.ListenerRuleConditionHostHeaderArgs(values=["odoo.amrx.xyz"]),
    )],
    actions=[aws.lb.ListenerRuleActionArgs(type="forward", target_group_arn=tg_odoo.arn)],
)

# -- ECS Task Definitions -------------------------------------------------------

# Helper: build EFS volume config block
def efs_volume(name, access_point_id=None):
    cfg = {"fileSystemId": efs.id.apply(lambda x: x)}
    if access_point_id:
        cfg["authorizationConfig"] = {"accessPointId": access_point_id, "iam": "DISABLED"}
        cfg["transitEncryption"] = "ENABLED"
    return {"name": name, "efsVolumeConfiguration": cfg}


# -- Task: OpenMRS backend ------------------------------------------------------
openmrs_td = aws.ecs.TaskDefinition(
    "ozone-td-openmrs",
    family="ozone-dev-openmrs",
    cpu="1024",
    memory="2048",
    network_mode="awsvpc",
    requires_compatibilities=["FARGATE"],
    execution_role_arn=exec_role.arn,
    container_definitions=pulumi.Output.all(
        pg_host=pg_db.address,
        my_host=aurora_cluster.endpoint,
    ).apply(lambda args: json.dumps([
        {
            "name": "openmrs",
            "image": OPENMRS_BACKEND_IMAGE,
            "portMappings": [{"containerPort": 8080, "protocol": "tcp"}],
            "environment": [
                {"name": "OMRS_DB_HOSTNAME",   "value": args["my_host"]},
                {"name": "OMRS_DB_PORT",        "value": "3306"},
                {"name": "OMRS_DB_NAME",        "value": "openmrs"},
                {"name": "OMRS_DB_USERNAME",    "value": "openmrs"},
                {"name": "OMRS_DB_PASSWORD",    "value": "OzoneAurora!My2024"},
                {"name": "OMRS_CREATE_TABLES",  "value": "true"},
                {"name": "OMRS_AUTO_UPDATE_DATABASE", "value": "true"},
                {"name": "OMRS_MODULE_WEB_ADMIN", "value": "false"},
                {"name": "JAVA_OPTS",           "value": "-Xmx1500m -Xms512m"},
            ],
            "logConfiguration": {
                "logDriver": "awslogs",
                "options": {
                    "awslogs-group":  "/ozone-dev/openmrs",
                    "awslogs-region": "us-east-2",
                    "awslogs-stream-prefix": "openmrs",
                },
            },
            "essential": True,
            "healthCheck": {
                "command": ["CMD-SHELL", "curl -fs http://localhost:8080/openmrs/health || exit 1"],
                "interval": 60,
                "timeout": 30,
                "retries": 5,
                "startPeriod": 180,
            },
        }
    ])),
    tags={**TAGS, "Name": "ozone-dev-td-openmrs"},
)

# -- Task: Odoo ERP -------------------------------------------------------------
odoo_td = aws.ecs.TaskDefinition(
    "ozone-td-odoo",
    family="ozone-dev-odoo",
    cpu="1024",
    memory="2048",
    network_mode="awsvpc",
    requires_compatibilities=["FARGATE"],
    execution_role_arn=exec_role.arn,
    container_definitions=pulumi.Output.all(pg_host=pg_db.address).apply(
        lambda args: json.dumps([
            {
                "name": "odoo",
                "image": ODOO_IMAGE,
                "portMappings": [{"containerPort": 8069, "protocol": "tcp"}],
                "environment": [
                    {"name": "HOST",     "value": args["pg_host"]},
                    {"name": "PORT",     "value": "5432"},
                    {"name": "USER",     "value": "ozone"},
                    {"name": "PASSWORD", "value": "OzoneRDS!Pg2024"},
                    {"name": "DB_NAME",  "value": "odoo"},
                ],
                "logConfiguration": {
                    "logDriver": "awslogs",
                    "options": {
                        "awslogs-group":  "/ozone-dev/odoo",
                        "awslogs-region": "us-east-2",
                        "awslogs-stream-prefix": "odoo",
                    },
                },
                "essential": True,
                "healthCheck": {
                    "command": ["CMD-SHELL", "curl -fs http://localhost:8069/web/health || exit 1"],
                    "interval": 30,
                    "timeout": 10,
                    "retries": 5,
                    "startPeriod": 120,
                },
            }
        ])
    ),
    tags={**TAGS, "Name": "ozone-dev-td-odoo"},
)

# -- Task: EIP Odoo <-> OpenMRS bridge -------------------------------------------
eip_td = aws.ecs.TaskDefinition(
    "ozone-td-eip-odoo",
    family="ozone-dev-eip-odoo",
    cpu="512",
    memory="1024",
    network_mode="awsvpc",
    requires_compatibilities=["FARGATE"],
    execution_role_arn=exec_role.arn,
    container_definitions=pulumi.Output.all(pg_host=pg_db.address).apply(
        lambda args: json.dumps([
            {
                "name": "eip-odoo-openmrs",
                "image": EIP_ODOO_IMAGE,
                "environment": [
                    {"name": "OPENMRS_URL",          "value": "http://openmrs.ozone-dev.local:8080/openmrs"},
                    {"name": "OPENMRS_USER",         "value": "admin"},
                    {"name": "OPENMRS_PASSWORD",     "value": "Admin123"},
                    {"name": "ODOO_URL",             "value": "http://odoo.ozone-dev.local:8069"},
                    {"name": "ODOO_DB",              "value": "odoo"},
                    {"name": "ODOO_USER",            "value": "admin"},
                    {"name": "ODOO_PASSWORD",        "value": "admin"},
                    {"name": "EIP_DB_DRIVER",        "value": "org.postgresql.Driver"},
                    {"name": "EIP_DB_URL",           "value": f"jdbc:postgresql://{args['pg_host']}:5432/eip"},
                    {"name": "EIP_DB_USER",          "value": "ozone"},
                    {"name": "EIP_DB_PASSWORD",      "value": "OzoneRDS!Pg2024"},
                ],
                "logConfiguration": {
                    "logDriver": "awslogs",
                    "options": {
                        "awslogs-group":  "/ozone-dev/eip-odoo",
                        "awslogs-region": "us-east-2",
                        "awslogs-stream-prefix": "eip-odoo",
                    },
                },
                "essential": True,
            }
        ])
    ),
    tags={**TAGS, "Name": "ozone-dev-td-eip-odoo"},
)

# -- Task: Nginx reverse proxy (O3 frontend + path routing) --------------------
proxy_td = aws.ecs.TaskDefinition(
    "ozone-td-proxy",
    family="ozone-dev-proxy",
    cpu="256",
    memory="512",
    network_mode="awsvpc",
    requires_compatibilities=["FARGATE"],
    execution_role_arn=exec_role.arn,
    container_definitions=json.dumps([
        {
            "name": "proxy",
            "image": NGINX_PROXY_IMAGE,
            "portMappings": [{"containerPort": 80, "protocol": "tcp"}],
            "environment": [
                {"name": "OPENMRS_HOST", "value": "openmrs.ozone-dev.local"},
                {"name": "OPENMRS_PORT", "value": "8080"},
                {"name": "ODOO_HOST",    "value": "odoo.ozone-dev.local"},
                {"name": "ODOO_PORT",    "value": "8069"},
            ],
            "logConfiguration": {
                "logDriver": "awslogs",
                "options": {
                    "awslogs-group":  "/ozone-dev/proxy",
                    "awslogs-region": "us-east-2",
                    "awslogs-stream-prefix": "proxy",
                },
            },
            "essential": True,
        }
    ]),
    tags={**TAGS, "Name": "ozone-dev-td-proxy"},
)

# -- Service Discovery (Cloud Map) - internal DNS for ECS <-> ECS calls ----------

dns_namespace = aws.servicediscovery.PrivateDnsNamespace(
    "ozone-dns-ns",
    name="ozone-dev.local",
    vpc=vpc.id,
    tags={**TAGS, "Name": "ozone-dev-dns-namespace"},
)

def make_sd_service(name, dns_ns_id, port):
    return aws.servicediscovery.Service(
        f"ozone-sd-{name}",
        name=name,
        dns_config=aws.servicediscovery.ServiceDnsConfigArgs(
            namespace_id=dns_ns_id,
            dns_records=[aws.servicediscovery.ServiceDnsConfigDnsRecordArgs(type="A", ttl=10)],
            routing_policy="MULTIVALUE",
        ),
        health_check_custom_config=aws.servicediscovery.ServiceHealthCheckCustomConfigArgs(failure_threshold=1),
        tags={**TAGS, "Name": f"ozone-dev-sd-{name}"},
        opts=pulumi.ResourceOptions(ignore_changes=["healthCheckCustomConfig"]),
    )

sd_openmrs = make_sd_service("openmrs", dns_namespace.id, 8080)
sd_odoo    = make_sd_service("odoo",    dns_namespace.id, 8069)
sd_proxy   = make_sd_service("proxy",   dns_namespace.id, 80)

# -- ECS Services --------------------------------------------------------------

common_net = aws.ecs.ServiceNetworkConfigurationArgs(
    assign_public_ip=False,
    subnets=[priv_a.id, priv_b.id],
    security_groups=[ecs_sg.id],
)

svc_openmrs = aws.ecs.Service(
    "ozone-svc-openmrs",
    name="ozone-dev-openmrs",
    cluster=cluster.arn,
    task_definition=openmrs_td.arn,
    desired_count=1,
    launch_type="FARGATE",
    network_configuration=common_net,
    load_balancers=[aws.ecs.ServiceLoadBalancerArgs(
        target_group_arn=tg_openmrs.arn,
        container_name="openmrs",
        container_port=8080,
    )],
    service_registries=aws.ecs.ServiceServiceRegistriesArgs(
        registry_arn=sd_openmrs.arn,
        container_name="openmrs",
    ),
    tags={**TAGS, "Name": "ozone-dev-svc-openmrs"},
    opts=pulumi.ResourceOptions(depends_on=[aurora_instance, listener_http]),
)

svc_odoo = aws.ecs.Service(
    "ozone-svc-odoo",
    name="ozone-dev-odoo",
    cluster=cluster.arn,
    task_definition=odoo_td.arn,
    desired_count=1,
    launch_type="FARGATE",
    network_configuration=common_net,
    load_balancers=[aws.ecs.ServiceLoadBalancerArgs(
        target_group_arn=tg_odoo.arn,
        container_name="odoo",
        container_port=8069,
    )],
    service_registries=aws.ecs.ServiceServiceRegistriesArgs(
        registry_arn=sd_odoo.arn,
        container_name="odoo",
    ),
    tags={**TAGS, "Name": "ozone-dev-svc-odoo"},
    opts=pulumi.ResourceOptions(depends_on=[pg_db, listener_http]),
)

svc_eip = aws.ecs.Service(
    "ozone-svc-eip-odoo",
    name="ozone-dev-eip-odoo",
    cluster=cluster.arn,
    task_definition=eip_td.arn,
    desired_count=1,
    launch_type="FARGATE",
    network_configuration=common_net,
    tags={**TAGS, "Name": "ozone-dev-svc-eip-odoo"},
    opts=pulumi.ResourceOptions(depends_on=[svc_openmrs, svc_odoo]),
)

svc_proxy = aws.ecs.Service(
    "ozone-svc-proxy",
    name="ozone-dev-proxy",
    cluster=cluster.arn,
    task_definition=proxy_td.arn,
    desired_count=1,
    launch_type="FARGATE",
    network_configuration=common_net,
    load_balancers=[aws.ecs.ServiceLoadBalancerArgs(
        target_group_arn=tg_proxy.arn,
        container_name="proxy",
        container_port=80,
    )],
    service_registries=aws.ecs.ServiceServiceRegistriesArgs(
        registry_arn=sd_proxy.arn,
        container_name="proxy",
    ),
    tags={**TAGS, "Name": "ozone-dev-svc-proxy"},
    opts=pulumi.ResourceOptions(depends_on=[listener_http]),
)

# -- Outputs -------------------------------------------------------------------

pulumi.export("alb_dns_name",         alb.dns_name)
pulumi.export("vpc_id",               vpc.id)
pulumi.export("ecs_cluster",          cluster.name)
pulumi.export("rds_postgres_host",    pg_db.address)
pulumi.export("rds_aurora_mysql_host",aurora_cluster.endpoint)
pulumi.export("efs_id",               efs.id)

pulumi.export("dns_records_to_create", pulumi.Output.concat(
    "Add these CNAME records in Route 53 / DNS provider (all -> ", alb.dns_name, "):\n"
    "  ozone.amrx.xyz      CNAME  <alb_dns_name>\n"
    "  openmrs.amrx.xyz    CNAME  <alb_dns_name>\n"
    "  odoo.amrx.xyz       CNAME  <alb_dns_name>\n"
))

pulumi.export("ssh_bastion_note",
    "No bastion needed - all tasks are Fargate. Use ECS Exec for shell access:\n"
    "  aws ecs execute-command --cluster ozone-dev --task <task-id> "
    "--container openmrs --interactive --command /bin/bash"
)
