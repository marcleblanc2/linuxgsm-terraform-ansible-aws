resource "aws_vpc" "vpc" {

    cidr_block                      = "10.0.0.0/16"
    enable_dns_hostnames            = true
    enable_dns_support              = true
    tags                            = local.tags

}

resource "aws_subnet" "public-subnet" {

    availability_zone               = local.availability_zone
    cidr_block                      = "10.0.0.0/24"
    map_public_ip_on_launch         = true
    tags                            = local.tags
    vpc_id                          = aws_vpc.vpc.id

}

resource "aws_internet_gateway" "internet-gateway" {

    tags                            = local.tags
    vpc_id                          = aws_vpc.vpc.id

}

resource "aws_route_table" "public-route-table" {

    tags                            = local.tags
    vpc_id                          = aws_vpc.vpc.id

    route {

        cidr_block                  = "0.0.0.0/0"
        gateway_id                  = aws_internet_gateway.internet-gateway.id
    
    }

}

resource "aws_route_table_association" "internet" {
 
    route_table_id                  = aws_route_table.public-route-table.id
    subnet_id                       = aws_subnet.public-subnet.id

}


resource "aws_security_group" "security-group" {

    description                     = "Allow inbound Valheim traffic from the internet"
    name                            = "security-group"
    tags                            = local.tags
    vpc_id                          = aws_vpc.vpc.id

    egress {
        description                 = "Access to the internet"
        from_port                   = 0
        to_port                     = 0
        protocol                    = "-1"
        cidr_blocks                 = ["0.0.0.0/0"]
    }

    ingress {
        description                 = "UDP 2456-2458 from the internet"
        from_port                   = 2456
        to_port                     = 2458
        protocol                    = "udp"
        cidr_blocks                 = ["0.0.0.0/0"]
    }

    ingress {
        description                 = "SSH inbound"
        from_port                   = 22
        to_port                     = 22
        protocol                    = "tcp"
        cidr_blocks                 = local.management-ip-address-list
    }

    ingress {
        description                 = "Ping inbound"
        from_port                   = 8
        to_port                     = -1
        protocol                    = "icmp"
        cidr_blocks                 = local.management-ip-address-list
    }

}

resource "aws_key_pair" "ssh-key-pair" {

    key_name                        = local.ssh-keypair-name
    public_key                      = file(local.ssh-keypair-public-key-filepath)

}

data "aws_ami" "ami" {

    most_recent                     = true
    owners                          = ["099720109477"] # Canonical

    filter {
        name                        = "architecture"
        values                      = ["x86_64"]
    }

    filter {
        name                        = "name"
        values                      = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]

    }

    filter {
        name                        = "virtualization-type"
        values                      = ["hvm"]
    }

}

data "template_file" "user-data-init" {

    template                        = file("user-data.sh")
    vars                            = {
        environment                             = terraform.workspace
        game-data-bucket-name                   = local.game-data-bucket-name
        region                                  = local.region
        valheim-server-display-name             = local.valheim-server-display-name
        valheim-server-world-name               = local.valheim-server-world-name
        valheim-server-world-password           = local.valheim-server-world-password
        valheim-server-public                   = local.valheim-server-public
        svc_account                             = local.svc_account
    }

}

resource "aws_instance" "ec2-instance" {

    ami                             = data.aws_ami.ami.id
    iam_instance_profile            = local.iam_instance_profile
    instance_type                   = local.instance_type
    key_name                        = aws_key_pair.ssh-key-pair.key_name
    subnet_id                       = aws_subnet.public-subnet.id
    tags                            = local.tags
    user_data                       = data.template_file.user-data-init.rendered
    vpc_security_group_ids          = [aws_security_group.security-group.id]

    root_block_device {
        encrypted                   = true
#        volume_size                 = 10
        volume_type                 = "gp3"

    }

}

resource "aws_route53_record" "route53-record" {

    name                            = local.route53-hostname
    records                         = [aws_instance.ec2-instance.public_dns] 
    type                            = "CNAME"
    ttl                             = "60"
    zone_id                         = local.route53-zone-id

}

resource "local_file" "ssh-sh" {
 
    filename                        = "./notes/ssh.sh"
    file_permission                 = "0600"
    content                         = <<-DOC
        ssh -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i ${local.ssh-keypair-private-key-filepath} ubuntu@${aws_route53_record.route53-record.fqdn}
    DOC

}

resource "local_file" "tf_ansible_vars_file_new" {
 
    filename                        = "../ansible/vars/tf_ansible_vars_file.yaml"
    file_permission                 = "0600"
    directory_permission            = "0600"
    content                         = <<-DOC
        # Ansible vars_file containing variable values, generated by Terraform.
        tf_svc_account: ${local.svc_account}
    DOC

}

resource "local_file" "tf_ansible_hosts" {
 
    filename                        = "../ansible/hosts"
    file_permission                 = "0600"
    directory_permission            = "0600"
    content                         = <<-DOC
        [terraform-ec2-instances]
        ${aws_route53_record.route53-record.fqdn}
        [terraform-ec2-instances:vars]
        ansible_ssh_private_key_file=${local.ssh-keypair-private-key-filepath}
        ansible_user=${local.ssh-user}
    DOC

}
