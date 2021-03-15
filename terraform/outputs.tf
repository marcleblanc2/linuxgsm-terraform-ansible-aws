output "ec2-instance-ami-creation-date" {

    value = data.aws_ami.ami.creation_date

}

output "ec2-instance-ami-description" {

    value = data.aws_ami.ami.description

}

output "ec2-instance-ami-id" {

    value = data.aws_ami.ami.id

}

output "ec2-instance-public-ip" {

    value = aws_instance.ec2-instance.public_ip
  
}

output "ec2-instance-route53-fqdn" {

    value = aws_route53_record.route53-record.fqdn
  
}
