# Elasticsearch Hadoop with AWS Signing Support

This repository is a fork of: https://github.com/elastic/elasticsearch-hadoop of the v6.0 branch with AWS signing of requests enabled.

The AWS Credential provider is: `DefaultCredentialProvider` which will use the EnvironementVars then System Properties and finally the EC2InstanceProfile to fetch the credentials.

