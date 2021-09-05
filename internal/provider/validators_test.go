package provider

import (
	"testing"
)


func TestValidateArn(t *testing.T) {
	v := ""
	_, errors := validateArn(v, "arn")
	if len(errors) != 0 {
		t.Fatalf("%q should not be validated as an ARN: %q", v, errors)
	}

	validNames := []string{
		"arn:aws:elasticbeanstalk:us-east-1:123456789012:environment/My App/MyEnvironment", // lintignore:AWSAT003,AWSAT005 // Beanstalk
		"arn:aws:iam::123456789012:user/David",                                             // lintignore:AWSAT005          // IAM User
		"arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess",                                 // lintignore:AWSAT005          // Managed IAM policy
		"arn:aws:rds:eu-west-1:123456789012:db:mysql-db",                                   // lintignore:AWSAT003,AWSAT005 // RDS
		"arn:aws:s3:::my_corporate_bucket/exampleobject.png",                               // lintignore:AWSAT005          // S3 object
		"arn:aws:events:us-east-1:319201112229:rule/rule_name",                             // lintignore:AWSAT003,AWSAT005 // CloudWatch Rule
		"arn:aws:lambda:eu-west-1:319201112229:function:myCustomFunction",                  // lintignore:AWSAT003,AWSAT005 // Lambda function
		"arn:aws:lambda:eu-west-1:319201112229:function:myCustomFunction:Qualifier",        // lintignore:AWSAT003,AWSAT005 // Lambda func qualifier
		"arn:aws-cn:ec2:cn-north-1:123456789012:instance/i-12345678",                       // lintignore:AWSAT003,AWSAT005 // China EC2 ARN
		"arn:aws-cn:s3:::bucket/object",                                                    // lintignore:AWSAT005          // China S3 ARN
		"arn:aws-iso:ec2:us-iso-east-1:123456789012:instance/i-12345678",                   // lintignore:AWSAT003,AWSAT005 // C2S EC2 ARN
		"arn:aws-iso:s3:::bucket/object",                                                   // lintignore:AWSAT005          // C2S S3 ARN
		"arn:aws-iso-b:ec2:us-isob-east-1:123456789012:instance/i-12345678",                // lintignore:AWSAT003,AWSAT005 // SC2S EC2 ARN
		"arn:aws-iso-b:s3:::bucket/object",                                                 // lintignore:AWSAT005          // SC2S S3 ARN
		"arn:aws-us-gov:ec2:us-gov-west-1:123456789012:instance/i-12345678",                // lintignore:AWSAT003,AWSAT005 // GovCloud EC2 ARN
		"arn:aws-us-gov:s3:::bucket/object",                                                // lintignore:AWSAT005          // GovCloud S3 ARN
	}
	for _, v := range validNames {
		_, errors := validateArn(v, "arn")
		if len(errors) != 0 {
			t.Fatalf("%q should be a valid ARN: %q", v, errors)
		}
	}

	invalidNames := []string{
		"arn",
		"123456789012",
		"arn:aws",
		"arn:aws:logs",            //lintignore:AWSAT005
		"arn:aws:logs:region:*:*", //lintignore:AWSAT005
	}
	for _, v := range invalidNames {
		_, errors := validateArn(v, "arn")
		if len(errors) == 0 {
			t.Fatalf("%q should be an invalid ARN", v)
		}
	}
}

