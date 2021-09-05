package provider

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go/aws/session"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/logging"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"

	awsbase "github.com/hashicorp/aws-sdk-go-base"
)

var descriptions map[string]string

func init() {
	// Set descriptions to support markdown syntax, this will be used in document generation
	// and the language server.
	schema.DescriptionKind = schema.StringMarkdown

	descriptions = map[string]string{
		"api_endpoint": "The HTTPS endpoint for the API. Examples are \n" +
			"https://myapi.com",
		"region": "The region where AWS operations will take place. Examples\n" +
			"are us-east-1, us-west-2, etc.", // lintignore:AWSAT003

		"access_key": "The access key for API operations. You can retrieve this\n" +
			"from the 'Security & Credentials' section of the AWS console.",

		"secret_key": "The secret key for API operations. You can retrieve this\n" +
			"from the 'Security & Credentials' section of the AWS console.",

		"profile": "The profile for API operations. If not set, the default profile\n" +
			"created with `aws configure` will be used.",

		"shared_credentials_file": "The path to the shared credentials file. If not set\n" +
			"this defaults to ~/.aws/credentials.",

		"token": "session token. A session token is only required if you are\n" +
			"using temporary security credentials.",

		"max_retries": "The maximum number of times an AWS API request is\n" +
			"being executed. If the API request still fails, an error is\n" +
			"thrown.",

		"skip_credentials_validation": "Skip the credentials validation via STS API. " +
			"Used for AWS API implementations that do not have STS available/implemented.",

		"skip_region_validation": "Skip static validation of region name. " +
			"Used by users of alternative AWS-like APIs or users w/ access to regions that are not public (yet).",

		"skip_requesting_account_id": "Skip requesting the account ID. " +
			"Used for AWS API implementations that do not have IAM/STS API and/or metadata API.",

	}

}

func New(version string) func() *schema.Provider {
	return func() *schema.Provider {
		p := &schema.Provider{
			Schema: map[string]*schema.Schema{
				"api_endpoint": {
					Type:     schema.TypeString,
					Required: true,
					Description:  descriptions["api_endpoint"],
					DefaultFunc: schema.EnvDefaultFunc("API_ENDPOINT", nil),
				},
				"access_key": {
					Type:        schema.TypeString,
					Optional:    true,
					Default:     "",
					Description: descriptions["access_key"],
				},
				"secret_key": {
					Type:        schema.TypeString,
					Optional:    true,
					Default:     "",
					Description: descriptions["secret_key"],
				},
				"profile": {
					Type:        schema.TypeString,
					Optional:    true,
					Default:     "",
					Description: descriptions["profile"],
				},
				"assume_role": assumeRoleSchema(),
				"shared_credentials_file": {
					Type:        schema.TypeString,
					Optional:    true,
					Default:     "",
					Description: descriptions["shared_credentials_file"],
				},
				"token": {
					Type:        schema.TypeString,
					Optional:    true,
					Default:     "",
					Description: descriptions["token"],
				},
				"region": {
					Type:     schema.TypeString,
					Required: true,
					DefaultFunc: schema.MultiEnvDefaultFunc([]string{
						"AWS_REGION",
						"AWS_DEFAULT_REGION",
					}, nil),
					Description:  descriptions["region"],
					InputDefault: "us-east-1", // lintignore:AWSAT003
				},
				"max_retries": {
					Type:        schema.TypeInt,
					Optional:    true,
					Default:     25,
					Description: descriptions["max_retries"],
				},
				"allowed_account_ids": {
					Type:          schema.TypeSet,
					Elem:          &schema.Schema{Type: schema.TypeString},
					Optional:      true,
					ConflictsWith: []string{"forbidden_account_ids"},
					Set:           schema.HashString,
				},
				"forbidden_account_ids": {
					Type:          schema.TypeSet,
					Elem:          &schema.Schema{Type: schema.TypeString},
					Optional:      true,
					ConflictsWith: []string{"allowed_account_ids"},
					Set:           schema.HashString,
				},
				"skip_credentials_validation": {
					Type:        schema.TypeBool,
					Optional:    true,
					Default:     false,
					Description: descriptions["skip_credentials_validation"],
				},
				"skip_region_validation": {
					Type:        schema.TypeBool,
					Optional:    true,
					Default:     false,
					Description: descriptions["skip_region_validation"],
				},
				"skip_requesting_account_id": {
					Type:        schema.TypeBool,
					Optional:    true,
					Default:     false,
					Description: descriptions["skip_requesting_account_id"],
				},
			},
			DataSourcesMap: map[string]*schema.Resource{
				"scaffolding_data_source": dataSourceScaffolding(),
			},
			ResourcesMap: map[string]*schema.Resource{
				"scaffolding_resource": resourceScaffolding(),
			},
		}

		p.ConfigureContextFunc = configure(version, p)

		return p
	}
}

type ApiClient struct {
	accountId                           string
	region                              string
	awsSession 							*session.Session
	signer                              *v4.Signer
	terraformVersion                    string
	apiEndpoint						    string
}

type Config struct {
	// Add whatever fields, client or connection info, etc. here
	// you would need to setup to communicate with the upstream
	// API.
	AccessKey     string
	SecretKey     string
	CredsFilename string
	Profile       string
	Token         string
	Region        string
	MaxRetries    int

	AssumeRoleARN               string
	AssumeRoleDurationSeconds   int
	AssumeRoleExternalID        string
	AssumeRolePolicy            string
	AssumeRolePolicyARNs        []string
	AssumeRoleSessionName       string
	AssumeRoleTags              map[string]string
	AssumeRoleTransitiveTagKeys []string

	AllowedAccountIds   []string
	ForbiddenAccountIds []string

	SkipCredsValidation     bool
	SkipRegionValidation    bool
	SkipRequestingAccountId bool

	TerraformVersion string
	ApiEndpoint string
}

func configure(version string, p *schema.Provider) func(context.Context, *schema.ResourceData) (interface{}, diag.Diagnostics) {
	return func(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
		var diags diag.Diagnostics

		config := Config{
			AccessKey:               d.Get("access_key").(string),
			SecretKey:               d.Get("secret_key").(string),
			Profile:                 d.Get("profile").(string),
			Token:                   d.Get("token").(string),
			Region:                  d.Get("region").(string),
			CredsFilename:           d.Get("shared_credentials_file").(string),
			MaxRetries:              d.Get("max_retries").(int),
			SkipCredsValidation:     d.Get("skip_credentials_validation").(bool),
			SkipRegionValidation:    d.Get("skip_region_validation").(bool),
			SkipRequestingAccountId: d.Get("skip_requesting_account_id").(bool),
			TerraformVersion:        version,
			ApiEndpoint: d.Get("api_endpoint").(string),
		}

		if l, ok := d.Get("assume_role").([]interface{}); ok && len(l) > 0 && l[0] != nil {
			m := l[0].(map[string]interface{})

			if v, ok := m["duration_seconds"].(int); ok && v != 0 {
				config.AssumeRoleDurationSeconds = v
			}

			if v, ok := m["external_id"].(string); ok && v != "" {
				config.AssumeRoleExternalID = v
			}

			if v, ok := m["policy"].(string); ok && v != "" {
				config.AssumeRolePolicy = v
			}

			if policyARNSet, ok := m["policy_arns"].(*schema.Set); ok && policyARNSet.Len() > 0 {
				for _, policyARNRaw := range policyARNSet.List() {
					policyARN, ok := policyARNRaw.(string)

					if !ok {
						continue
					}

					config.AssumeRolePolicyARNs = append(config.AssumeRolePolicyARNs, policyARN)
				}
			}

			if v, ok := m["role_arn"].(string); ok && v != "" {
				config.AssumeRoleARN = v
			}

			if v, ok := m["session_name"].(string); ok && v != "" {
				config.AssumeRoleSessionName = v
			}

			if tagMapRaw, ok := m["tags"].(map[string]interface{}); ok && len(tagMapRaw) > 0 {
				config.AssumeRoleTags = make(map[string]string)

				for k, vRaw := range tagMapRaw {
					v, ok := vRaw.(string)

					if !ok {
						continue
					}

					config.AssumeRoleTags[k] = v
				}
			}

			if transitiveTagKeySet, ok := m["transitive_tag_keys"].(*schema.Set); ok && transitiveTagKeySet.Len() > 0 {
				for _, transitiveTagKeyRaw := range transitiveTagKeySet.List() {
					transitiveTagKey, ok := transitiveTagKeyRaw.(string)

					if !ok {
						continue
					}

					config.AssumeRoleTransitiveTagKeys = append(config.AssumeRoleTransitiveTagKeys, transitiveTagKey)
				}
			}

			log.Printf("[INFO] assume_role configuration set: (ARN: %q, SessionID: %q, ExternalID: %q)", config.AssumeRoleARN, config.AssumeRoleSessionName, config.AssumeRoleExternalID)
		}

		if v, ok := d.GetOk("allowed_account_ids"); ok {
			for _, accountIDRaw := range v.(*schema.Set).List() {
				config.AllowedAccountIds = append(config.AllowedAccountIds, accountIDRaw.(string))
			}
		}

		if v, ok := d.GetOk("forbidden_account_ids"); ok {
			for _, accountIDRaw := range v.(*schema.Set).List() {
				config.ForbiddenAccountIds = append(config.ForbiddenAccountIds, accountIDRaw.(string))
			}
		}

		c, err := config.Client()
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Unable to create API client",
				Detail:   err.Error(),
			})

			return nil, diags
		}
		return c, diags
	}
}

// Client configures and returns a fully initialized ApiClient
func (c *Config) Client() (interface{}, error) {
	// Get the auth and region. This can fail if keys/regions were not
	// specified and we're attempting to use the environment.
	if !c.SkipRegionValidation {
		if err := awsbase.ValidateRegion(c.Region); err != nil {
			return nil, err
		}
	}

	awsbaseConfig := &awsbase.Config{
		AccessKey:                   c.AccessKey,
		AssumeRoleARN:               c.AssumeRoleARN,
		AssumeRoleDurationSeconds:   c.AssumeRoleDurationSeconds,
		AssumeRoleExternalID:        c.AssumeRoleExternalID,
		AssumeRolePolicy:            c.AssumeRolePolicy,
		AssumeRolePolicyARNs:        c.AssumeRolePolicyARNs,
		AssumeRoleSessionName:       c.AssumeRoleSessionName,
		AssumeRoleTags:              c.AssumeRoleTags,
		AssumeRoleTransitiveTagKeys: c.AssumeRoleTransitiveTagKeys,
		CallerDocumentationURL:      "https://registry.terraform.io/providers/cloudandthings/apigw",
		CallerName:                  "APIGW Terraform Provider",
		CredsFilename:               c.CredsFilename,
		DebugLogging:                logging.IsDebugOrHigher(),

		MaxRetries:                  c.MaxRetries,
		Profile:                     c.Profile,
		Region:                      c.Region,
		SecretKey:                   c.SecretKey,
		SkipCredsValidation:         c.SkipCredsValidation,
		SkipRequestingAccountId:     c.SkipRequestingAccountId,

		Token:                       c.Token,
		UserAgentProducts: []*awsbase.UserAgentProduct{
			{Name: "APN", Version: "1.0"},
			{Name: "HashiCorp", Version: "1.0"},
			{Name: "Terraform", Version: c.TerraformVersion, Extra: []string{"+https://www.terraform.io"}},
			{Name: "terraform-provider-aws", Version: "0.0.1-hard-coded", Extra: []string{"+https://registry.terraform.io/providers/hashicorp/aws"}},
		},
	}

	sess, accountID, _, err := awsbase.GetSessionWithAccountIDAndPartition(awsbaseConfig)
	if err != nil {
		return nil, fmt.Errorf("error configuring Terraform AWS Provider: %w", err)
	}

	if accountID == "" {
		log.Printf("[WARN] AWS account ID not found for provider. See https://www.terraform.io/docs/providers/aws/index.html#skip_requesting_account_id for implications.")
	}

	if err := awsbase.ValidateAccountID(accountID, c.AllowedAccountIds, c.ForbiddenAccountIds); err != nil {
		return nil, err
	}

	signer := v4.NewSigner(sess.Config.Credentials)

	client := &ApiClient{
		accountId:        accountID,
		region:           c.Region,
		awsSession:       sess,
		signer :		  signer,
		terraformVersion: c.TerraformVersion,
		apiEndpoint:     c.ApiEndpoint,
	}

	return client, nil
}

func assumeRoleSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"duration_seconds": {
					Type:        schema.TypeInt,
					Optional:    true,
					Description: "Seconds to restrict the assume role session duration.",
				},
				"external_id": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "Unique identifier that might be required for assuming a role in another account.",
				},
				"policy": {
					Type:         schema.TypeString,
					Optional:     true,
					Description:  "IAM Policy JSON describing further restricting permissions for the IAM Role being assumed.",
					ValidateFunc: validation.StringIsJSON,
				},
				"policy_arns": {
					Type:        schema.TypeSet,
					Optional:    true,
					Description: "Amazon Resource Names (ARNs) of IAM Policies describing further restricting permissions for the IAM Role being assumed.",
					Elem: &schema.Schema{
						Type:         schema.TypeString,
						ValidateFunc: validateArn,
					},
				},
				"role_arn": {
					Type:         schema.TypeString,
					Optional:     true,
					Description:  "Amazon Resource Name of an IAM Role to assume prior to making API calls.",
					ValidateFunc: validateArn,
				},
				"session_name": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "Identifier for the assumed role session.",
				},
				"tags": {
					Type:        schema.TypeMap,
					Optional:    true,
					Description: "Assume role session tags.",
					Elem:        &schema.Schema{Type: schema.TypeString},
				},
				"transitive_tag_keys": {
					Type:        schema.TypeSet,
					Optional:    true,
					Description: "Assume role session tag keys to pass to any subsequent sessions.",
					Elem:        &schema.Schema{Type: schema.TypeString},
				},
			},
		},
	}
}