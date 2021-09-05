package provider

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"log"
	"net/http"
)

func dataSourceScaffolding() *schema.Resource {
	return &schema.Resource{
		// This description is used by the documentation generator and the language server.
		Description: "Sample data source in the Terraform provider scaffolding.",

		ReadContext: dataSourceScaffoldingRead,

		Schema: map[string]*schema.Schema{
			"sample_attribute": {
				// This description is used by the documentation generator and the language server.
				Description: "Sample attribute.",
				Type:        schema.TypeString,
				Required:    true,
			},
		},
	}
}

func dataSourceScaffoldingRead(_ context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	client := meta.(*ApiClient)
	statusCode, response, err := request(client, http.MethodGet, "resource", nil)

	fmt.Println(fmt.Sprintf("statusCode:%d",statusCode))
	if err != nil {
		log.Println(err)
	}
	fmt.Println(string(response))

	idFromAPI := "my-id"
	d.SetId(idFromAPI)

	return diags
}