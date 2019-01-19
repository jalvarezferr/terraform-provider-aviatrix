package aviatrix

import (
	"fmt"
	"log"
	"strings"

	"github.com/AviatrixSystems/go-aviatrix/goaviatrix"
	"github.com/hashicorp/terraform/helper/schema"
)

func resourceAviatrixGateway() *schema.Resource {
	return &schema.Resource{
		Create: resourceAviatrixGatewayCreate,
		Read:   resourceAviatrixGatewayRead,
		Update: resourceAviatrixGatewayUpdate,
		Delete: resourceAviatrixGatewayDelete,
		Importer: &schema.ResourceImporter{
			State: resourceAviatrixGatewayImportState,
		},

		Schema: map[string]*schema.Schema{
			"cloud_type": {
				Type:     schema.TypeInt,
				Required: true,
			},
			"account_name": {
				Type:     schema.TypeString,
				Required: true,
			},
			"gw_name": {
				Type:     schema.TypeString,
				Required: true,
			},
			"vpc_id": {
				Type:     schema.TypeString,
				Required: true,
			},
			"vpc_reg": {
				Type:     schema.TypeString,
				Required: true,
			},
			"vpc_size": {
				Type:     schema.TypeString,
				Required: true,
			},
			"vpc_net": {
				Type:     schema.TypeString,
				Required: true,
			},
			"ha_subnet": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"public_ip": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"backup_public_ip": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"security_group_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"enable_nat": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"dns_server": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"public_dns_server": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"vpn_access": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"cidr": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"enable_elb": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"elb_name": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"split_tunnel": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"otp_mode": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"saml_enabled": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"okta_token": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"okta_url": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"okta_username_suffix": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"duo_integration_key": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"duo_secret_key": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"duo_api_hostname": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"duo_push_mode": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"enable_ldap": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"ldap_server": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"ldap_bind_dn": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"ldap_password": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"ldap_base_dn": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"ldap_username_attribute": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"public_subnet": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"zone": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"cloud_instance_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"cloudn_bkup_gateway_inst_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"single_az_ha": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"allocate_new_eip": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"eip": {
				Type:     schema.TypeString,
				Optional: true,
			},
		},
	}
}

func resourceAviatrixGatewayImportState(
	d *schema.ResourceData,
	meta interface{}) ([]*schema.ResourceData, error) {
	
	client := meta.(*goaviatrix.Client)
	result := resourceAviatrixGateway()
	r := result.Data(nil)

    substr := strings.Split(d.Id(),"@")
    account_name := substr[1]
    gateway_name := substr[0]	
	
	r.SetId (gateway_name)
	
	gateway := &goaviatrix.Gateway{
		GwName:      gateway_name,
		AccountName: account_name,
	}
	gw, err := client.GetGateway(gateway)
	if err != nil {
		if err == goaviatrix.ErrNotFound {
			return nil,fmt.Errorf("Gateway %s not found", gateway.GwName)
		}
		return nil,fmt.Errorf("Couldn't get Aviatrix Gateway data for import: %s", err)
	}
	
	r.Set("cloud_type",gw.CloudType)
	r.Set("account_name",gw.AccountName)
	r.Set("gw_name",gw.GwName)
	r.Set("vpc_id",strings.Split(gw.VpcID,"~~")[0])
	r.Set("vpc_reg",gw.VpcRegion)
	if gw.VpcNet != "" { r.Set("vpc_net",gw.VpcNet) }
	if gw.EnableNat != ""  { r.Set("enable_nat",gw.EnableNat) }
	if gw.DnsServer != "" { r.Set("dns_server",gw.DnsServer) }
	if gw.VpnStatus != "" { r.Set("vpn_access",gw.VpnStatus) }
	if gw.VpnCidr != "" { r.Set("cidr",gw.VpnCidr) }
	if gw.ElbState == "enabled" {
	    r.Set("enable_elb","yes")
	} else {
	    r.Set("enable_elb","no")
	}
	if gw.SplitTunnel != "" { r.Set("split_tunnel",gw.SplitTunnel) }
	if gw.OtpMode != "" { r.Set("otp_mode",gw.OtpMode) }
	if gw.SamlEnabled != "" { r.Set("saml_enabled",gw.SamlEnabled) }
	if gw.OktaToken != "" { r.Set("okta_token",gw.OktaToken) }
	if gw.OktaURL != "" { r.Set("okta_url",gw.OktaURL) }
	if gw.OktaUsernameSuffix != "" { r.Set("okta_username_suffix",gw.OktaUsernameSuffix) }
	if gw.DuoIntegrationKey != "" { r.Set("duo_integration_key",gw.DuoIntegrationKey) }
	if gw.DuoSecretKey != "" { r.Set("duo_secret_key",gw.DuoSecretKey) }
	if gw.DuoAPIHostname != "" { r.Set("duo_api_hostname",gw.DuoAPIHostname) }
	if gw.DuoPushMode != "" { r.Set("duo_push_mode",gw.DuoPushMode) }
	if gw.EnableLdap != "" { r.Set("enable_ldap",gw.EnableLdap) }
	if gw.LdapServer != "" { r.Set("ldap_server",gw.LdapServer) }
	if gw.LdapBindDn!= "" { r.Set("ldap_bind_dn",gw.LdapBindDn) }
	if gw.LdapPassword != "" { r.Set("ldap_password",gw.LdapPassword) }
	if gw.LdapBaseDn != "" { r.Set("ldap_base_dn",gw.LdapBaseDn) }
	if gw.LdapUserAttr != "" { r.Set("ldap_username_attribute",gw.LdapUserAttr) }
	if gw.HASubnet != "" { r.Set("ha_subnet",gw.HASubnet) }
	if gw.PeeringHASubnet != "" { r.Set("public_subnet",gw.PeeringHASubnet) }
	if gw.NewZone != "" { r.Set("zone",gw.NewZone) }
	if gw.SingleAZ != "" { r.Set("single_az_ha",gw.SingleAZ) }
//	r.Set("allocate_new_eip",gw.AllocateNewEip)
	if gw.Eip != "" { r.Set("eip",gw.Eip) }
	r.Set("public_ip",gw.PublicIP)
	
	r.SetType("aviatrix_gateway")
	
	err = resourceAviatrixGatewayRead(r,meta)
	if err != nil {
	    return nil,fmt.Errorf("[ERROR] Could not import gateway resource: %s",err)
    }
	results := make([]*schema.ResourceData, 1,1)
	results[0] = r
    return results, nil
}

func resourceAviatrixGatewayCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*goaviatrix.Client)
	gateway := &goaviatrix.Gateway{
		CloudType:          d.Get("cloud_type").(int),
		AccountName:        d.Get("account_name").(string),
		GwName:             d.Get("gw_name").(string),
		VpcID:              d.Get("vpc_id").(string),
		VpcRegion:          d.Get("vpc_reg").(string),
		VpcSize:            d.Get("vpc_size").(string),
		VpcNet:             d.Get("vpc_net").(string),
		EnableNat:          d.Get("enable_nat").(string),
		DnsServer:          d.Get("dns_server").(string),
		VpnStatus:          d.Get("vpn_access").(string),
		VpnCidr:            d.Get("cidr").(string),
		EnableElb:          d.Get("enable_elb").(string),
		ElbName:            d.Get("elb_name").(string),
		SplitTunnel:        d.Get("split_tunnel").(string),
		OtpMode:            d.Get("otp_mode").(string),
		SamlEnabled:        d.Get("saml_enabled").(string),
		OktaToken:          d.Get("okta_token").(string),
		OktaURL:            d.Get("okta_url").(string),
		OktaUsernameSuffix: d.Get("okta_username_suffix").(string),
		DuoIntegrationKey:  d.Get("duo_integration_key").(string),
		DuoSecretKey:       d.Get("duo_secret_key").(string),
		DuoAPIHostname:     d.Get("duo_api_hostname").(string),
		DuoPushMode:        d.Get("duo_push_mode").(string),
		EnableLdap:         d.Get("enable_ldap").(string),
		LdapServer:         d.Get("ldap_server").(string),
		LdapBindDn:         d.Get("ldap_bind_dn").(string),
		LdapPassword:       d.Get("ldap_password").(string),
		LdapBaseDn:         d.Get("ldap_base_dn").(string),
		LdapUserAttr:       d.Get("ldap_username_attribute").(string),
		HASubnet:           d.Get("ha_subnet").(string),
		PeeringHASubnet:    d.Get("public_subnet").(string),
		NewZone:            d.Get("zone").(string),
		SingleAZ:           d.Get("single_az_ha").(string),
		AllocateNewEip:     d.Get("allocate_new_eip").(string),
		Eip:                d.Get("eip").(string),
	}

	log.Printf("[INFO] Creating Aviatrix gateway: %#v", gateway)

	err := client.CreateGateway(gateway)
	if err != nil {
		log.Printf("[INFO] failed to create Aviatrix gateway: %#v", gateway)
		return fmt.Errorf("failed to create Aviatrix gateway: %s", err)
	}
	if enableNAT := d.Get("enable_nat").(string); enableNAT == "yes" {
		log.Printf("[INFO] Aviatrix NAT enabled gateway: %#v", gateway)
	}
	if DNSServer := d.Get("dns_server").(string); DNSServer != "" {
		log.Printf("[INFO] Aviatrix gateway DNS server: %#v", gateway)
	}
	// single_AZ enabled for Gateway. https://docs.aviatrix.com/HowTos/gateway.html#high-availability
	if singleAZHA := d.Get("single_az_ha").(string); singleAZHA == "enabled" {
		singleAZGateway := &goaviatrix.Gateway{
			GwName:   d.Get("gw_name").(string),
			SingleAZ: d.Get("single_az_ha").(string),
		}
		log.Printf("[INFO] Enable Single AZ GW HA: %#v", singleAZGateway)
		err := client.EnableSingleAZGateway(gateway)
		if err != nil {
			return fmt.Errorf("failed to create single AZ GW HA: %s", err)
		}
	}

	// ha_subnet is for Gateway HA. Deprecated. https://docs.aviatrix.com/HowTos/gateway.html#high-availability
	if ha_subnet := d.Get("ha_subnet").(string); ha_subnet != "" {
		ha_gateway := &goaviatrix.Gateway{
			GwName:   d.Get("gw_name").(string),
			HASubnet: d.Get("ha_subnet").(string),
		}
		log.Printf("[INFO] Enable gateway HA: %#v", ha_gateway)
		err := client.EnableHaGateway(ha_gateway)
		if err != nil {
			del_err := client.DeleteGateway(gateway)
			if del_err != nil {
				return fmt.Errorf("failed to auto-cleanup failed gateway: %s", del_err)
			}
			return fmt.Errorf("failed to create GW HA: %s", err)
		}
	}
	// public_subnet is for Peering HA Gateway. https://docs.aviatrix.com/HowTos/gateway.html#high-availability
	if public_subnet := d.Get("public_subnet").(string); public_subnet != "" {
		ha_gateway := &goaviatrix.Gateway{
			GwName:          d.Get("gw_name").(string),
			PeeringHASubnet: d.Get("public_subnet").(string),
			NewZone:         d.Get("zone").(string),
		}
		log.Printf("[INFO] Enable peering HA: %#v", ha_gateway)
		err := client.EnablePeeringHaGateway(ha_gateway)
		if err != nil {
			return fmt.Errorf("failed to create peering HA: %s", err)
		}
	}
	d.SetId(gateway.GwName)
	return resourceAviatrixGatewayRead(d, meta)
}

func resourceAviatrixGatewayRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*goaviatrix.Client)
	gateway := &goaviatrix.Gateway{
		AccountName: d.Get("account_name").(string),
		GwName:      d.Get("gw_name").(string),
	}
	if d.Get("single_az_ha") != nil {
		gateway.SingleAZ = d.Get("single_az_ha").(string)
	}
	gw, err := client.GetGateway(gateway)
	if err != nil {
		if err == goaviatrix.ErrNotFound {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("couldn't find Aviatrix Gateway: %s", err)
	}
	log.Printf("[TRACE] reading gateway %s: %#v", d.Get("gw_name").(string), gw)
	if gw != nil {
		d.Set("vpc_size", gw.GwSize)
		d.Set("public_ip", gw.PublicIP)
		d.Set("cloud_instance_id", gw.CloudnGatewayInstID)
		d.Set("public_dns_server", gw.PublicDnsServer)
		d.Set("security_group_id", gw.GwSecurityGroupID)
		d.Set("elb_name", gw.ElbName)

		if publicSubnet := d.Get("public_subnet").(string); publicSubnet != "" {
			gateway.GwName += "-hagw"
			gw, err := client.GetGateway(gateway)
			if err == nil {
				d.Set("cloudn_bkup_gateway_inst_id", gw.CloudnGatewayInstID)
				d.Set("backup_public_ip", gw.PublicIP)
			}
			log.Printf("[TRACE] reading peering HA gateway %s: %#v", d.Get("gw_name").(string), gw)
		}
	}
	return nil
}

func resourceAviatrixGatewayUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*goaviatrix.Client)
	gateway := &goaviatrix.Gateway{
		GwName:   d.Get("gw_name").(string),
		GwSize:   d.Get("vpc_size").(string),
		SingleAZ: d.Get("single_az_ha").(string),
	}

	log.Printf("[INFO] Updating Aviatrix gateway: %#v", gateway)

	err := client.UpdateGateway(gateway)
	if err != nil {
		return fmt.Errorf("failed to update Aviatrix Gateway: %s", err)
	}
	d.SetId(gateway.GwName)
	return nil
}

func resourceAviatrixGatewayDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*goaviatrix.Client)
	gateway := &goaviatrix.Gateway{
		CloudType: d.Get("cloud_type").(int),
		GwName:    d.Get("gw_name").(string),
	}
	// ha_subnet is for Gateway HA
	if HASubnet := d.Get("ha_subnet").(string); HASubnet != "" {
		log.Printf("[INFO] Deleting Aviatrix gateway HA: %#v", gateway)
		err := client.DisableHaGateway(gateway)
		if err != nil {
			return fmt.Errorf("failed to disable Aviatrix gateway HA: %s", err)
		}
	}
	// public_subnet is for Peering HA
	if publicSubnet := d.Get("public_subnet").(string); publicSubnet != "" {
		//Delete backup gateway first
		gateway.GwName += "-hagw"
		log.Printf("[INFO] Deleting Aviatrix Backup Gateway [-hagw]: %#v", gateway)
		err := client.DeleteGateway(gateway)
		if err != nil {
			return fmt.Errorf("failed to delete backup [-hgw] gateway: %s", err)
		}
	}
	gateway.GwName = d.Get("gw_name").(string)
	log.Printf("[INFO] Deleting Aviatrix gateway: %#v", gateway)
	err := client.DeleteGateway(gateway)
	if err != nil {
		return fmt.Errorf("failed to delete Aviatrix Gateway: %s", err)
	}
	return nil
}
