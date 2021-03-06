package aviatrix

import (
	"fmt"
	"log"
	"strings"

	"github.com/AviatrixSystems/go-aviatrix/goaviatrix"
	"github.com/hashicorp/terraform/helper/schema"
)

func resourceAviatrixSpokeVpc() *schema.Resource {
	return &schema.Resource{
		Create: resourceAviatrixSpokeVpcCreate,
		Read:   resourceAviatrixSpokeVpcRead,
		Update: resourceAviatrixSpokeVpcUpdate,
		Delete: resourceAviatrixSpokeVpcDelete,

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
				Optional: true,
			},
			"vnet_and_resource_group_names": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"vpc_reg": {
				Type:     schema.TypeString,
				Required: true,
			},
			"vpc_size": {
				Type:     schema.TypeString,
				Required: true,
			},
			"subnet": {
				Type:     schema.TypeString,
				Required: true,
			},
			"enable_nat": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"ha_subnet": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"ha_gw_size": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"dns_server": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"transit_gw": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"tag_list": {
				Type:     schema.TypeList,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Optional: true,
			},
			"cloud_instance_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func resourceAviatrixSpokeVpcCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*goaviatrix.Client)
	gateway := &goaviatrix.SpokeVpc{
		CloudType:      d.Get("cloud_type").(int),
		AccountName:    d.Get("account_name").(string),
		GwName:         d.Get("gw_name").(string),
		VpcID:          d.Get("vpc_id").(string),
		VnetRsrcGrp:    d.Get("vnet_and_resource_group_names").(string),
		VpcRegion:      d.Get("vpc_reg").(string),
		VpcSize:        d.Get("vpc_size").(string),
		Subnet:         d.Get("subnet").(string),
		HASubnet:       d.Get("ha_subnet").(string),
		EnableNAT:      d.Get("enable_nat").(string),
		DnsServer:      d.Get("dns_server").(string),
		TransitGateway: d.Get("transit_gw").(string),
	}
	if cloudType := d.Get("cloud_type").(int); cloudType == 1 {
		gateway.VnetRsrcGrp = ""
		d.Set("vnet_and_resource_group_names", gateway.VnetRsrcGrp)
	}
	if cloudType := d.Get("cloud_type").(int); cloudType == 8 {
		gateway.VpcID = ""
		d.Set("vpc_id", gateway.VpcID)
	}
	if _, ok := d.GetOk("tag_list"); ok {
		tagList := d.Get("tag_list").([]interface{})
		tagListStr := goaviatrix.ExpandStringList(tagList)
		gateway.TagList = strings.Join(tagListStr, ",")
	}
	log.Printf("[INFO] Creating Aviatrix Spoke VPC: %#v", gateway)

	err := client.LaunchSpokeVpc(gateway)
	if err != nil {
		return fmt.Errorf("failed to create Aviatrix Spoke VPC: %s", err)
	}
	haSubnet := d.Get("ha_subnet").(string)
	haGwSize := d.Get("ha_gw_size").(string)
	transitGwName := d.Get("transit_gw").(string)
	d.SetId(gateway.GwName)
	d.Set("ha_subnet", "")
	d.Set("ha_gw_size", "")
	d.Set("transit_gw", "")
	if haSubnet != "" {
		//Enable HA
		haGateway := &goaviatrix.SpokeVpc{
			GwName:   d.Get("gw_name").(string),
			HASubnet: haSubnet,
		}

		err = client.EnableHaSpokeVpc(haGateway)
		if err != nil {
			return fmt.Errorf("failed to enable HA Aviatrix TransitVpc: %s", err)
		}
		d.Set("ha_subnet", haSubnet)
		d.Set("ha_gw_size", gateway.VpcSize)

		log.Printf("[INFO]Resizing Spoke HA Gateway: %#v", haGwSize)
		if haGwSize != gateway.VpcSize {
			if haGwSize == "" {
				return fmt.Errorf("A valid non empty ha_gw_size parameter is mandatory for this resource if " +
					"ha_subnet is set. Example: t2.micro")
			}
			haGateway := &goaviatrix.Gateway{
				CloudType: d.Get("cloud_type").(int),
				GwName:    d.Get("gw_name").(string) + "-hagw",
			}
			haGateway.GwSize = d.Get("ha_gw_size").(string)
			err := client.UpdateGateway(haGateway)
			log.Printf("[INFO] Resizing Spoke HA GAteway size to: %s ", haGateway.GwSize)
			if err != nil {
				return fmt.Errorf("failed to update Aviatrix Transit HA Gateway size: %s", err)
			}
			d.Set("ha_gw_size", haGwSize)
		}
	}

	if transitGwName != "" {
		//No HA config, just return
		err := client.SpokeJoinTransit(gateway)
		if err != nil {
			return fmt.Errorf("failed to join TransitVpc: %s", err)
		}
		d.Set("transit_gw", transitGwName)
	}

	return resourceAviatrixSpokeVpcRead(d, meta)
}

func resourceAviatrixSpokeVpcRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*goaviatrix.Client)
	gateway := &goaviatrix.Gateway{
		AccountName: d.Get("account_name").(string),
		GwName:      d.Get("gw_name").(string),
	}
	gw, err := client.GetGateway(gateway)
	if err != nil {
		if err == goaviatrix.ErrNotFound {
			d.SetId("")
			return nil
		}
		return fmt.Errorf("couldn't find Aviatrix SpokeVpc: %s", err)
	}
	log.Printf("[TRACE] reading spoke gateway %s: %#v",
		d.Get("gw_name").(string), gw)
	if gw != nil {
		d.Set("vpc_size", gw.GwSize)
		d.Set("public_ip", gw.PublicIP)
		d.Set("cloud_instance_id", gw.CloudnGatewayInstID)
	}
	haGateway := &goaviatrix.Gateway{
		AccountName: d.Get("account_name").(string),
		GwName:      d.Get("gw_name").(string) + "-hagw",
	}
	haGw, err := client.GetGateway(haGateway)
	if err != nil {
		if err == goaviatrix.ErrNotFound {
			d.Set("ha_gw_size", "")
			d.Set("ha_subnet", "")
			return nil
		}
		return fmt.Errorf("couldn't find Aviatrix SpokeVpc HA Gateway: %s", err)
	}
	log.Printf("[INFO] Spoke HA Gateway size: %s", haGw.GwSize)
	d.Set("ha_gw_size", haGw.GwSize)
	//d.SetPartial("ha_subnet")

	return nil
}

func resourceAviatrixSpokeVpcUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*goaviatrix.Client)
	gateway := &goaviatrix.Gateway{
		CloudType: d.Get("cloud_type").(int),
		GwName:    d.Get("gw_name").(string),
	}
	haGateway := &goaviatrix.Gateway{
		CloudType: d.Get("cloud_type").(int),
		GwName:    d.Get("gw_name").(string) + "-hagw",
	}
	log.Printf("[INFO] Updating Aviatrix gateway: %#v", gateway)

	d.Partial(true)
	if d.HasChange("tag_list") {
		tags := &goaviatrix.Tags{
			CloudType:    1,
			ResourceType: "gw",
			ResourceName: d.Get("gw_name").(string),
		}
		o, n := d.GetChange("tag_list")
		if o == nil {
			o = new([]interface{})
		}
		if n == nil {
			n = new([]interface{})
		}
		os := o.([]interface{})
		ns := n.([]interface{})
		oldTagList := goaviatrix.ExpandStringList(os)
		tags.TagList = strings.Join(oldTagList, ",")
		err := client.DeleteTags(tags)
		if err != nil {
			return fmt.Errorf("failed to delete tags : %s", err)
		}
		newTagList := goaviatrix.ExpandStringList(ns)
		tags.TagList = strings.Join(newTagList, ",")
		err = client.AddTags(tags)
		if err != nil {
			return fmt.Errorf("failed to add tags : %s", err)
		}
		d.SetPartial("tag_list")
	}
	if d.HasChange("vpc_size") {
		gateway.GwSize = d.Get("vpc_size").(string)
		err := client.UpdateGateway(gateway)
		if err != nil {
			return fmt.Errorf("failed to update Aviatrix SpokeVpc: %s", err)
		}
		d.SetPartial("vpc_size")
	}

	if d.HasChange("ha_subnet") {
		spokeGateway := &goaviatrix.SpokeVpc{
			GwName:   d.Get("gw_name").(string),
			HASubnet: d.Get("ha_subnet").(string),
		}

		o, n := d.GetChange("ha_subnet")
		if o == "" {
			//New configuration to enable HA
			err := client.EnableHaSpokeVpc(spokeGateway)
			if err != nil {
				return fmt.Errorf("failed to enable HA Aviatrix SpokeVpc: %s", err)
			}
		} else if n == "" {
			//Ha configuration has been deleted
			err := client.DeleteGateway(haGateway)
			if err != nil {
				return fmt.Errorf("failed to delete Aviatrix SpokeVpc HA gateway: %s", err)
			}
		} else {
			//HA subnet has been modified. Delete older HA GW,
			// and launch new HA GW in new subnet.
			err := client.DeleteGateway(haGateway)
			if err != nil {
				return fmt.Errorf("failed to delete Aviatrix SpokeVpc HA gateway: %s", err)
			}

			gateway.GwName = d.Get("gw_name").(string)
			//New configuration to enable HA
			haErr := client.EnableHaSpokeVpc(spokeGateway)
			if haErr != nil {
				return fmt.Errorf("failed to enable HA Aviatrix SpokeVpc: %s", err)
			}
		}
		d.SetPartial("ha_subnet")
	}
	if d.HasChange("ha_gw_size") {
		_, err := client.GetGateway(haGateway)
		if err != nil {
			if err == goaviatrix.ErrNotFound {
				d.Set("ha_gw_size", "")
				d.Set("ha_subnet", "")
				return nil
			}
			return fmt.Errorf("couldn't find Aviatrix Spoke HA Gateway while trying to update HA Gw "+
				"size: %s", err)
		}
		haGateway.GwSize = d.Get("ha_gw_size").(string)
		if haGateway.GwSize == "" {
			return fmt.Errorf("A valid non empty ha_gw_size parameter is mandatory for this resource if " +
				"ha_subnet is set. Example: t2.micro")
		}
		err = client.UpdateGateway(haGateway)
		log.Printf("[INFO] Updating HA GAteway size to: %s ", haGateway.GwSize)
		if err != nil {
			return fmt.Errorf("failed to update Aviatrix Spoke HA Gw size: %s", err)
		}
		d.SetPartial("ha_gw_size")
	}
	if d.HasChange("transit_gw") {
		spokeVPC := &goaviatrix.SpokeVpc{
			CloudType:      d.Get("cloud_type").(int),
			GwName:         d.Get("gw_name").(string),
			HASubnet:       d.Get("ha_subnet").(string),
			TransitGateway: d.Get("transit_gw").(string),
		}

		o, n := d.GetChange("transit_gw")
		if o == "" {
			//New configuration to join to transit GW
			err := client.SpokeJoinTransit(spokeVPC)
			if err != nil {
				return fmt.Errorf("failed to join transit VPC: %s", err)
			}
		} else if n == "" {
			//Transit GW has been deleted, leave transit GW.
			err := client.SpokeLeaveTransit(spokeVPC)
			if err != nil {
				return fmt.Errorf("failed to leave transit VPC: %s", err)
			}
		} else {
			//Change transit GW
			err := client.SpokeLeaveTransit(spokeVPC)
			if err != nil {
				return fmt.Errorf("failed to leave transit VPC: %s", err)
			}

			err = client.SpokeJoinTransit(spokeVPC)
			if err != nil {
				return fmt.Errorf("failed to join transit VPC: %s", err)
			}
		}
		d.SetPartial("transit_gw")

	}
	d.Partial(false)
	//d.SetId(gateway.GwName)
	return nil
}

func resourceAviatrixSpokeVpcDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*goaviatrix.Client)
	gateway := &goaviatrix.Gateway{
		CloudType: d.Get("cloud_type").(int),
		GwName:    d.Get("gw_name").(string),
	}

	log.Printf("[INFO] Deleting Aviatrix Spoke VPC: %#v", gateway)

	if transitGw := d.Get("transit_gw").(string); transitGw != "" {
		spokeVPC := &goaviatrix.SpokeVpc{
			GwName: d.Get("gw_name").(string),
		}

		err := client.SpokeLeaveTransit(spokeVPC)
		if err != nil {
			return fmt.Errorf("failed to leave transit VPC: %s", err)
		}
	}

	//If HA is enabled, delete HA GW first.
	if haSubnet := d.Get("ha_subnet").(string); haSubnet != "" {
		//Delete HA Gw too
		gateway.GwName += "-hagw"
		err := client.DeleteGateway(gateway)
		if err != nil {
			return fmt.Errorf("failed to delete Aviatrix SpokeVpc HA gateway: %s", err)
		}
	}
	gateway.GwName = d.Get("gw_name").(string)
	err := client.DeleteGateway(gateway)
	if err != nil {
		return fmt.Errorf("failed to delete Aviatrix SpokeVpc: %s", err)
	}
	return nil
}
