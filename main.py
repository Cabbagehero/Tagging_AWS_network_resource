import network_tagging
import tag_repo


def main():
    for i in tag_repo.region:
        for j in tag_repo.account_profile:
            print(j)
            print('In region ' + i + ' now, and working on account ' + j)
            client = network_tagging.requesting_client(i)
            # print(client)
            network_tagging.tagging_vpcs(i, j)
            network_tagging.tagging_subnets(i, j)
            network_tagging.tagging_routetables(i, j)
            network_tagging.tagging_igws(i,j)
            network_tagging.tagging_pxc(i, j)
            network_tagging.tagging_natgw(i, j)
            network_tagging.tagging_vgw(i, j)
            network_tagging.tagging_vpce(i, j)
            network_tagging.tagging_network_acl(i, j)
            network_tagging.tagging_tgw_attachment(i, j)
            network_tagging.tagging_eips(i, j)
            network_tagging.tagging_certificate(i, j)
            network_tagging.tagging_dxconns(i, j)
            network_tagging.tagging_dxvif(i, j)

if __name__ == '__main__':
    main()
