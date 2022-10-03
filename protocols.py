import argparse
import datetime
import json
import logging
import os
import sys
import traceback

import yaml
from wekapyutils.wekalogging import configure_logging, register_module

from wekalib.wekacluster import WekaApi
import wekalib.exceptions

# get root logger
log = logging.getLogger()


class LocalWekaApi():
    def __init__(self, hostname):
        self.api = None
        try:
            self.api = WekaApi(hostname, tokens=get_tokens("auth-token.json"),
                               verify_cert=False, old_format=False)
        except wekalib.exceptions.HTTPError as exc:
            if exc.code == 403:
                log.critical(f"Cluster returned permission error - is the userid level ReadOnly or above?")
                sys.exit(1)
            log.critical(f"Cluster returned HTTP error {exc}; aborting")
            sys.exit(1)
        except wekalib.exceptions.SSLError as exc:
            log.critical(f"SSL Error:")
            log.critical(f"Error is {exc}")
            sys.exit(1)
        except wekalib.exceptions.NewConnectionError as exc:
            log.critical(f"Unable to open api with host {hostname}")
            sys.exit(1)
        except Exception as exc:
            log.critical(f"Unable to create Weka Cluster: {exc}")
            log.critical(traceback.format_exc())
            sys.exit(1)

        self.status = self.call_api(method='status', errortext="Problem getting cluster status", exitonerror=True)


    def call_api(self, method, parms={}, errortext=None, exitonerror=False):
        try:
            return self.api.weka_api_command(method=method, parms=parms)
        except wekalib.exceptions.IOStopped as exc:
            if errortext is not None:
                log.error(f"    {errortext}")
            else:
                log.error(f'    API Exception: {exc.args[0]}')

            if exitonerror:
                sys.exit(1)
        return False

def ip_list_to_range(iplist):
    # iplist is a list of ip addrs, in text
    first_octets = iplist[0].split('.')
    last_octets = iplist[-1:][0].split('.')

    for index in range(0, 4):
        if first_octets[index] != last_octets[index]:
            break

    return iplist[0] + '-' + '.'.join(last_octets[index:])


def find_token_file(token_file):
    search_path = ['.', '~/.weka', '.weka']

    log.info(f"looking for token file {token_file}")
    if token_file is None:
        return None

    test_name = os.path.expanduser(token_file)  # will expand to an absolute path (starts with /) if ~ is used
    log.debug(f"name expanded to {test_name}")

    if test_name[0] == '/':
        # either token_file was already an abssolute path, or expansuser did it's job
        if os.path.exists(test_name):
            return test_name
        else:
            # can't expand a abs path any further, and it does not exist
            return None

    # search for it in the path
    for path in search_path:
        base_path = os.path.expanduser(path)
        test_name = os.path.abspath(f"{base_path}/{token_file}")
        log.info(f"Checking for {test_name}")
        if os.path.exists(test_name):
            log.debug(f"Found '{test_name}'")
            return test_name

    log.debug(f"token file {token_file} not found")
    return None


def get_tokens(filename):
    tokenfile = open(find_token_file(filename), 'r')
    tokens = json.load(tokenfile)
    return tokens


def main():
    # parse arguments
    parser = argparse.ArgumentParser(description='Backup or Restore Weka Protocol configurations',
                                     prog=sys.argv[0])

    # example of how to add a switch-line argument
    parser.add_argument("--backup", dest='backup_flag', action='store_true', help="Backup the configurations")
    parser.add_argument("--delete", dest='delete_configfile', nargs=1, help="Delete the configuration from configfile")
    parser.add_argument("--restore", dest='configfile', nargs=1, help="Restore the configuration from configfile")
    parser.add_argument('--host', type=str, dest='hostname', nargs=1,
                        default=['localhost'], help='Name or ip of a weka host - localhost if not specified')

    # these next args are passed to the script and parsed in etc/preamble - this is more for syntax checking
    parser.add_argument("-v", "--verbose", dest='verbosity', action='store_true', help="enable verbose mode")

    args = parser.parse_args()

    backingup = args.backup_flag
    deleting = args.delete_configfile is not None
    restoring = args.configfile is not None

    actionlist = list()
    if backingup:
        actionlist.append("backingup")
    if deleting:
        actionlist.append("deleting")
        configfile = args.delete_configfile[0]
    if restoring:
        actionlist.append("restoring")
        configfile = args.configfile[0]

    if len(actionlist) == 0:
        parser.print_help()
        log.error(f"You must specify one of --backup, --delete, or --restore")
        sys.exit(1)
    elif len(actionlist) > 1:
        parser.print_help()
        log.error(f"You must specify only ONE of --backup, --delete, or --restore")
        sys.exit(1)

    # local modules - override a module's logging level
    register_module("wekalib.wekaapi", logging.CRITICAL)

    # set up logging in a standard way...
    configure_logging(log, args.verbosity)

    api = LocalWekaApi(args.hostname[0])
    clustername = api.status['name']

    config = dict()
    if backingup:
        method_list = [
            # "s3_bucket_list",
            # "s3_get_cluster_info",
            # "s3_policy_list",
            # "s3_user_policy_list",
            # "s3_bucket_get_policy",
            # "s3_get_containers_config_gen",
            # "minio_policy_list",
            # "minio_user_list",
            "samba_get_cluster_info",
            "samba_host_access_cluster_list",
            "samba_host_access_share_list",
            "nfs_permission_list",
            "interface_group_list",
            "client_group_list",
            "get_nfs_custom_options",
            "tls_status",
            "tls_download_certificate"
        ]
        log.info(f"Backing up Weka Cluster {clustername}")
        for method in method_list:
            config[method] = api.call_api(method, exitonerror=True)

        now = datetime.datetime.now()
        filename = args.hostname[0] + "_" + now.strftime("%d%m%Y-%H%M%S") + ".cfg"
        log.info(f"Writing config to {filename}")
        stream = open(filename, 'w')
        yaml.dump(config, stream)
        sys.exit(0)

    log.info(f"Reading {configfile}")

    try:
        with open(configfile, 'r') as stream:
            config = yaml.safe_load(stream)
    except Exception as exc:
        log.error(f"Error loading config file: {exc}")
        sys.exit(1)

    log.info("Configuration loaded")

    error_message = 'API Exception: {exc.args[0]}'  # default message
    if restoring:
        log.info(f"Restoring from {configfile}")
        # load the config...

        # create NFS
        for interface_group in config['interface_group_list']:
            log.info(f"  Creating NFS interface group {interface_group['name']}")
            parms = {'name': interface_group['name'],
                     'type': interface_group['type'],
                     'gateway': interface_group['gateway'],
                     'subnet': interface_group['subnet_mask'],
                     'allow_manage_gids': interface_group['allow_manage_gids']}
            api.call_api('interface_group_create', parms=parms)

            for port in interface_group['ports']:
                log.info(f"  Creating NFS interface group {interface_group['name']} port {port['port']}")
                parms = {'name': interface_group['name'], 'host_id': port['host_id'], 'port': port['port']}
                api.call_api('interface_group_add_port', parms=parms)

            log.info(f"  Creating NFS interface group {interface_group['name']} ip-range")

            if len(interface_group['ips']) != 0:
                parms = {'name': interface_group['name'], 'ips': ip_list_to_range(interface_group['ips'])}
                api.call_api('interface_group_add_ip_range', parms=parms)

        # restore SMB
        log.info(f"Restoring SMB Cluster {config['samba_get_cluster_info']['name']}")
        Samba = config['samba_get_cluster_info']
        parms = {
            'name': Samba['name'],
            'sambaHosts': Samba['sambaHosts'],
            'sambaIps': Samba['sambaIps'],
            'domain': Samba['domainName'],
            'domainNetbiosName': Samba['domainNetbiosName'],
            'idmapBackend': Samba['idmapBackend'],
            'smbConfExtra': Samba['smbConfExtra'],
            'defaultDomainMappingFromId': Samba['defaultDomainMappingFromId'],
            'defaultDomainMappingToId': Samba['defaultDomainMappingToId'],
            'joinedDomainMappingFromId': Samba['joinedDomainMappingFromId'],
            'joinedDomainMappingToId': Samba['joinedDomainMappingToId'],
            'encryption': Samba['encryption']
        }
        api.call_api('samba_set_cluster_info', parms=parms)

    elif deleting:
        log.info(f"Deleting from {configfile}")
        # remove the config

        # delete NFS
        log.info(f"Removing NFS interface groups")
        for interface_group in config['interface_group_list']:
            log.info(f"  Removing NFS interface group {interface_group['name']} ip-range")
            if len(interface_group['ips']) != 0:
                parms = {'name': interface_group['name'], 'ips': ip_list_to_range(interface_group['ips'])}
                api.call_api('interface_group_delete_ip_range', parms=parms)

            for port in interface_group['ports']:
                log.info(f"  Removing NFS interface group {interface_group['name']} port {port['port']}")
                parms = {'name': interface_group['name'], 'host_id': port['host_id'], 'port': port['port']}
                api.call_api('interface_group_delete_port', parms=parms)

            log.info(f"  Removing NFS interface group {interface_group['name']}")
            parms = {'name': interface_group['name']}
            api.call_api('interface_group_delete', parms=parms)

        # delete SMB
        if config['samba_get_cluster_info']['name'] is None:
            log.info("No SMB Cluster defined")
        else:
            log.info(f"Removing SMB Cluster {config['samba_get_cluster_info']['name']}")
            api.call_api('samba_clear_cluster_info')
        # delete S3

    else:
        log.error("Vince messed up")

    print("complete")


if __name__ == '__main__':
    main()
