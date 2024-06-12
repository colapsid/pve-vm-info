#!/usr/bin/python3
# -*- coding: UTF-8 -*-

import re
import os
import sys
import getpass
import urllib3
import datetime
import argparse
from proxmoxer import ProxmoxAPI
from colorama import Fore

class GetPassword(argparse.Action):
    def __call__(self, parser, nm, values, option_string=None):
        if values is None:
            values = getpass.getpass(prompt = 'Enter password: ')
        setattr(nm, self.dest, values)

parser = argparse.ArgumentParser(prog='pve-vm-info', description='Get VM info', epilog='RK CIT 2024')
parser.add_argument('-s', '--server',   type=str, default='localhost',           help='PVE hostname or IP')
parser.add_argument('-n', '--vmname',   type=str, default=None,                  help='Search by VM name')
parser.add_argument('-i', '--vmid',     type=str, default=None,                  help='Search by VM ID')
parser.add_argument('-a', '--ipv4addr', type=str, default=None,                  help='Search by VM IPv4 address')
parser.add_argument('-u', '--user',     type=str, default=None,                  help='PVE user')
parser.add_argument('-p', '--passwd',   type=str, action=GetPassword, nargs='?', help='PVE password')
parser.add_argument('--ssl',            type=str, default='False',               help='Use secure connection, <True|False>')
parser.add_argument('-t', '--template', type=str, default='False',               help='Search VM templates too, <True|False>')
nm = parser.parse_args(sys.argv[1:])

pve_host = nm.server
pve_user = nm.user
pve_pass = nm.passwd
vm_name  = nm.vmname
vm_id    = nm.vmid
vm_ip    = nm.ipv4addr
sec      = nm.ssl
template = nm.template

# Get user from env 'PVE_VM_INFO_USER'
if not pve_user: 
    pve_user = os.environ.get('PVE_VM_INFO_USER')

# Get pass from env 'PVE_VM_INFO_PASS'
if not pve_pass:
    pve_pass = os.environ.get('PVE_VM_INFO_PASS')

# Secure connection
if sec == 'False':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    print(f"{Fore.LIGHTBLUE_EX}Connecting to {pve_host}...{Fore.RESET}")
    try:
        proxmox = ProxmoxAPI(pve_host, user=pve_user, password=pve_pass, verify_ssl=False, )
    except Exception as eggog:
        print(f"{Fore.RED}{eggog}. Failed to connect to {pve_host}...{Fore.RESET}")
        sys.exit(1)
elif sec == 'True':
    print("Note: You may use this variable 'export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt' to working secure connection.")
    print(f"{Fore.LIGHTBLUE_EX}Connecting to {pve_host}...{Fore.RESET}")
    try:
        proxmox = ProxmoxAPI(pve_host, user=pve_user, password=pve_pass)
    except Exception as eggog:
        print(f"{Fore.RED}{eggog}. Failed to connect to {pve_host}...{Fore.RESET}")
        sys.exit(1)
else:
    print(f"{Fore.RED}Unknown option '--ssl {sec}'...{Fore.RESET}")
    sys.exit(1)

# b_convert()
def b_convert(size):
    if 1000000 <= size < 1000000000:
        return '%.1f' % float(size/1000000)       + ' Mb'
    elif 1000000000 <= size < 1000000000000:
        return '%.1f' % float(size/1000000000)    + ' Gb'
    elif 1000000000000 <= size:
        return '%.1f' % float(size/1000000000000) + ' Tb'

# GetVMs()
def GetVMs(vname, vid, vip):
    # Search VM Name
    if vname:
        vm_found = None
        print(f"{Fore.LIGHTBLUE_EX}Get nodes ...{Fore.RESET}")
        for node in sorted(proxmox.nodes.get(), key=lambda n: n['node']):
            if node['status'] == "online":
                print(f"{Fore.LIGHTGREEN_EX}Node '{node['node']}' status: {node['status']}{Fore.RESET}")
                vmlist = proxmox.nodes(node["node"]).qemu.get()
                for vm_search in vmlist:
                    if vm_search['name'] == vname:
                        vid = vm_search['vmid']
                        vdata = proxmox.nodes(node["node"]).qemu(vid)
                        GetVMInfo(vm_data=vdata)
                        vm_found = True
                        break
            elif node['status'] == "offline":
                print(f"{Fore.LIGHTCYAN_EX}Node '{node['node']}' status: {node['status']}{Fore.RESET}")
            else:
                print(f"{Fore.LIGHTMAGENTA_EX}Node '{node['node']}' status: {node['status']}{Fore.RESET}")
        if not vm_found:
            print(f"{Fore.RED}VM '{vname}' not found {Fore.RESET}")
            sys.exit(1)

    # Search VM ID
    elif vid:
        vm_found = None
        print(f"{Fore.LIGHTBLUE_EX}Get nodes ...{Fore.RESET}")
        for node in sorted(proxmox.nodes.get(), key=lambda n: n['node']):
            if node['status'] == "online":
                print(f"{Fore.LIGHTGREEN_EX}Node '{node['node']}' status: {node['status']}{Fore.RESET}")
                if any(vm_chk['vmid'] == int(vid) for vm_chk in proxmox.nodes(node["node"]).qemu().get()):
                    vdata = proxmox.nodes(node["node"]).qemu(vid)
                    GetVMInfo(vm_data=vdata)
                    vm_found = True
                    break
            elif node['status'] == "offline":
                print(f"{Fore.LIGHTCYAN_EX}Node '{node['node']}' status: {node['status']}{Fore.RESET}")
            else:
                print(f"{Fore.LIGHTMAGENTA_EX}Node '{node['node']}' status: {node['status']}{Fore.RESET}")
        if not vm_found:
            print(f"{Fore.RED}VM '{vid}' not found {Fore.RESET}")
            sys.exit(1)

    # Search VM IP
    elif vip:
        vm_found = None
        print(f"{Fore.LIGHTBLUE_EX}Get nodes ...{Fore.RESET}")
        for node in sorted(proxmox.nodes.get(), key=lambda n: n['node']):
            if node['status'] == "online":
                print(f"{Fore.LIGHTGREEN_EX}Node '{node['node']}' status: {node['status']}{Fore.RESET}")
                vmlist = proxmox.nodes(node["node"]).qemu().get()
                for v in vmlist:
                    vdata = proxmox.nodes(node["node"]).qemu(v['vmid'])
                    vm_status = vdata.status('current').get()
                    if vm_status['status'] == 'running':
                        vm_agent_network = vdata.agent('network-get-interfaces').get()
                        for netw in vm_agent_network['result']:
                            for ipadr in netw['ip-addresses']:
                                if ipadr['ip-address'] == vip:
                                    vm_found = True
                                    GetVMInfo(vm_data=vdata)
                                    break
            elif node['status'] == "offline":
                print(f"{Fore.LIGHTCYAN_EX}Node '{node['node']}' status: {node['status']}{Fore.RESET}")
            else:
                print(f"{Fore.LIGHTMAGENTA_EX}Node '{node['node']}' status: {node['status']}{Fore.RESET}")
        if not vm_found:
            print(f"{Fore.RED}VM not found {Fore.RESET}")
            sys.exit(1)

# Function GetVMInfo()
def GetVMInfo(vm_data):
    vm_status = vm_data.status('current').get()
    vm_conf   = vm_data.config().get()
    vm_snap   = vm_data.snapshot().get()
    vm_agent_running = None
    if vm_status['status'] == 'running':
        try:
            vm_agent_osinfo  = vm_data.agent('get-osinfo').get()
        except Exception as eggog:
            print(f"{Fore.YELLOW}* {eggog}{Fore.RESET}")
            vm_agent_running = False
        else:
            vm_agent_running = True
            vm_agent_network = vm_data.agent('network-get-interfaces').get()
            vm_agent_fsinfo  = vm_data.agent('get-fsinfo').get()

    print(f"{Fore.LIGHTYELLOW_EX}Name           : {Fore.RESET}{Fore.CYAN}{vm_conf['name']}{Fore.RESET}")

    print(f"{Fore.LIGHTYELLOW_EX}VMID           : {Fore.RESET}{Fore.CYAN}{vm_status['vmid']}{Fore.RESET}")

    print(f"{Fore.LIGHTYELLOW_EX}Uptime         : {Fore.RESET}{str(datetime.timedelta(seconds=vm_status['uptime']))}")

    if vm_status['status'] == 'running':
        print(f"{Fore.LIGHTYELLOW_EX}Status         : {Fore.RESET}{Fore.GREEN}{vm_status['status']}{Fore.RESET} [pid={vm_status['pid']}]")
    elif vm_status['status'] == 'stopped':
        print(f"{Fore.LIGHTYELLOW_EX}Status         : {Fore.RESET}{Fore.RED}{vm_status['status']}{Fore.RESET}")
    else:
        print(f"{Fore.LIGHTYELLOW_EX}Status         : {Fore.RESET}{Fore.YELLOW}{vm_status['status']}{Fore.RESET}")

    # 'case'
    vm_os_type = vm_conf['ostype']
    if vm_os_type == 'other':
        os_type = 'unspecified OS'
    elif vm_os_type == 'wxp': 
        os_type = 'Microsoft Windows XP'
    elif vm_os_type == 'w2k':
        os_type = 'Microsoft Windows 2000'
    elif vm_os_type == 'w2k3':
        os_type = 'Microsoft Windows 2003'
    elif vm_os_type == 'w2k8':
        os_type = 'Microsoft Windows 2008'
    elif vm_os_type == 'wvista':
        os_type = 'Microsoft Windows Vista'
    elif vm_os_type == 'win7':
        os_type = 'Microsoft Windows 7'
    elif vm_os_type == 'win8':
        os_type = 'Microsoft Windows 8/2012/2012 R2'
    elif vm_os_type == 'win10':
        os_type = 'Microsoft Windows 10/2016/2019'
    elif vm_os_type == 'win11':
        os_type = 'Microsoft Windows 11/2022/2025'
    elif vm_os_type == 'l24':
        os_type = 'Linux 2.4 Kernel'
    elif vm_os_type == 'l26':
        os_type = 'Linux 2.6 - 6.X Kernel'
    elif vm_os_type == 'solaris':
        os_type = 'Solaris/OpenSolaris/OpenIndiania kernel'
    else:
        os_type = 'Unknown'
    print(f"{Fore.LIGHTYELLOW_EX}OS type        : {Fore.RESET}{os_type}")

    if vm_status['status'] == 'running' and vm_agent_running:
        print(f"{Fore.LIGHTYELLOW_EX}OS name/kernel : {Fore.RESET}{vm_agent_osinfo['result']['pretty-name']} [{vm_agent_osinfo['result']['kernel-release']}]")
    if 'agent' in vm_conf:
        if vm_conf['agent'] == "1":
            print(f"{Fore.LIGHTYELLOW_EX}Agent          : {Fore.GREEN}Enable{Fore.RESET}")
        elif vm_conf['agent'] == "0":
            print(f"{Fore.LIGHTYELLOW_EX}Agent          : {Fore.BLUE}Disable{Fore.RESET}")

    if 'template' in vm_conf:
        print(f"{Fore.LIGHTYELLOW_EX}Template       : {Fore.CYAN}Yes{Fore.RESET}")

    bios_uuid = (vm_conf['smbios1']).split("=")
    print(f"{Fore.LIGHTYELLOW_EX}Bios UUID      : {Fore.RESET}{bios_uuid[1]}")

    
    if 'cpu' in vm_conf:
        print(f"{Fore.LIGHTYELLOW_EX}vCPU           : {Fore.RESET}{vm_conf['sockets']} [{vm_conf['cores']}] [{vm_conf['cpu']}]")
    else:
        print(f"{Fore.LIGHTYELLOW_EX}vCPU           : {Fore.RESET}{vm_conf['sockets']} [{vm_conf['cores']}]")

    memGB = (int(vm_conf['memory']) / 1024)
    print(f"{Fore.LIGHTYELLOW_EX}vRAM (Gb)      : {Fore.RESET}{memGB}")

    for scsi_key in vm_conf:
        if re.match("^scsi\d",scsi_key):
            scsi = (vm_conf[scsi_key]).split(",")
            for s in scsi:
                if 'size' in s:
                    scsi_size = s
            print(f"{Fore.LIGHTYELLOW_EX}{scsi_key}          : {Fore.RESET}{scsi[0]} [{Fore.LIGHTMAGENTA_EX}{scsi_size}{Fore.RESET}]")

    if vm_status['status'] == 'running' and vm_agent_running:
        for fsinfo in vm_agent_fsinfo['result']:
            if fsinfo['disk']:
                disk_info = fsinfo['disk']
                if 'total-bytes' in fsinfo:
                    total_bytes = b_convert(fsinfo['total-bytes'])
                else:
                    total_bytes = 'None'
                if 'used-bytes' in fsinfo:
                    used_bytes = b_convert(fsinfo['used-bytes'])
                else:
                    used_bytes = 'None'
                print(f"{Fore.LIGHTYELLOW_EX}Disk {fsinfo['name']}      :{Fore.RESET} {Fore.LIGHTMAGENTA_EX}{disk_info[0]['dev']}{Fore.RESET}, Type:{fsinfo['type']}, Mount:{Fore.LIGHTMAGENTA_EX}{fsinfo['mountpoint']}{Fore.RESET}, Size: {total_bytes}, Used: {used_bytes}")

    for net_key in vm_conf:
        if re.match("^net\d",net_key):
            net  = (vm_conf[net_key]).split(",")
            vnet = (net[0]).split("=")
            br   = (net[1]).split("=")
            print(f"{Fore.LIGHTYELLOW_EX}{net_key}           : {Fore.RESET}{vnet[0]} [{Fore.LIGHTMAGENTA_EX}{vnet[1]}{Fore.RESET}], {br[0]} [{Fore.LIGHTMAGENTA_EX}{br[1]}{Fore.RESET}]")

    if vm_status['status'] == 'running' and vm_agent_running:
        for eth in vm_agent_network['result']:
            if eth['name'] != 'lo' and eth['name'] != 'Loopback Pseudo-Interface 1':
                print(f"{Fore.LIGHTYELLOW_EX}Net device     :{Fore.RESET} {eth['name']} [{Fore.LIGHTMAGENTA_EX}{eth['hardware-address']}{Fore.RESET}]")
                for adr in eth['ip-addresses']:
                    if adr['ip-address-type'] == 'ipv4':
                        print(f"{Fore.LIGHTYELLOW_EX}ipv4 address   :{Fore.RESET} {Fore.LIGHTMAGENTA_EX}{adr['ip-address']}/{adr['prefix']}{Fore.RESET}")

    print(f"{Fore.LIGHTYELLOW_EX}Snapshot       : {Fore.RESET}", end='')
    for snap in vm_snap:
        if snap['name'] == 'current':
            print(f"{snap['name']} [{snap['description']}]", end='')
        else:
            print(f"{snap['name']} [{snap['description']}] > ", end='')
    print()

    if 'description' in vm_conf:
        print(f"{Fore.LIGHTYELLOW_EX}Notes          : \n{Fore.LIGHTWHITE_EX}{vm_conf['description']}{Fore.RESET}")

# main()
def main():
    # Route for options
    if vm_name == None and vm_id == None and vm_ip == None:
        print(f"{Fore.LIGHTBLUE_EX}Get Nodes ...{Fore.RESET}")
        for node in sorted(proxmox.nodes.get(), key=lambda n: n['node']):
            if node['status'] == "online":
                print(f"{Fore.LIGHTGREEN_EX}Node '{node['node']}' status: {node['status']}{Fore.RESET}")
                vmlist = proxmox.nodes(node["node"]).qemu.get()
                for vm in sorted(vmlist, key=lambda d: d['vmid']):
                    if template == 'True':
                        vcpu = vm['cpus']
                        vram = ((vm['maxmem']) / 1024 / 1024 / 1024 )
                        if vm['status'] == 'stopped':
                            print(f"  {Fore.CYAN}{vm['vmid']}{Fore.RESET} {vm['name']} : {Fore.MAGENTA}{vm['status']}{Fore.RESET} (vCPU: {vcpu} vRAM:", f"{vram:.0f})")
                        elif vm['status'] == 'running':
                            print(f"  {Fore.CYAN}{vm['vmid']}{Fore.RESET} {vm['name']} : {Fore.GREEN}{vm['status']}{Fore.RESET} [pid={vm['pid']}] (vCPU: {vcpu} vRAM:", f"{vram:.0f})")
                        else:
                            print(f"  {Fore.CYAN}{vm['vmid']}{Fore.RESET} {vm['name']} : {Fore.YELLOW}{vm['status']}{Fore.RESET} (vCPU: {vcpu} vRAM:", f"{vram:.0f})")
                    elif template == 'False':
                        if 'template' not in vm:
                            vcpu = vm['cpus']
                            vram = ((vm['maxmem']) / 1024 / 1024 / 1024 )
                            if vm['status'] == 'stopped':
                                print(f"  {Fore.CYAN}{vm['vmid']}{Fore.RESET} {vm['name']} : {Fore.MAGENTA}{vm['status']}{Fore.RESET} (vCPU: {vcpu} vRAM:", f"{vram:.0f})")
                            elif vm['status'] == 'running':
                                print(f"  {Fore.CYAN}{vm['vmid']}{Fore.RESET} {vm['name']} : {Fore.GREEN}{vm['status']}{Fore.RESET} [pid={vm['pid']}] (vCPU: {vcpu} vRAM:", f"{vram:.0f})")
                            else:
                                print(f"  {Fore.CYAN}{vm['vmid']}{Fore.RESET} {vm['name']} : {Fore.YELLOW}{vm['status']}{Fore.RESET} (vCPU: {vcpu} vRAM:", f"{vram:.0f})")
                    else:
                        print(f"{Fore.RED}Unknown option '--template' {template} {Fore.RESET}")
                        sys.exit(1)
            elif node['status'] == "offline":
                print(f"{Fore.LIGHTCYAN_EX}Node '{node['node']}' status: {node['status']}{Fore.RESET}")
            else:
                print(f"{Fore.LIGHTMAGENTA_EX}Node '{node['node']}' status: {node['status']}{Fore.RESET}")


    elif (vm_name != None and vm_id != None) or (vm_name != None and vm_ip != None) or (vm_id != None and vm_ip != None):
        print(f"{Fore.RED}Do not mix [-a], [-i] and [-n] options {Fore.RESET}")
        sys.exit(1)

    elif vm_name:
        if re.match(r'^[-a-zA-Z0-9._]+$', vm_name):
            print(f"{Fore.YELLOW}Search VM with name '{vm_name}' ...{Fore.RESET}")
            GetVMs(vname=vm_name, vid=None, vip=None)
        else:
            print(f"{Fore.RED}Name must contain chars: a-zA-Z0-9.-_ {Fore.RESET}")
            sys.exit(1)

    elif vm_id:
        if re.match(r'^[0-9]+$', vm_id):
            print(f"{Fore.YELLOW}Get VM with ID '{vm_id}' ...{Fore.RESET}")
            GetVMs(vname=None, vid=vm_id, vip=None)
        else:
            print(f"{Fore.RED}VM ID must be number (Example: 100){Fore.RESET}")
            sys.exit(1)

    elif vm_ip:
        if re.match(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', vm_ip):
            print(f"{Fore.YELLOW}Search VM with IP '{vm_ip}' ...{Fore.RESET}")
            GetVMs(vname=None, vid=None, vip=vm_ip)
        else:
            print(f"{Fore.RED}String '{vm_ip}' is not IP address {Fore.RESET}")
            sys.exit(1)

if __name__ == "__main__":
    main()
