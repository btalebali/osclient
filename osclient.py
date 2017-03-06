##########################################################
##########################################################
### OpenStack client for wrapping Openstack platform #####
##########################################################
##########################################################

#### sudo pip install openstacksdk==0.9.11
#### tested using Python 2.7

import os
import sys
import re
import time
import random
import socket
import json
import uuid
import pypacksrc
from pyclient import *
from pyclient import (_init_logger, get_log)
import subprocess
import requests


####### import openstack librairies
from openstack import *
from novaclient.client import Client ## Used for somme functions because openstacksdk do not support yet

##### VARIABLES
BILLING_INVOICES = "BILLING_INVOICES"
CONSUMPTION = "CONSUMPTION"





def str_remove_specialchars( s ):
    response = None
    resp=[]
    respdict={}
    if hasattr(s, 'status') and hasattr(s, 'message'):
        respdict["provider.status"] = str(s.status)
        respdict["provider.message"] = "failure " + str(s.message)
        resp.append(respdict)
        response = json.dumps(resp)
    elif hasattr(s, 'http_status') and hasattr(s, 'message'):
        respdict["provider.status"] = str(s.http_status)
        respdict["provider.message"] = "failure " + str(s.message)
        resp.append(respdict)
        response = json.dumps(resp)
    else:
        response = "failure " + str(s)
    response = response.replace(pypacksrc.dcvt_delimiter," ")
    return response


def str_remove_specialcharsb( s ):
    response = None
    resp=[]
    respdict={}
    if hasattr(s, 'status') and hasattr(s, 'message'):
        respdict["provider.status"] = str(s.status)
        respdict["provider.message"] = str(s.message)
        resp.append(respdict)
        response = json.dumps(resp)
    elif hasattr(s, 'http_status') and hasattr(s, 'message'):
        respdict["provider.status"] = str(s.http_status)
        respdict["provider.message"] = str(s.message)
        resp.append(respdict)
        response = json.dumps(resp)
        response = str(s)
    response = response.replace(pypacksrc.dcvt_delimiter," ")
    return response



def get_credentials(tenant, user, password, host):
    """
    :param tenant:
    :param user:
    :param password:
    :param host:
    :return:
    """
    auth_args = {
        'auth_url': host,
        'project_name': tenant,
        'username': user,
        'password': password,
    }
    return auth_args


def listFalvors( tenant, user, password, host, version, region):
    """
    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param region:
    :return a list of openstack.compute.v2.flavor.FlavorDetail  class
    """
    flv=[];
    auth_args = get_credentials(tenant, user, password, host)
    con = connection.Connection(**auth_args)
    for flavor in con.compute.flavors():
        flv.append(flavor)
    return flv


def normalizeb_value( vardata ):
    """
    :param vardata:
    :return:
    """
    try:
        mlist = [x for x in re.split(r'\s+|(\d+)',vardata) if x]
    except:
        return None
    if '.' in vardata :
        mvalue = mlist[0] + '.' + mlist[2]
        fvalue = float(mvalue)
        if len(mlist) > 2:
            if 't' in mlist[3].lower():
                rvalue = fvalue * 1024 * 1024
                nvalue = int(rvalue)
            elif 'g' in mlist[3].lower():
                rvalue = fvalue * 1024
                nvalue = int(rvalue)
            elif 'm' in mlist[3].lower():
                rvalue = fvalue
                nvalue = int(rvalue)
            else:
                rvalue = fvalue
                nvalue = int(rvalue)
        else:
            rvalue = fvalue
            nvalue = int(rvalue)
    else:
        fvalue = float(mlist[0])
        if len(mlist) > 1:
            if 't' in mlist[1].lower():
                rvalue = fvalue * 1024 * 1024
                nvalue = int(rvalue)
            elif 'g' in mlist[1].lower():
                rvalue = fvalue * 1024
                nvalue = int(rvalue)
            elif 'm' in mlist[1].lower():
                rvalue = fvalue
                nvalue = int(rvalue)
            else:
                rvalue = fvalue
                nvalue = int(rvalue)
        else:
            rvalue = fvalue
            nvalue = int(rvalue)
    return nvalue



def get_provider(host):
    if "cloudwatt" in host:
        return "cloudwatt"
    else:
        return "openstack"



def get_logger_pname(host):
    if "cloudwatt" in host:
        return "PRCW"
    else:
        return "PROS"




def os_get_flavor( tenant, user, password, host, version, regions, memory, cores, speed, storage, flavor ):
    """
    get flavor image from openstack platform
    param: strings: tenant, user, password, host, version: Credentials for openstack
    param: string: memory: memory size
    param: string: cores: cores number
    param: string: speed: speed value
    param: string: storage: storage size
    param: string: flavor: name of the flavor
    """
    pmodule = get_logger_pname(host)
    logger = _init_logger(pmodule, account_= "undefined",user_="undefined")
    logger.logger.info('get flavor from openstack provider -> ?', extra=logger.extra)
    get_log(logger)
    region = None
    if regions and not(regions.isspace()):
        try:
            mregions = json.loads(regions)
            region = mregions['zone'][0]
        except ValueError:
            region = None
    try:
        flavors = listFalvors( tenant, user, password, host, version, region )
    except Exception as error:
        response = str_remove_specialchars( error )
        return response
    if flavor == None:
        try:
            ram = normalizeb_value(memory)
        except Exception as error:
            response = str_remove_specialchars( error )
            return response
        if ram is None:
            return 'failure memory syntax error'
        ramlist={}
        for flv in flavors:
            ramlist[flv.name]=flv.ram
        ramlist = sorted(ramlist.items(), key=lambda t: t[1])
        for cpt in ramlist:
            if ram <= cpt[1]:
                logger.logger.info('get flavor from openstack provider OK',extra=logger.extra)
                get_log(logger)
                return cpt[0]
        else:
            logger.logger.error('get flavor from openstack provider %s','failure no size match', extra=logger.extra)
            get_log(logger)
            return 'failure no size match'
    else:
        for flv in flavors:
            if flavor == flv.name:
                logger.logger.info('get flavor from openstack provider -> OK',extra=logger.extra)
                get_log(logger)
                return flv.name
    logger.logger.error('get flavor from openstack provider %s','failure no flavor with the provided name', extra=logger.extra)
    get_log(logger)
    return 'failure no flavor with the provided name'



def os_check_image_name(tenant, user, password, host, version, region, imgname):
    """
    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param region:
    :param imgname: the name
    :return:
    """
    auth_args = get_credentials(tenant, user, password, host)
    con = connection.Connection(**auth_args)
    images = con.compute.images()
    for image in images:
        if imgname == image.name:
            return imgname
    return None




def list_os_images_from_nova(tenant, user, password, host, version):
    """
    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :return:
    """
    auth_args = get_credentials(tenant, user, password, host)
    con = connection.Connection(**auth_args)
    response = []
    images = con.compute.images()
    for image in images:
        response_={}
        response_['name'] = unicode2str(image.name)
        response_['id'] = unicode2str(image.id)
        response_['minDisk'] = unicode2str(image.min_disk)
        response_['minRam'] = unicode2str(image.min_ram)
        response_['metadata'] = str(image.metadata)
        response_['created'] = unicode2str(image.created_at)
        response_['size'] = str(image.size)
        response.append(response_)
    return response


def os_get_image( tenant, user, password, host, version, regions, imgname ):
    """
    Get image name from openstack platform

    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param regions:
    :param imgname:
    :return:
    """
    pmodule = get_logger_pname(host)
    logger = _init_logger(pmodule, account_= "undefined",user_="undefined")
    logger.logger.info('get image from openstack provider',extra=logger.extra)
    get_log(logger)
    imagename = None
    region = None
    if regions and not(regions.isspace()):
        try:
            mregions = json.loads(regions)
            region = mregions['zone'][0]
        except ValueError:
            region = None
    try:
        imagename = os_check_image_name( tenant, user, password, host, version, region, imgname )
    except Exception as error:
        imagename =  str_remove_specialchars( error )
        logger.logger.error('get image from openstack provider %s', imagename, extra=logger.extra)
        get_log(logger)
    if not(imagename):
        imagename = "failure: the given imagename not found"
        logger.logger.error('get image from openstack provider %s', imagename, extra=logger.extra)
        get_log(logger)
    return imagename



def os_get_image_coips( tenant, user, password, host, version, regions, imgname ):
    """
    Get image name from openstack platform
    param: tenant, user, password, host, version: Credentials for openstack
    param: imgname: the name of the image

    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param regions:
    :param imgname:
    :return:
    """
    pmodule = get_logger_pname(host)
    logger = _init_logger(pmodule, account_= "undefined",user_="undefined")
    logger.logger.info('get coips image from openstack provider',extra=logger.extra)
    imagename = None
    region = None
    if regions and not(regions.isspace()):
        try:
            mregions = json.loads(regions)
            region = mregions['zone'][0]
        except ValueError:
            region = None
    try:
        imagename = os_check_image_name( tenant, user, password, host, version, region, imgname )
    except Exception as error:
        imagename = "null " + str_remove_specialcharsb( error )
        logger.logger.warning('get coips image from openstack provider %s',imagename, extra=logger.extra)
        get_log(logger)
    if not(imagename):
        imagename = "null: the given imagename not found"
        logger.logger.warning('get coips image from openstack provider %s',imagename, extra=logger.extra)
        get_log(logger)
    return imagename


def os_get_zone(tenant, user, password, host, version, regions, zone):
    """
    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param regions:
    :param zone:
    :return:
    """
    region = zone
    if regions and not(regions.isspace()):
        try:
            mregions = json.loads(regions)
            for r in mregions['zone']:
                if r == zone:
                    region = r
                    break
        except ValueError:
            region = zone
    return region



def os_get_or_create_network(tenant, user, password, host, version, region, networkname, accountname="undefined", userowner="undefined"):
    """
    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param region:
    :param networkname:
    :param accountname:
    :param userowner:
    :return:
    """
    pmodule = get_logger_pname(host)
    logger = _init_logger(pmodule, account_=accountname,user_=userowner)
    auth_args = get_credentials(tenant, user, password, host)
    con = connection.Connection(**auth_args)
    netid = None
    logger.logger.info('get or create openstack network -> ?', extra=logger.extra)
    get_log(logger)
    try:
        Found=False
        for network in con.network.networks():
            if network.id == networkname:
                Found = True
                netid = network.id
                netname=network.name
                logger.logger.info('get openstack network -> %s', netid, extra=logger.extra)
                get_log(logger)
                response = netname + ":" + netid
        if not Found :
            network = con.network.create_network(name=networkname)
            netid=network.id
            logger.logger.info('create openstack network -> %s', netid, extra=logger.extra)
            get_log(logger)
            response = networkname + ":" + netid
    except Exception as error:
        response = str_remove_specialchars( error )
        logger.logger.error('get or create openstack network -> %s', response, extra=logger.extra)
        get_log(logger)
    return response


def os_get_or_create_subnet(tenant, user, password, host, version, region, subnetname, networkid, cidr, dnsNameServer=None, ipversion=4, accountname="undefined", userowner="undefined"):
    """
    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param region:
    :param subnetname:
    :param networkid:
    :param cidr:
    :param dnsNameServer:
    :param ipversion:
    :param accountname:
    :param userowner:
    :return:
    """
    pmodule = get_logger_pname(host)
    logger = _init_logger(pmodule, account_=accountname,user_=userowner)
    logger.logger.info('get or create openstack subnet -> ?', extra=logger.extra)
    get_log(logger)
    auth_args = get_credentials(tenant, user, password, host)
    con = connection.Connection(**auth_args)
    subnetid = "failure"
    if (not(ipversion) or str(ipversion).isspace()):
        ipversion = "4"
    try:
        subnets=[]
        for subnet in con.network.subnets():
            if subnet.network_id == networkid:
                subnets.append(subnet)
        for subnet in subnets:
            if subnet.id == subnetname:
                logger.logger.info('get or create openstack subnet -> %s', subnetname, extra=logger.extra)
                get_log(logger)
                response = subnet['name'] + ":" + subnet['id']
                return response
        try:
            ipversion = int(ipversion)
        except ValueError:
            return "failure ip_version invalide value"
        if(dnsNameServer) and not(dnsNameServer.isspace()):
            dnsNameServer = dnsNameServer.split('&')
            body_create_subnet = {'subnets': [{'name': subnetname, 'cidr': cidr, 'ip_version': ipversion, 'network_id': networkid, 'dns_nameservers':dnsNameServer}]}
            subnet = con.network.create_subnet(name=subnetname, network_id=networkid, ip_version=ipversion, cidr=cidr, dns_nameservers=dnsNameServer)
        else:
            body_create_subnet = {'subnets': [{'name': subnetname, 'cidr': cidr, 'ip_version': ipversion, 'network_id': networkid}]}
            subnet = con.network.create_subnet(name=subnetname, network_id=networkid, ip_version=ipversion, cidr=cidr)
        subnetid = subnet.id
        logger.logger.info('get or create openstack subnet -> %s', subnetid, extra=logger.extra)
        get_log(logger)
        response = subnetname + ":" + subnetid
    except Exception as error:
        response = str_remove_specialchars( error )
        logger.logger.error('get or create openstack subnet -> %s', response, extra=logger.extra)
        get_log(logger)
    return response




def os_create_subnet(tenant, user, password, host, version, region, subnetname, networkid, cidr, router_id="public", routername=None, dnsNameServer=None, ipversion=4, accountname="undefined", userowner="undefined"):
    """
    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param region:
    :param subnetname:
    :param networkid:
    :param cidr:
    :param router_id:
    :param routername:
    :param dnsNameServer:
    :param ipversion:
    :param accountname:
    :param userowner:
    :return:
    """

    pmodule = get_logger_pname(host)
    logger = _init_logger(pmodule, account_=accountname,user_=userowner)
    logger.logger.info('get or create openstack subnet -> ?', extra=logger.extra)
    get_log(logger)
    auth_args = get_credentials(tenant, user, password, host)
    con = connection.Connection(**auth_args)
    response = "failure to create subnet"
    if (not(ipversion) or str(ipversion).isspace()):
        ipversion = "4"
    try:
        try:
            ipversion = int(ipversion)
        except ValueError:
            return "failure ip_version invalide value"
        if(dnsNameServer) and not(dnsNameServer.isspace()):
            dnsNameServer = dnsNameServer.split(',')
            body_create_subnet = {'subnets': [{'name': subnetname, 'cidr': cidr, 'ip_version': ipversion, 'network_id': networkid, 'dns_nameservers':dnsNameServer}]}
            subnet = con.network.create_subnet(name=subnetname, network_id=networkid, ip_version=ipversion, cidr=cidr, dns_nameservers=dnsNameServer)
        else:
            body_create_subnet = {'subnets': [{'name': subnetname, 'cidr': cidr, 'ip_version': ipversion, 'network_id': networkid}]}
            subnet = con.network.create_subnet(name=subnetname, network_id=networkid, ip_version=ipversion, cidr=cidr)
        subnetid = subnet.id
        logger.logger.info('get or create openstack subnet -> %s', subnetid, extra=logger.extra)
        get_log(logger)
        routerid = ""
        portid = ""
        if router_id:
            resp = os_get_or_create_router_b(con, router_id, routername, subnetid, logger)
            if ':' in resp:
                l = resp.split(':')
                routerid = l[0]
                portid = l[1]
                response = {'zone': region, 'name': subnetname, 'id': subnetid, 'cidr_block': cidr, 'ipversion': ipversion,'routerid': routerid, 'portid': portid}
            else:
                response = resp
    except Exception as error:
        response = str_remove_specialchars( error )
        logger.logger.error('get or create openstack subnet -> %s', response, extra=logger.extra)
        get_log(logger)
    return response


def os_list_public_networks(tenant, user, password, host, version, region):
    """
    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param region:
    :return:
    """

    auth_args = get_credentials(tenant, user, password, host)
    con = connection.Connection(**auth_args)
    response = []
    for network in con.network.networks():
        for k, v in network.items():
            if (k == 'router:external') and (v == True):
                response.append(network)
    return response


def os_list_networks(tenant, user, password, host, version, region):
    """
    List public networks of openatck platform
    param: tenant, user, password, host, version: Credentials for openstack
    return list of object of Network Class
    """
    auth_args = get_credentials(tenant, user, password, host)
    con = connection.Connection(**auth_args)
    response=[]
    for network in con.network.networks():
        response.append(network)
    return response





def os_get_or_create_router(tenant, user, password, host, version, region, routername, subnetid, routername="public", accountname="undefined", userowner="undefined"):
    """
    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param region:
    :param routername:
    :param subnetid:
    :param routername:
    :param accountname:
    :param userowner:
    :return:
    """
    pmodule = get_logger_pname(host)
    logger = _init_logger(pmodule, account_= accountname,user_=userowner)
    logger.logger.info('get or create openstack router -> ?', extra=logger.extra)
    get_log(logger)
    auth_args = get_credentials(tenant, user, password, host)
    con = connection.Connection(**auth_args)
    response = "failure"
    router = None
    if (not(routername) or routername.isspace()):
        routername = "public"
    try:
        router = con.network.find_router(name_or_id=routername)
        if  router :
            routerid = router.id
        else:
            if routername.lower() == "public":
                public_net = os_get_public_networks(con)
                if public_net:
                    pub_net_id = public_net[0].id
                else:
                    logger.logger.info('get or create openstack rollic network available', extra=logger.extra)
                    get_log(logger)
                    return "failure there is no public network available"
                routername = routername
            try:
                router = con.network.create_router(name=routername, admin_state_up=True, external_gateway_info={'network_id': pub_net_id})
            except:
                router = con.network.create_router(name=routername, admin_state_up=True)
            if router:
                routerid = router.id
            else:
                return "failure to create openstack router"
        portid = os_add_router_interface_b(con, routerid, subnetid, logger)
        response = routerid + ":" + portid
    except Exception as error:
        response = str_remove_specialchars( error )
        logger.logger.error('get or create openstack router -> %s', response, extra=logger.extra)
        get_log(logger)
    return response





### not used
"""
def os_add_router_interface(tenant, user, password, host, version, region, routerid, subnetid, accountname="undefined", userowner="undefined"):
    pmodule = get_logger_pname(host)
    logger = _init_logger(pmodule, account_= accountname,user_=userowner)
    logger.logger.info('openstack add router interface -> ?', extra=logger.extra)
    get_log(logger)
    credentials = get_credentials(tenant, user, password, host, '0', region=region)
    neutron = ntclient.Client(**credentials)
    portid = "failure"
    try:
        req = {"subnet_id": subnetid}
        resp = neutron.add_interface_router(router=routerid, body=req)
        portid = resp['port_id']
        logger.logger.info('openstack add router interface -> %s', portid, extra=logger.extra)
        get_log(logger)
    except Exception as error:
        portid = str_remove_specialchars( error )
        logger.logger.error('openstack add router interface -> %s', portid, extra=logger.extra)
        get_log(logger)
    return portid
"""



def os_add_router_interface_b(con, routerid, subnetid, logger):
    """
    :param con:
    :param routerid:
    :param subnetid:
    :param logger:
    :return: port ID
    """
    logger.logger.info('openstack add router interface -> ?', extra=logger.extra)
    get_log(logger)
    portid = "failure"
    try:
        r = con.network.get_router(router=routerid)
        resp = con.network.add_interface_to_router(router=r,subnet_id=subnetid)
        portid = resp['port_id']
        logger.logger.info('openstack add router interface -> %s', portid, extra=logger.extra)
        get_log(logger)
    except Exception as error:
        portid = str_remove_specialchars( error )
        logger.logger.error('openstack add router interface -> %s', portid, extra=logger.extra)
        get_log(logger)
    return portid



def os_get_or_create_router_b(con, routerid, routername, subnetid, logger):
    """
    :param con:
    :param routerid:
    :param routername:
    :param subnetid:
    :param logger:
    :return: routerid:portid
    """
    logger.logger.info('get or create openstack router -> ?', extra=logger.extra)
    get_log(logger)
    response = "failure"
    try:
        router = con.network.find_router(name_or_id=routerid)
        if  router :
            routerid = router.id
        elif routerid.lower() == "public":
            public_net = os_get_public_networks(con)
            if public_net:
                pub_net_id = public_net[0].id
            else:
                logger.logger.info('get or create openstack router  -> there is no public network available', extra=logger.extra)
                get_log(logger)
                return "failure there is no public network available"
            if not(routername) or routername.isspace():
                routername = "rtnew"
            try:
                router = con.network.create_router(name=routername, admin_state_up=True, external_gateway_info={'network_id': pub_net_id})
            except:
                router = con.network.create_router(name=routername, admin_state_up=True)
            if router:
                routerid = router.id
            else:
                return "failure to create openstack router"
        else:
            logger.logger.info('get or create openstack router  -> there is no router with given ID', extra=logger.extra)
            get_log(logger)
            return "failure there is no router found with given ID"
        portid = os_add_router_interface_b(con, routerid, subnetid, logger)
        response = routerid + ":" + portid
    except Exception as error:
        response = str_remove_specialchars( error )
        logger.logger.error('get or create openstack router -> %s', response, extra=logger.extra)
        get_log(logger)
    return response





def os_extract_subnet(zone, subnetid, subnets):
    response = "subnet not found"
    try:
        if subnets.isspace() or not(subnets):
             response = "failure"
        else:
            msubnets = json.loads( subnets )
            for subnet in msubnets:
                if subnet['zone'] == zone and subnet['id'] == subnetid:
                    response = subnet['name'] + ":" + subnet['id'] + ":" + subnet['cidr_block'] + ":" + subnet['ipversion'] + ":" + subnet['routerid'] + ":" + subnet['portid']
                    break
    except Exception as error:
        response = str_remove_specialchars(error)
    return response



def os_format_subnets(zone, subnetname, subnetid, cidr_block, ipversion, router, subnets):
    """
    :param zone:
    :param subnetname:
    :param subnetid:
    :param cidr_block:
    :param ipversion:
    :param router:
    :param subnets:
    :return:
    """
    response = "failure"
    routerid =""
    portid = ""
    l = router.split(":")
    if len(l) > 0:
        routerid = l[0]
    if len(l) > 1:
        portid = l[1]
    try:
        if subnets.isspace() or not(subnets):
             response = "failure"
        else:
            msubnets = json.loads( subnets )
            msubnets.append({'zone': zone, 'name': subnetname, 'id': subnetid, 'cidr_block': cidr_block, 'ipversion': ipversion, 'routerid': routerid, 'portid': portid})
            response = json.dumps(msubnets)
    except Exception as error:
        response = str_remove_specialchars(error)
    return response





def os_format_subnet(zone, subnetname, subnetid, cidr_block, ipversion, router):
    """
    :param zone:
    :param subnetname:
    :param subnetid:
    :param cidr_block:
    :param ipversion:
    :param router:
    :return:
    """
    response = "failure"
    routerid =""
    portid = ""
    l = router.split(":")
    if len(l) > 0:
        routerid = l[0]
    if len(l) > 1:
        portid = l[1]
    try:
        msubnets = []
        msubnets.append({'zone':zone, 'name': subnetname, 'id': subnetid, 'cidr_block': cidr_block, 'ipversion': ipversion, 'routerid': routerid, 'portid': portid})
        response = json.dumps(msubnets)
    except Exception as error:
        response = str_remove_specialchars(error)
    return response




def os_remove_subnet(subnets, subnetid):
    """
    :param subnets:
    :param subnetid:
    :return:
    """
    response = "failure syntax error"
    try:
        if subnets.isspace() or not(subnets):
             response = "failure syntax error"
        else:
            msubnets = json.loads( subnets )
            i = 0
            for subnet in msubnets:
                if subnet['id'] in subnetid:
                    msubnets.pop(i)
                    break
                i = i+1
            response = json.dumps(msubnets)
    except Exception as error:
        response = str_remove_specialchars(error)
    return response




def os_add_subnet(subnets, subnet):
    """
    :param subnets:
    :param subnet:
    :return:
    """
    response = "failure syntax error"
    try:
        if subnets.isspace() or not(subnets):
             response = "failure syntax error"
        else:
            t = subnet.split('json:')
            m = t[1].split(']')
            msubnets = json.loads(subnets)
            msubnet = json.loads(m[0])
            msubnets.append(msubnet)
            response = json.dumps(msubnets)
    except Exception as error:
        response = str_remove_specialchars(error)
    return response




def get_or_create_keypair( tenant, user, password, host, version, region, keyname, keydir ):
    """
    Get or create a keypair from openstack platform
    param: tenant, user, password, host, version: Credentials for openstack
    param: keyname: enrate:keyname or use:keyname
    param: keydir: the path name for storing the private key

    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param region:
    :param keyname:
    :param keydir:
    :return:
    """
    auth_args = get_credentials(tenant, user, password, host)
    con = connection.Connection(**auth_args)
    n_keydir = os.path.expanduser(keydir)
    n_keydir = os.path.expandvars(n_keydir)
    if not os.path.exists(n_keydir):
        os.makedirs(n_keydir)
    try:
        if not (":" in keyname):
            return "failure syntax error for keypair attribute the valide syntax is (generate:keyname/use:keyname)"
        keyn = keyname.split(':')[1]
        if "use" in keyname:
            keypair_path = n_keydir + "/" + keyn + ".pem"
            if(os.path.isfile(keypair_path)):
                return keypair_path
            else:
                return keyn
        elif "generate" in keyname:
            keypair = con.compute.create_keypair(name=keyn)
            keypair_path = n_keydir + "/" + keyn + ".pem"
            with open(keypair_path, "w") as kfile:
                kfile.write(keypair.private_key)
            os.chmod(keypair_path, 0600)
            return keypair_path
    except Exception as error:
        response = str_remove_specialchars( error )
        return response



def get_or_create_secgroup(tenant, user, password, host, version, region, secname):
    """
    Get or create a security group from openstack platform
    param: tenant, user, password, host, version: Credentials for openstack
    param: sgname: the name of security group

    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param region:
    :param secname:
    :return:
    """

    auth_args = get_credentials(tenant, user, password, host)
    con = connection.Connection(**auth_args)
    response = "failure"
    try:
        sg = con.network.find_security_group(name_or_id=secname, ignore_missing=True)
        if sg:
            response = sg.id
        else:
            sg = con.network.create_security_group(name=secname, description='New security group from UiCB')
            response = sg.id
    except Exception as error:
        response = str_remove_specialchars( error )
    return response




def add_security_group_rule(tenant, user, password, host, version, region, sgid, rname, ip_protocol, from_port, to_port, cidr, fwp):
    """
    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param region:
    :param sgid:
    :param rname:
    :param ip_protocol:
    :param from_port:
    :param to_port:
    :param cidr:
    :param fwp:
    :return:
    """
    response = fwp
    if fwp.isspace() or not(fwp):
         response = "succeeded"
    else:
        rlist = []
        endpoints = json.loads( fwp )
        rlist = endpoints
        rlist.append( {'name': rname, 'protocol': ip_protocol, 'fport': from_port, 'tport': to_port, 'direction': 'in', 'range': cidr} )
        response = json.dumps(rlist)
    if cidr.isspace() or not(cidr):
        cidr=None
    auth_args = get_credentials(tenant, user, password, host)
    con = connection.Connection(**auth_args)
    try:
        rule = {
            'direction': 'ingress',
            'remote_ip_prefix': cidr,
            'protocol': ip_protocol,
            'port_range_min': from_port,
            'port_range_max': to_port,
            'security_group_id': sgid,
            'ethertype': 'IPv4'
        }
        result = con.network.create_security_group_rule(**rule)
    except Exception as error:
        if "rule already exists" in str(error):
            response = "warning rule already exists"
        else:
            response = str_remove_specialchars( error )
    return response




def remove_security_group_rule(tenant, user, password, host, version, region, sgid, ip_protocol, from_port, to_port, cidr, fwp):
    """
    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param region:
    :param sgid:
    :param ip_protocol:
    :param from_port:
    :param to_port:
    :param cidr:
    :param fwp:
    :return:
    """
    auth_args = get_credentials(tenant, user, password, host)
    con = connection.Connection(**auth_args)
    response = fwp
    if fwp.isspace() or not(fwp):
         response = "succeeded"
    else:
        rlist = []
        endpoints = json.loads( fwp )
        rlist = endpoints
        for rl in endpoints:
            if ( str(rl['protocol']) == ip_protocol and str(rl['fport']) == from_port and str(rl['tport']) == to_port and str(rl['range']) == cidr ):
                rlist.remove(rl)
        response = json.dumps(rlist)
    try:
        for secgroup in con.network.security_group_rules():
            if ( str(secgroup.protocol) == ip_protocol and secgroup.port_range_min == int(from_port) and secgroup.port_range_max == int(to_port) and str(secgroup.remote_ip_prefix) == cidr ) :
                res = con.network.delete_security_group_rule(security_group_rule = secgroup, ignore_missing = True)
    except Exception as error:
        response = str_remove_specialchars( error )
    return response


def os_get_public_networks(con):
    """
    get public networks of openatck platform
    return list of object of Network Class
    """
    response = []
    for network in con.network.networks():
        for k, v in network.items():
            if (k == 'router:external') and (v == True):
                response.append(network)
    return response


def get_security_group_rule(sg):
    """
    list rules from a security group in openstack platform
    :param sg:
    :return:
    """

    response = "succeeded"
    if not(sg):
        return "[]"
    secgroup = sg[0]
    rlist = []
    try:
        if not(secgroup.rules):
            return "[]"
        for rl in secgroup.rules:
            rlist.append( {'name': str(rl['ip_protocol']), 'protocol': str(rl['ip_protocol']), 'fport': str(rl['from_port']), 'tport': str(rl['to_port']), 'direction': 'in', 'range': str(rl['ip_range']['cidr'])} )
        response = json.dumps(rlist)
    except Exception as error:
        response = str_remove_specialchars( error )
    return response



def delete_security_group(tenant, user, password, host, version, region, secgid):
    """
    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param region:
    :param secgid:
    :return:
    """
    auth_args = get_credentials(tenant, user, password, host)
    con = connection.Connection(**auth_args)
    response = "succeeded"
    try:
        secgp = con.network.find_security_group(name_or_id=secgid,  ignore_missing=True)
        if secgp:
            result= con.network.delete_security_group(security_group=secgp, ignore_missing=True)
        else: response = "failure: security group not exists"
    except Exception as error:
        response = str_remove_specialchars( error )
    return response


def delete_floatingip(tenant, user, password, host, version, region, floatingipid):
    """
    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param region:
    :param floatingipid:
    :return:
    """
    auth_args = get_credentials(tenant, user, password, host)
    con = connection.Connection(**auth_args)
    response = "succeeded"
    try:
        ip = con.network.find_ip(name_or_id=floatingipid,  ignore_missing=True)
        if ip:
            result= con.network.delete_ip(floating_ip=ip, ignore_missing=True)
        else: response = "failure: floating ip not exists"
    except Exception as error:
        response = str_remove_specialchars( error )
    return response



def delete_keypair( tenant, user, password, host, version, region, keyname, keydir ):
    """
    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param region:
    :param keyname:
    :param keydir:
    :return:
    """
    auth_args = get_credentials(tenant, user, password, host)
    con = connection.Connection(**auth_args)
    response = "succeeded"
    try:
        if not(check_keypair_used(con, keyname)):
            kp = con.compute.find_keypair(name_or_id=keyname, ignore_missing=True)
            if kp:
                result = con.compute.delete_keypair(keypair=kp, ignore_missing=True)
            else:
                response = "failure: keypair not exists"
            if(os.path.isfile(keydir)):
                os.remove(keydir)
    except Exception as error:
        response = str_remove_specialchars( error )
    return response



def get_securitygroup_name(con, secgid):
    """
    :param con:
    :param secgid:
    :return:
    """
    sg = con.network.find_security_group(name_or_id=secgid, ignore_missing=True)
    return str(sg.name)



def get_or_create_floating_ip(tenant, user, password, host, version, region, pool=None):
    """
    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param region:
    :param pool:
    :return: instances of class openstack.network.v2.floating_ip.FloatingIP
    """
    auth_args = get_credentials(tenant, user, password, host)
    con = connection.Connection(**auth_args)
    # Filtering out associated floating IPs
    ip_list = [ip for ip in con.network.ips() if ip.fixed_ip_address is None]
    # Filtering floating IPs accord to a specific pool
    if pool :
        #ip_list = [ip for ip in ip_list if ip.pool == pool]
        #TODO
        return None
    if len(ip_list) > 0:
        return random.choice(ip_list)
    else:
        if pool :
            #TODO
            return None
            #return nova_client.floating_ips.create(pool)
        else:
            publicnetid = os_get_public_networks(con)[0].id
            floatingip = con.network.create_ip(floating_network_id=publicnetid)
            return floatingip


def create_floating_ip( tenant, user, password, host, version, region, pool=None):
    """
    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param region:
    :param pool:
    :return:
    """
    auth_args = get_credentials(tenant, user, password, host)
    con = connection.Connection(**auth_args)
    if pool is not None:
        # TODO
        return None
        #return nova_client.floating_ips.create(pool)
    else:
        publicnetid = os_get_public_networks(con)[0].id
        floatingip = con.network.create_ip(floating_network_id=publicnetid)
        return floatingip



def os_disassociate_floating_ip(tenant, user, password, host, version, region, instanceid, flipid):
    """
    Disassociate and delete floating ip
    param: tenant, user, password, host, version: Credentials for openstack
    param instanceid: the id of the instance
    param flipid: the floating ip id

    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param region:
    :param instanceid:
    :param flipid:
    :return:
    """

    auth_args = get_credentials(tenant, user, password, host)
    con = connection.Connection(**auth_args)
    response = "succeeded"
    try:
        myinstance = con.compute.find_server(name_or_id = instanceid, ignore_missing=True)
        myflip = con.network.find_ip(name_or_id = flipid, ignore_missing=True)
        for port in con.network.ports():
            if port.device_id ==  instanceid:
                flip_port = port
                res = con.network.remove_ip_from_port(myflip)
                if not res:
                    response= "unable to disassociate floating ip"
        #delete floating ip
        con.network.delete_ip(myflip, ignore_missing=True)  # ressults = None whatever succeeded or not
    except Exception as error:
        response = str_remove_specialchars( error )
    return response


def os_associate_floating_ip(tenant, user, password, host, version, region, instanceid ):
    """
    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param region:
    :param instanceid:
    :return:
    """
    auth_args = get_credentials(tenant, user, password, host)
    con = connection.Connection(**auth_args)
    response = None
    try:
        myinstance = con.compute.find_server(name_or_id=instanceid, ignore_missing=True)
        floatip = get_or_create_floating_ip( tenant, user, password, host, version, region)
        for port in con.network.ports():
            if port.device_id ==  instanceid:
                flip_port = port
                res = con.network.add_ip_to_port(flip_port,floatip)
                if not res:
                    response= "unable to associate floating ip"
        response = floatip.floating_ip_address + ":" + floatip.id
    except Exception as error:
        response =  str_remove_specialchars( error )
    return response


def os_delete_network(tenant, user, password, host, version, region, netid, accountname="undefined", userowner="undefined"):
    """
    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param region:
    :param netid:
    :param accountname:
    :param userowner:
    :return:
    """
    response = "succeeded"
    auth_args = get_credentials(tenant, user, password, host)
    con = connection.Connection(**auth_args)
    pmodule = get_logger_pname(host)
    logger = _init_logger(pmodule, account_= accountname,user_=userowner)
    logger.logger.info('openstack delete network -> ?', extra=logger.extra)
    get_log(logger)
    try:
        network = con.network.find_network(name_or_id=netid, ignore_missing=True)
        if not network:
            return "openstack network not found"
        ports = [inst for inst in con.network.ports() if inst.network_id == netid]
        routerPort = [port for port in ports if port.device_owner == 'network:router_interface']
        #get subnet
        if len(routerPort) > 0:
            subnetRouter = routerPort[0].fixed_ips[0]['subnet_id']
            routerid = routerPort[0].device_id
            #delete attachment
            delete_router_iface(con,routerid,subnetRouter )
            logger.logger.info('openstack delete interface -> ok', extra=logger.extra)
            get_log(logger)
            #delete router
            delete_router(con,routerid)
            logger.logger.info('openstack delete router -> ok', extra=logger.extra)
            get_log(logger)
        #delete network
        res = con.network.delete_network(network=network, ignore_missing=True)
        logger.logger.info('openstack delete network -> ok', extra=logger.extra)
        get_log(logger)
    except Exception as error:
        resp = "warning " + str_remove_specialchars( error ) #todo check if any attached port
        logger.logger.warning('openstack delete network -> %s', resp, extra=logger.extra)
        get_log(logger)
        pass
    return response





def delete_router_iface(con, routerid, subnet_id):
    """
    :param neutron:
    :param router: instance of router class
    :param subnet_id:
    :return:
    """
    try:
        router = con.network.find_router(name_or_id=routerid, ignore_missing=True)
        con.network.remove_interface_from_router(router=router, subnet_id=subnet_id)
        body={}
        con.network.remove_gateway_from_router(router=router, **body)
    except:
        pass



def delete_router(con, routerid):
    """
    :param neutron:
    :param router:  instance of router class
    :return:
    """
    try:
        router = con.network.find_router(name_or_id=routerid, ignore_missing=True)
        con.network.delete_router(router=router, ignore_missing=True)
    except:
        pass






def os_delete_network_subnet(tenant, user, password, host, version, region, netid, subnetid, routerid=None):
    """
    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param region:
    :param netid:
    :param subnetid:
    :param routerid:
    :return:
    """
    response = "succeeded"
    auth_args = get_credentials(tenant, user, password, host)
    con = connection.Connection(**auth_args)
    if routerid:
        resp = os_delete_router_iface(tenant, user, password, host, version, region, routerid, subnetid)
    rsubnet = con.network.find_subnet(name_or_id=subnetid, ignore_missing=True)
    if rsubnet:
        result = con.network.delete_subnet(subnet=rsubnet, ignore_missing=True)
    else:
        response = "failure the provided subnet id not found"
    return response



def os_delete_router_iface(tenant, user, password, host, version, region, routerid, subnetid):
    """
    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param region:
    :param routerid:
    :param subnetid:
    :return:
    """
    auth_args = get_credentials(tenant, user, password, host)
    con = connection.Connection(**auth_args)
    router = con.network.find_router(name_or_id=routerid, ignore_missing=True)
    con.network.remove_interface_from_router(router=router, subnet_id=subnetid)
    response = "succeeded"
    return response


def os_delete_router(tenant, user, password, host, version, region, routerid):
    """
    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param region:
    :param routerid:
    :return:
    """
    auth_args = get_credentials(tenant, user, password, host)
    con = connection.Connection(**auth_args)
    router = con.network.find_router(name_or_id=routerid, ignore_missing=True)
    con.network.delete_router(router=router, ignore_missing=True)
    response = "succeeded"
    return response



def check_ssh_connection(oshost, logger, hostname):
    """
    :param oshost:
    :param logger:
    :param hostname:
    :return:
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    retry = True
    connection = False
    check = 0;
    while retry and check < 60:
        try:
            s.connect((hostname, 22))
            retry = False
            connection = True
            #command = 'echo test port 22 OK >> /tmp/ostest'
            logger.logger.info('openstack provider test ssh port(22) connection -> ?',extra=logger.extra)
            get_log(logger)
            #os.system(command)
        except socket.error as e:
            #command = 'echo test port 22 >> /tmp/ostest'
            #os.system(command)
            time.sleep(10)
        check += 1
    s.close()
    return connection





def ssh_connect(oshost, hostname, username, keyfile, hostpot, version, package, accountname, workdir):
    pmodule = get_logger_pname(oshost)
    logger = _init_logger(pmodule, account_= accountname,user_="undefined")
    keydir = os.path.expanduser(keyfile)
    cert_ca = workdir + '/' + pypacksrc.securitydir + '/' + 'ca.crt'
    cert_cosacs_crt = workdir + '/' + pypacksrc.securitydir + '/cosacs/' + accountname + '.crt'
    cert_cosacs_key = workdir + '/' + pypacksrc.securitydir + '/cosacs/' + accountname + '.key'
    commanddeposit = hostpot + '/' + version + '/' + package
    if(check_ssh_connection(oshost, logger, hostname)):
        logger.logger.info('openstack provider test ssh port(22) connection -> OK',extra=logger.extra)
        get_log(logger)
        command_sh = '''sh /usr/local/lib/accords/py/ssh_install.sh {1} {0} {2} {3} {4} {5} {6}'''.format(keydir,username,hostname,commanddeposit,cert_ca,cert_cosacs_crt,cert_cosacs_key)
        try:
            reponse_cmd = os.system(command_sh)
            #reponse_cmd = subprocess.Popen(command_sh, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        except OSError as e:
            logger.logger.error('UiCBAgent install -> failure %s',str(e.error), extra=logger.extra)
            get_log(logger)
            return "failure"
        logger.logger.info('UiCBAgent install -> OK', extra=logger.extra)
        get_log(logger)
        return "succeeded"
    else:
        logger.logger.error('openstack provider test ssh port(22) connection -> failure',extra=logger.extra)
        get_log(logger)
        return "failure"





def oswaitfor_running(instanceip, port, timeout):
    counter = 0
    while counter < 4:
        try:
            testconnect = socket.create_connection((instanceip, port), timeout)
            testconnect.close()
            break
        except socket.timeout:
            counter += 1
            pass
        except socket.error:
            time.sleep(timeout)
    time.sleep(timeout)





def get_instance_password(instance,instanceip, keyfile, port, timeout):
    oswaitfor_running(instanceip, port, timeout)
    password = None
    counter = 0
    while not password:
        if counter > 30:
            break
        password = instance.get_password(keyfile)
        if password:
            return password
        time.sleep(10)
        counter += 1
    return "no password timeout expired"



def vwait_until_state( con, volume, state, timeout ):
    """
    :param con:
    :param volume:
    :param state:
    :return  True or False:
    """
    counter = 0
    response = True
    volume = con.block_store.get_volume(volume)
    while str(volume.status) != state :
        volume = con.block_store.get_volume(volume)
        time.sleep(5)
        counter += 5
        if counter > timeout:
            response = False
            break
    return response



def os_create_volume(tenant, user, password, host, version, pregion, zone, name, size, snapshotId, vtype, imageid, accountname="Undefined", userowner="Undefined"):
    """
    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param pregion:
    :param zone:
    :param name:
    :param size:
    :param snapshotId:
    :param vtype:
    :param imageid:
    :param accountname:
    :param userowner:
    :return: volume id
    """
    pmodule = get_logger_pname(host)
    logger = _init_logger(pmodule, account_=accountname,user_=userowner)
    logger.logger.info('Create volume -> ?',extra=logger.extra)
    get_log(logger)
    description = "new volume from UiCB"
    snapshotid = None
    if snapshotId and not(snapshotId.isspace()) :
        snapshotid = snapshotId
    volume_type = None
    if vtype and not(vtype.isspace()):
        if vtype.lower() != "empty":
            volume_type = vtype
    avzone = None
    if zone and not(zone.isspace()):
        avzone = zone
    imgref = None
    if imageid and not(imageid.isspace()):
        imgref = imageid
    response = None
    try:
        auth_args = get_credentials(tenant, user, password, host)
        con = connection.Connection(**auth_args)
        param = {
            #"status": "creating",
            "name": name,
            #"attachments": [],
            "availability_zone": avzone,
            #"bootable": "false",
            #"created_at": "2015-03-09T12:14:57.233772",
            "description": description,
            "volume_type": volume_type,
            "snapshot_id": snapshotid,
            #"source_volid": None,
            "imageRef": imgref,
            #"metadata": {},
            #"id": FAKE_ID,
            "size": int(size)
        }
        volume = con.block_store.create_volume(**param)
        r = vwait_until_state(con, volume, 'available', 600 )
        response = str(volume.id)
        logger.logger.info('Create volume -> OK',extra=logger.extra)
        get_log(logger)
    except AttributeError:
        mregion = None
        if pregion and not(pregion.isspace()):
            mregion = pregion
        res = con.profile.set_region(service='volume', region=mregion )
        volume = con.block_store.create_volume(**param)
        r = vwait_until_state(con, volume, 'available', 600)
        response = str(volume.id)
        logger.logger.info('Create volume -> OK',extra=logger.extra)
        get_log(logger)
    except Exception as error:
        response = str_remove_specialchars( error )
        logger.logger.error('Create volume -> %s', response, extra=logger.extra)
        get_log(logger)
    return response



#### openstacksdk do not suport os_attach_volume

def os_attach_volume(tenant, user, password, host, version, region, vmid, volumeid, devicename, accountname="Undefined", userowner="undefined"):
    """
    Attach a new volume

    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param region:
    :param vmid:
    :param volumeid:
    :param devicename:
    :param accountname:
    :param userowner:
    :return:
    """

    pmodule = get_logger_pname(host)
    logger = _init_logger(pmodule, account_=accountname,user_=userowner)
    logger.logger.info('Attach volume -> ?',extra=logger.extra)
    get_log(logger)
    credentials = get_credentials(tenant, user, password, host, version, region)
    nova_client = Client(**credentials)
    from cinderclient.v1 import client
    mregion = None
    if region and not(region.isspace()):
        mregion = region
    cinder_client = client.Client(user,password,tenant,host,region_name=mregion)

    device = None
    if devicename and not(devicename.isspace()):
        device = devicename

    response = None
    try:
        volume = nova_client.volumes.create_server_volume( vmid, volumeid, device )
        vwait_until_state(cinder_client, volumeid, 'in-use')
        response = str(volume.device)
        logger.logger.info('Attach volume -> OK',extra=logger.extra)
        get_log(logger)
    except Exception as error:
        response = str_remove_specialchars( error )
        logger.logger.error('Attach volume -> %s', response, extra=logger.extra)
        get_log(logger)
    return response





def check_keypair_used(con, keyname):
    """
    :param con:
    :param keyname:
    :return:
    """
    for server in con.compute.servers():
        if str(server.key_name) == str(keyname):
            return True
    return False






def list_os_flavors(tenant, user, password, host, version, region):
    """
    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param region:
    :return:
    """
    flavors = listFalvors(tenant, user, password, host, version, region=region)
    response = []
    resp = "ok"
    for flavor in flavors:
        response_={}
        response_['id']=flavor.id
        response_['name']=flavor.name
        response_['vcpus'] = flavor.vcpus
        response_['ram'] = flavor.ram
        response_['disk']=flavor.disk
        response_['ephemeral']=flavor.ephemeral
        response_['swap']=flavor.swap
        response.append(response_)
    resp = response
    return resp




def os_get_flavor_name(tenant, user, password, host, version, region, flavorid):
    """
    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param region:
    :param flavorid:
    :return:
    """
    fname = "not found"
    flavors = list_os_flavors(tenant, user, password, host, version, region)
    flavor =  [x for x in flavors if x['id'] == flavorid]
    if len(flavorid) > 0:
        fname = flavor[0]['name']
    return str(fname)


def os_get_flavor_by_id(tenant, user, password, host, version, region, flavorid):
    """
    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param region:
    :param flavorid:
    :return:
    """
    fname = "not found"
    flavors = list_os_flavors(tenant, user, password, host, version, region)
    flavor =  [x for x in flavors if x['id'] == flavorid]
    if len(flavor) == 0:
        return []
    nflavor = dict([(str(k),str(v)) for k, v in flavor[0].items()])
    return [nflavor]


def os_get_flavor_by_name(tenant, user, password, host, version, region, flavorname):
    """
    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param region:
    :param flavorname:
    :return:
    """
    fname = "not found"
    flavors = list_os_flavors(tenant, user, password, host, version, region)
    flavor =  [x for x in flavors if x['name'] == flavorname]
    if len(flavor) == 0:
        return []
    nflavor = dict([(str(k),str(v)) for k, v in flavor[0].items()])
    return [nflavor]


def get_os_quotas(tenant, user, password, host, version, region):
    """
    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param region:
    :return:
    """
    auth_args = get_credentials(tenant, user, password, host)
    con = connection.Connection(**auth_args)
    response = []
    response_ = {}
    resp = "ok"
    mregion = None
    if region and not (region.isspace()):
        mregions = region
    res = con.profile.set_region(service='volume', region=mregion)
    q = con.compute.get_limits()
    quota = q.to_dict()['absolute'].to_dict()
    response = json.dumps(quota)
    return json.loads(response)





def get_os_volume_types(tenant, user, password, host, version, region):
    """
    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param region:
    :return:
    """
    auth_args = get_credentials(tenant, user, password, host)
    con = connection.Connection(**auth_args)
    response = []
    vtypes = types=con.block_store.types()
    for vtype in vtypes:
        response_ = {}
        response_['name'] = vtype.name
        response_['id'] = vtype.id
        response.append(response_)
    return response




def cw_get_billing_cred(tenant, username, password, host, servicename):
    """
    :param tenant:
    :param username:
    :param password:
    :param host:
    :param servicename:  in nova, neutron, cinderv2, swift_s3, glance, heat-cfn, cinder, heat, swift, keystone, horse
    :return:
    """
    data = '{"auth":{"tenantName": "%s", "passwordCredentials":{"username": "%s", "password": "'"%s"'"}}}' % (tenant, username, password)
    url = host + "/tokens"
    resp = requests.post(url,data)
    if resp.status_code in (200, 201, 202):
        resp_data = resp.json()
        token = resp_data['access']['token']['id']
        billing_url=None
        for service in resp_data['access']['serviceCatalog']:
            if service['name'] == servicename:
                billing_url = service['endpoints'][0]['publicURL']
                break
        return True, token, billing_url
    else:
        message = str(resp.text)
        return False, message, resp.status_code


def cw_get_customerid(burl, token, target):
    """
    :param burl:
    :param token:
    :param target: str in ['ACCOUNT_EDIT', 'ACCOUNT_SHOW', 'ACCOUNT_ROLES_EDIT', 'ACCOUNT_ROLES_LIST', 'BILLING_EDIT', 'BILLING_INVOICES', 'BILLING_INVOICES_REFERENCE_SHOW',
    'BILLING_INVOICES_REFERENCE_EDIT', 'BILLING_PAYMENT_EDIT', 'BILLING_PAYMENT_SHOW', 'BILLING_SHOW', 'CONSUMPTION', 'SUB_ACCOUNTS_LIST', 'TENANT_EDIT', 'TENANT_SHOW',
    'TENANTS_LIST', 'TICKET_CREATE', 'TICKET_LIST', 'VIEW_INSTANT_CONSUMPTION', 'VIEW_PRICED_INSTANT_CONSUMPTION']
    :return:
    """
    h = {}
    h['X-Auth-Token']=token
    turl = burl+"/bss/1/contact/roles"
    customerid = None
    resp = requests.get(turl,headers=h)
    if resp.status_code in (200, 201, 202):
        resp_data = resp.json()
        for account in resp_data['accounts']:
            if target in  account['caps']:
                customerid = account['accountInformation']['customer_id']
                break
        if customerid:
            return True, resp_data, customerid
        else:
            return False, resp_data, customerid
    else:
        message = str(resp.text)
        return False, message, resp.status_code


def cw_list_invoice(burl, token, customerid, extension='csv', fromdata=None, todate=None):
    """
    :param burl:
    :param token:
    :param customerid:
    :param extension:
    :param fromdata:
    :param todate:
    :return:
    """
    h = {}
    h['X-Auth-Token']=token
    turl = burl + "/bss/1/accounts/" + customerid + "/listInvoices" + "?extensions=" + extension
    resp = requests.get(turl,headers=h)
    if resp.status_code in (200, 201, 202):
        resp_data = resp.json()
        return True, resp_data, resp.status_code
    else:
        message = str(resp.text)
        return False, message, resp.status_code



def cw_get_current_usage(burl, token, customerid):
    h = {}
    h['X-Auth-Token']=token
    turl = burl + "/bss/1/accounts/" + customerid + "/currentUsage"
    resp = requests.get(turl,headers=h)
    if resp.status_code in (200, 201, 202):
        resp_data = resp.json()
        return True, resp_data, resp.status_code
    else:
        message = str(resp.text)
        return False, message, resp.status_code

def os_format_security_group(secgroup):
    if len(secgroup) == 0:
        return None, None
    msecgroup = secgroup[0]
    secgroupid = str(msecgroup.id)
    rules=[]
    for rule in msecgroup.rules:
        resp = {}
        resp['protocol'] = rule['ip_protocol']
        resp['fport'] = rule['from_port']
        resp['tport'] = rule['to_port']
        if rule['ip_range'].has_key('cidr'):
            resp['range'] = rule['ip_range']['cidr']
        else:
            resp['range'] = ''
        resp['direction'] = 'inout'
        rules.append(resp)
    return secgroupid, rules


def os_format_addresses( addresses ):
    networkname = str(addresses.keys()[0])
    publicaddr = ""
    privateaddr = ""
    for interface in addresses[networkname]:
        if interface['OS-EXT-IPS:type'] == 'fixed':
            privateaddr = str(interface['addr'])
        elif interface['OS-EXT-IPS:type'] == 'floating':
            publicaddr = str(interface['addr'])
    return networkname, publicaddr, privateaddr


def os_list_instances(tenant, user, password, host, version, region, uicbflag=None):
    """
    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param region:
    :param uicbflag:
    :return:
    """
    auth_args = get_credentials(tenant, user, password, host)
    con = connection.Connection(**auth_args)
    response = []
    servers = con.compute.servers()
    if uicbflag == "not_uicb":
        instances=[x for x in servers if not("uicb" in str(x.metadata))]
    elif uicbflag == "only_uicb":
        instances=[x for x in servers if ("uicb" in str(x.metadata))]
    else:
        instances = servers
    for inst in instances:
        resp={}
        resp['id'] = str(inst.id)
        resp['name'] = str(inst.name)
        resp['flavor'] = os_get_flavor_name(tenant,user,password,host,version,region,inst.flavor['id'])
        resp['image'] = str(inst.image['id'])
        #resp['secgroupid'],resp['firewallpolicy'] = os_format_security_group(inst.security_groups())   inst.security_groups not yet implemented
        resp['networkname'], resp['publicaddr'], resp['privateaddr'] = os_format_addresses( inst.addresses)
        resp['created'] = inst.created_at
        resp['keyname'] = inst.key_name
        resp['zone'] = ''
        resp['status'] = str(inst.status)
        resp['pstate'] = str(inst.vm_state)
        resp['avzone'] = str(inst.availability_zone)
        response.append(resp)
    return response


def os_list_snapshot_images(tenant, user, password, host, version, region):
    """
    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param region:
    :return:
    """
    auth_args = get_credentials(tenant, user, password, host)
    con = connection.Connection(**auth_args)
    response = []
    images = con.compute.images()
    response = []
    snapshots = [ x for x in images if( x.metadata.has_key('image_type') and str(x.metadata['image_type']).lower() == "snapshot")]
    for snap in snapshots:
        resp = {}
        resp['name'] = snap.name
        resp['id'] = snap.id
        resp['snapshot_type'] = 'image'
        resp['minDisk'] = str(snap.min_disk)
        resp['minRam'] = str(snap.min_ram)
        resp['created'] = snap.created_at
        resp['updated'] = snap.updated_at
        resp['metadata'] = snap.metadata
        resp['status'] = snap.status
        resp['zone'] =''
        response.append(resp)
    return response



def os_list_backup_images(tenant, user, password, host, version, region):
    """
    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param region:
    :return:
    """
    auth_args = get_credentials(tenant, user, password, host)
    con = connection.Connection(**auth_args)
    response = []
    images = con.compute.images()
    response = []
    snapshots = [ x for x in images if(x.metadata.has_key('image_type') and str(x.metadata['image_type']).lower() == "backup")]
    for snap in snapshots:
        resp = {}
        resp['name'] = snap.name
        resp['id'] = snap.id
        resp['snapshot_type'] = 'image'
        resp['minDisk'] = str(snap.minDisk)
        resp['minRam'] = str(snap.minRam)
        resp['created'] = snap.created
        resp['updated'] = snap.updated
        resp['metadata'] = snap.metadata
        resp['status'] = snap.status
        resp['zone'] =''
        response.append(resp)
    return response




def os_list_snapshot_volumes(tenant, user, password, host, version, region):
    """
    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param region:
    :return:
    """
    auth_args = get_credentials(tenant, user, password, host)
    con = connection.Connection(**auth_args)
    response = []
    snapshots = con.block_store.snapshots()
    response = []
    for snap in snapshots:
        resp = {}
        resp['size'] = snap.size
        resp['id'] = snap.id
        resp['volume_id'] = snap.volume_id
        resp['snapshot_type'] = 'volume'
        resp['created'] = snap.created_at
        resp['metadata'] = snap.metadata
        resp['status'] = snap.status
        resp['zone'] = ''
        resp['type'] = ''
        response.append(resp)
    return response



def os_perform_on_snapshot_image(tenant, user, password, host, version, region, snapid, method):
    """
    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param region:
    :param snapid:
    :param method:
    :return:
    """
    response = {'message': 'succeeded', 'status': '200'}
    auth_args = get_credentials(tenant, user, password, host)
    con = connection.Connection(**auth_args)
    image = con.image.find_image(name_or_id=snapid, ignore_missing=True)
    if method.lower() == "delete":
        res = con.image.delete_image(image=image, ignore_missing=True)
    else:
        response = {'message': 'failure method not found', 'status': '404'}
    return response




def os_perform_on_snapshot_volume(tenant, user, password, host, version, region, snapid, method):
    response = {'message': 'succeeded', 'status': '200'}
    auth_args = get_credentials(tenant, user, password, host)
    con = connection.Connection(**auth_args)
    snap = con.block_store.get_snapshot(snapshot = snapid)
    if method.lower() == "delete":
        snap.delete()
    else:
        response = {'message': 'failure method not found','status': '404'}
    return response


#### openstacksdk do not support these actions: get_xxx_consle(), backup

def os_perform_on_instance(tenant, user, password, host, version, region, instanceid, method, flavorid=None,
                           confirm=None, console=None, console_type=None, snapshot_name=None, metadata=None,
                           vm_name=None, image_id=None, preserve=None, backup_name=None, backup_type=None, rotation=None):
    """
    Use novaclient, openstacksdk do not support these features: backup, get_XXX_console.
    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param region:
    :param instanceid:
    :param method:
    :param flavorid:
    :param confirm:
    :param console:
    :param console_type:
    :param snapshot_name:
    :param metadata:
    :param vm_name:
    :param image_id:
    :param preserve:
    :param backup_name:
    :param backup_type:
    :param rotation:
    :return:
    """
    response = {'message': 'succeeded', 'status': '200'}
    credentials = get_credentials(tenant, user, password, host, version, region)
    nova_client = Client(**credentials)
    myinstance = nova_client.servers.get(instanceid)
    if method.lower() == "delete":
        myinstance.delete()
    elif method.lower() == "stop":
        myinstance.stop()
    elif method.lower() == "start":
        myinstance.start()
    elif method.lower() == "revert":
        myinstance.revert_resize()
    elif method.lower() == "suspend":
        myinstance.suspend()
    elif method.lower() == "shelve":
        myinstance.shelve()
    elif method.lower() == "unshelve":
        myinstance.unshelve()
    elif method.lower() == "pause":
        myinstance.pause()
    elif method.lower() == "unpause":
        myinstance.unpause()
    elif method.lower() == "rescue":
        myinstance.rescue()
    elif method.lower() == "unrescue":
        myinstance.unrescue()
    elif method.lower() == "restore":
        myinstance.restore()
    elif method.lower() == "update":
        if ( not(vname) or vname.isspace()):
            response = {'message': 'failure instance_name parameters is mandatory for update method','status': '504'}
        else:
            myinstance.update(name=vm_name)
    elif method.lower() == "shelve_offload":
        myinstance.shelve_offload()
    elif method.lower() == "restart":
        myinstance.reboot()
    elif method.lower() == "resize":
        if ( not(flavorid) or flavorid.isspace()):
            response = {'message': 'failure flavor_id and confirm parameters are mandatory for resize method','status': '504'}
        else:
            myinstance.resize(flavorid)
            if confirm:
                counter = 0
                timeout = 60
                while counter < timeout:
                    myinstance = nova_client.servers.get(instanceid)
                    if 'verify' in str(myinstance.status).lower():
                        myinstance.confirm_resize()
                        break
                    time.sleep(5.0)
                    counter += 1
    elif method.lower() == "console":
        if console not in ["vnc", "rdp", "spice"]:
            response = {'message': 'failure console parameter sould be in [vnc,rdp,spice] for console method','status': '400'}
            return response
        if ( not(console_type) or console_type.isspace()):
            response = {'message': 'failure type parameters is mandatory for console method','status': '504'}
            return response
        if console == "vnc":
            vncaccess = myinstance.get_vnc_console(console_type)
            response = json.dumps(vncaccess)
        elif console == "rdp":
            vncaccess =  myinstance.get_rdp_console(console_type)
            response = json.dumps(vncaccess)
        elif console == "spice":
            vncaccess =  myinstance.get_spice_console(console_type)
            response = vncaccess
    elif method.lower() == "snapshot":
        if ( not(snapshot_name) or snapshot_name.isspace()):
            response = {'message': 'failure snapshot_name and metadata parameters are mandatory for snapshot method','status': '400'}
            return response
        meta = {}
        meta["name"] = snapshot_name
        meta["snapshotfrom"] = "uicb"
        if metadata:
            meta.update(metadata)
        snap_id = nova_client.servers.create_image(instanceid, snapshot_name, metadata=meta)
        response = {"snapshotid":snap_id, "status": "200"}
    elif method.lower() == "rebuild":
        preserve_ephemeral = False
        if "true" in preserve.lower():
            preserve_ephemeral = True
        myinstance.rebuild(image_id, preserve_ephemeral=preserve_ephemeral)
        response = {"action":"rebuild", "status": "200"}
    elif method == "backup":
        if backup_type not in ['daily','weekly']:
            response = {'message': 'failure backup_type value not valid [daily, weekly]','status': '400'}
            return response
        myinstance.backup(backup_name, backup_type, rotation)
        response = {"action":"backup", "status": "200"}
    else:
        response = {'message': 'failure method not found','status': '404'}
    return response





def list_os_keys(tenant, user, password, host, version, region):
    """
    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param region:
    :return:
    """
    auth_args = get_credentials(tenant, user, password, host)
    con = connection.Connection(**auth_args)
    keys = con.compute.keypairs()
    response = []
    for key in keys:
      response.append(key.to_dict())
    return response

def list_os_sgroups(tenant, user, password, host, version, region):
    """
    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param region:
    :return:
    """
    auth_args = get_credentials(tenant, user, password, host)
    con = connection.Connection(**auth_args)
    sgs = con.network.security_groups()
    response = []
    for sg in sgs:
      response.append(sg.to_dict())
    return response




def list_os_images_from_glance(tenant, user, password, host, version, region, tenant_owner):
    """
    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param region:
    :param tenant_owner: type boolean: if True list images awning by the used tenant else list all images for all tenant if permission is granted
    :return:
    """
    auth_args = get_credentials(tenant, user, password, host)
    con = connection.Connection(**auth_args)
    images = con.image.images()
    response = []
    if tenant_owner:
        for image in images:
            project_id = con.session.get_project_id()
            if unicode2str(project_id) == unicode2str(image.to_dict()['owner_id']):
                response.append(image.to_dict())
    else:
        for image in images:
            response.append(image.to_dict())
    return response




def os_create_keypair( tenant, user, password, host, version, region, keyname, keydir ):
    """
    create a keypair from openstack platform
    param: tenant, user, password, host, version: Credentials for openstack
    param: keyname: name of the keypair
    param: keydir: the path name for to save the private key

    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param region:
    :param keyname:
    :param keydir:
    :return:
    """
    try:
        auth_args = get_credentials(tenant, user, password, host)
        con = connection.Connection(**auth_args)
        n_keydir = os.path.expanduser(keydir)
        n_keydir = os.path.expandvars(n_keydir)
        if not os.path.exists(n_keydir):
            os.makedirs(n_keydir)
        keypair = con.compute.create_keypair(name=keyname)
        keypair_path = n_keydir + "/" + keyname + ".pem"
        with open(keypair_path, "w") as kfile:
            kfile.write(keypair.private_key)
        os.chmod(keypair_path, 0600)
        response = {}
        response['name'] = keyname
        response['path'] = keypair_path
        response['private_key'] = keypair.private_key
    except Exception as error:
        response = str_remove_specialchars( error )
    return response





def os_perform_on_vnet(tenant, user, password, host, version, region, vnetid, method, routerid=None, routername=None, portid=None, subnetname=None, subnetid=None, dns=None, ipversion=4, cidr=None):
    """
    :param tenant:
    :param user:
    :param password:
    :param host:
    :param version:
    :param region:
    :param vnetid:
    :param method:
    :param routerid:
    :param routername:
    :param portid:
    :param subnetname:
    :param subnetid:
    :param dns:
    :param ipversion:
    :param cidr:
    :return:
    """
    response = "failure"
    if method == "delete":
        response = os_delete_network(tenant, user, password, host, version, region, vnetid)
    elif method == "delete_subnet":
        if ( not(subnetid) or subnetid.isspace()):
            response = {'message': 'failure subnet_id parameters is mandatory for this method','status': '504'}
        else:
            resp = os_delete_network_subnet(tenant, user, password, host, version, region, vnetid, subnetid, routerid=routerid)
            if resp ==  "succeeded" and subnetid:
                response = "delete_vnet_subnetid:" + subnetid
    elif method == "delete_router":
        if ( not(routerid) or routerid.isspace()):
            response = {'message': 'failure router_id parameters is mandatory for this method','status': '504'}
        else:
            response = os_delete_router(tenant, user, password, host, version, region, routerid)
    elif method == "delete_interface":
        if ( not(routerid) or routerid.isspace()):
            response = {'message': 'failure router_id parameters is mandatory for this method','status': '504'}
            return response
        if ( not(subnetid) or subnetid.isspace()):
            response = {'message': 'failure subnet_id parameters is mandatory for this method','status': '504'}
            return response
        response = os_delete_router_iface(tenant, user, password, host, version, region, routerid, subnetid)
    elif method == "add_subnet":
        if (not(routerid) or routerid.isspace()):
            routerid="public"
        if (not(subnetname) or subnetname.isspace()):
            response = {'message': 'failure subnet_name parameters is mandatory for this method','status': '504'}
            return response
        if (not(cidr) or cidr.isspace()):
            response = {'message': 'failure cidr_block parameters is mandatory for this method','status': '504'}
            return response
        resp = os_create_subnet(tenant, user, password, host, version, region, subnetname, vnetid, cidr, routerid, routername, dnsNameServer=dns, ipversion=ipversion)
        response = resp
    else:
        response = {'message': 'failure method not found','status': '404'}
    return response






class OsFunction:
    def __init__( self, tenant, user, password, host, version, accountname, action, args):
        self.tenant = tenant
        self.user = user
        self.password = password
        self.host = host
        self.version = version
        self.accountname = accountname
        self.action = action
        self.args = args

    def list_flavors(self):
        resp = []
        region = None
        try:
            if(is_json(self.args)):
                margs = json.loads(self.args)
                if margs.has_key("region"):
                    region = margs["region"]
            flavors = list_os_flavors(self.tenant, self.user, self.password, self.host, self.version, region)
            resp = json.dumps(flavors)
        except Exception as error:
            resp = str_remove_specialchars( error )
        return resp

    def get_quotas(self):
        resp = []
        region = None
        try:
            if(is_json(self.args)):
                margs = json.loads(self.args)
                if margs.has_key("region"):
                    region = margs["region"]
            quotas = get_os_quotas(self.tenant, self.user, self.password, self.host, self.version, region)
            resp = json.dumps(quotas)
        except Exception as error:
            resp = str_remove_specialchars( error )
        return resp


    def list_images(self):
        resp = []
        region = None
        try:
            if(is_json(self.args)):
                margs = json.loads(self.args)
                if margs.has_key("region"):
                    region = margs["region"]
            response = list_os_images_from_glance(self.tenant, self.user, self.password, self.host, self.version, region,False)
            resp = json.dumps(response)
        except Exception as error:
            resp = str_remove_specialchars( error )
        return resp


    def list_self_owned_images(self):
        resp = []
        region = None
        try:
            if(is_json(self.args)):
                margs = json.loads(self.args)
                if margs.has_key("region"):
                    region = margs["region"]
            response = list_os_images_from_glance(self.tenant, self.user, self.password, self.host, self.version,region,True)
            resp = json.dumps(response)
        except Exception as error:
            resp = str_remove_specialchars( error )
        return resp


    def list_keypairs(self):
        resp = []
        region = None
        try:
            if(is_json(self.args)):
                margs = json.loads(self.args)
                if margs.has_key("region"):
                    region = margs["region"]
            response = list_os_keys(self.tenant, self.user, self.password, self.host, self.version, region)
            resp = json.dumps(response)
        except Exception as error:
            resp = str_remove_specialchars( error )
        return resp


    def list_firewalls(self):
        resp = []
        region = None
        try:
            if(is_json(self.args)):
                margs = json.loads(self.args)
                if margs.has_key("region"):
                    region = margs["region"]
            response = list_os_sgroups(self.tenant, self.user, self.password, self.host, self.version, region)
            resp = json.dumps(response)
        except Exception as error:
            resp = str_remove_specialchars( error )
        return resp


    def create_keypair(self):
        resp = []
        keyname = None
        region = None
        try:
            if not(is_json(self.args)):
                response='{"message": "failure key_name argument is mandatory for this action", "status": "400"}'
                return response
            margs = json.loads(self.args)
            if not(margs.has_key("key_name")):
                response = '{"message": "failure key_name argument is mandatory for this action", "status": "400"}'
                return response
            keyname = margs["key_name"]
            if margs.has_key("region"):
                region = margs["region"]

            provider = "openstack"
            if "cloudwatt" in self.host:
                provider = "cloudwatt"
            keydir = pypacksrc.workdir + "/" + pypacksrc.sshdir + "/" + self.accountname + "/" + provider
            response = os_create_keypair( self.tenant, self.user, self.password, self.host, self.version, region, keyname, keydir )
            resp = json.dumps(response)
        except Exception as error:
            resp = str_remove_specialchars( error )
        return resp


    def delete_firewall(self):
        resp = []
        secgid = None
        region = None
        try:
            if not(is_json(self.args)):
                response='{"message": "failure security_group_id argument is mandatory for this action", "status": "400"}'
                return response
            margs = json.loads(self.args)
            if not(margs.has_key("security_group_id")):
                response = '{"message": "failure security_group_id argument is mandatory for this action", "status": "400"}'
                return response
            secgid = margs["security_group_id"]
            if margs.has_key("region"):
                region = margs["region"]

            response = delete_security_group( self.tenant, self.user, self.password, self.host, self.version, region, secgid )
            resp = json.dumps(response)
        except Exception as error:
            resp = str_remove_specialchars( error )
        return resp


    def delete_keypair(self):
        resp = []
        keyname = None
        region = None
        try:
            if not(is_json(self.args)):
                response='{"message": "failure key_name argument is mandatory for this action", "status": "400"}'
                return response
            margs = json.loads(self.args)
            if not(margs.has_key("key_name")):
                response = '{"message": "failure key_name argument is mandatory for this action", "status": "400"}'
                return response
            keyname = margs["key_name"]
            if margs.has_key("region"):
                region = margs["region"]

            keydir = pypacksrc.workdir + "/" + pypacksrc.sshdir + "/" + self.accountname + "/" + keyname + ".pem"
            response = delete_keypair( self.tenant, self.user, self.password, self.host, self.version, region, keyname, keydir )
            resp = json.dumps(response)
        except Exception as error:
            resp = str_remove_specialchars( error )
        return resp


    def get_volume_types(self):
        resp = []
        region = None
        try:
            if(is_json(self.args)):
                margs = json.loads(self.args)
                if margs.has_key("region"):
                    region = margs["region"]
            vtypes = get_os_volume_types(self.tenant, self.user, self.password, self.host, self.version, region)
            resp = json.dumps(vtypes)
        except Exception as error:
            resp = str_remove_specialchars( error )
        return resp


    def get_current_usage(self):
        resp = []
        sname ="horse"
        region = None
        if not( "cloudwatt" in self.host):
            return "This action is not yet supported on this provider"
        try:
            if not(is_json(self.args)):
                response='{"message": "failure service_name argument is mandatory for this action", "status": "400"}'
                return response
            margs = json.loads(self.args)
            if not(margs.has_key("service_name")):
                response = '{"message": "failure service_name argument is mandatory for this action", "status": "400"}'
                return response
            sname = margs["service_name"]
            if margs.has_key("region"):
                region = margs["region"]

            status, token, urlb =  cw_get_billing_cred(self.tenant, self.user, self.password, self.host, sname)
            if not (status):
                return '{"message": "failure %s", "status_code": "%s"}' % (token, urlb)

            status, resp_data, customerid = cw_get_customerid(urlb, token, CONSUMPTION)
            if not (status):
                return '{"message": "failure %s", "status_code": "%s"}' % (resp_data, customerid)

            status, usage, code = cw_get_current_usage(urlb, token, customerid)
            if not (status):
                return '{"message": "failure %s", "status_code": "%s"}' % (usage, code)
            resp = json.dumps(usage)
        except Exception as error:
            resp = str_remove_specialchars( error )
        return resp


    def list_invoices(self):
        resp = []
        sname ="horse"
        extension = "csv"
        region = None
        if not( "cloudwatt" in self.host):
            return "This action is not yet supported on this provider"
        try:
            if not(is_json(self.args)):
                response='{"message": "failure extension and service_name arguments are mandatory for this action", "status": "400"}'
                return response
            margs = json.loads(self.args)
            if not(margs.has_key("service_name")) or not(margs.has_key("extension")):
                response = '{"message": "failure extension and servic_ename arguments are mandatory for this action", "status": "400"}'
                return response
            extension = margs["extension"]
            sname = margs["service_name"]
            if margs.has_key("region"):
                region = margs["region"]

            status, token, urlb =  cw_get_billing_cred(self.tenant, self.user, self.password, self.host, sname)
            if not (status):
                return '{"message": "failure %s", "status_code": "%s"}' % (token, urlb)

            status, resp_data, customerid = cw_get_customerid(urlb, token, BILLING_INVOICES)
            if not (status):
                return '{"message": "failure %s", "status_code": "%s"}' % (resp_data, customerid)

            status, invoice, code = cw_list_invoice(urlb, token, customerid, extension=extension)
            if not (status):
                return '{"message": "failure %s", "status_code": "%s"}' % (invoice, code)
            resp = json.dumps(invoice)
        except Exception as error:
            resp = str_remove_specialchars( error )
        return resp


    def list_instances(self):
        resp = "failure to list provider instances"
        region = None
        uicbflag = None
        try:

            if (is_json(self.args)):
                margs = json.loads(self.args)
                if margs.has_key("region"):
                    region = margs["region"]
                if margs.has_key("filter"):
                    uicbflag = margs["filter"]
            if uicbflag not in ['only_uicb','not_uicb']:
                return '{"message": "failure filter valid value (only_uicb/not_uicb) for this action", "status_code": "400"}'
            response = os_list_instances(self.tenant, self.user, self.password, self.host, self.version, region, uicbflag=uicbflag)
            resp = json.dumps(response)
        except Exception as error:
            resp = str_remove_specialchars( error )
        return resp


    def list_snapshot_images(self):
        resp = []
        region = None
        try:
            if (is_json(self.args)):
                margs = json.loads(self.args)
                if margs.has_key("region"):
                    region = margs["region"]
            response = os_list_snapshot_images(self.tenant, self.user, self.password, self.host, self.version, region)
            resp = json.dumps(response)
        except Exception as error:
            resp = str_remove_specialchars( error )
        return resp


    def list_backup_images(self):
        resp=[]
        region = None
        try:
            if (is_json(self.args)):
                margs = json.loads(self.args)
                if margs.has_key("region"):
                    region = margs["region"]
            response = os_list_backup_images(self.tenant, self.user, self.password, self.host, self.version, region)
            resp = json.dumps(response)
        except Exception as error:
            resp = str_remove_specialchars( error )
        return resp


    def list_networks(self):
        resp=[]
        region = None
        try:
            if (is_json(self.args)):
                margs = json.loads(self.args)
                if margs.has_key("region"):
                    region = margs["region"]
            response = os_list_networks(self.tenant, self.user, self.password, self.host, self.version, region)
            resp = json.dumps(response)
        except Exception as error:
            resp = str_remove_specialchars( error )
        return resp


    def list_snapshot_volumes(self):
        resp = []
        region = None
        try:
            if (is_json(self.args)):
                margs = json.loads(self.args)
                if margs.has_key("region"):
                    region = margs["region"]
            response = os_list_snapshot_volumes(self.tenant, self.user, self.password, self.host, self.version, region)
            resp = json.dumps(response)
        except Exception as error:
            resp = str_remove_specialchars( error )
        return resp


    def perform_on_snapshot_image(self):
        snapid = None
        method = None
        resp = []
        region = None
        try:
            if not(is_json(self.args)):
                response='{"message": "failure method and snapshot_id arguments are mandatory for this action", "status": "400"}'
                return response
            margs = json.loads(self.args)
            if not(margs.has_key("method")) or not(margs.has_key("snapshot_id")):
                response = '{"message": "failure method and snapshot_id arguments are mandatory for this action", "status": "400"}'
                return response
            snapid = margs["snapshot_id"]
            method = margs["method"]
            if margs.has_key("region"):
                region = margs["region"]
            response = os_perform_on_snapshot_image(self.tenant, self.user, self.password, self.host, self.version, region, snapid, method)
            resp = json.dumps(response)
        except Exception as error:
            resp = str_remove_specialchars( error )
        return resp


    def perform_on_snapshot_volume(self):
        snapid = None
        method = None
        resp = []
        region = None
        try:
            if not(is_json(self.args)):
                response='{"message": "failure method and snapshot_id arguments are mandatory for this action", "status": "400"}'
                return response
            margs = json.loads(self.args)
            if not(margs.has_key("method")) or not(margs.has_key("snapshot_id")):
                response = '{"message": "failure method and snapshot_id arguments are mandatory for this action", "status": "400"}'
                return response
            snapid = margs["snapshot_id"]
            method = margs["method"]
            if margs.has_key("region"):
                region = margs["region"]
            response = os_perform_on_snapshot_volume(self.tenant, self.user, self.password, self.host, self.version, region, snapid, method)
            resp = json.dumps(response)
        except Exception as error:
            resp = str_remove_specialchars( error )
        return resp


    def perform_on_instance(self):
        instanceid = None
        method = None
        resp = []
        metadata = None
        flavor_id = None
        confirm = None
        snapshot_name = None
        console_type = None
        console = None
        name = None
        image_id = None
        preserve = None
        backup_name = None
        backup_type = None
        rotation = None
        region = None
        try:
            if not(is_json(self.args)):
                response='{"message": "failure method and instance_id arguments are mandatory for this action", "status": "400"}'
                return response
            margs = json.loads(self.args)
            if not(margs.has_key("method")) or not(margs.has_key("instance_id")):
                response = '{"message": "failure method and instance_id arguments are mandatory for this action", "status": "400"}'
                return response
            instanceid = margs["instance_id"]
            method = margs["method"]
            if margs.has_key("console"):
                console = margs["console"]
            if margs.has_key("metadata"):
                metadata = margs["metadata"]
            if margs.has_key("flavor_id"):
                flavor_id = margs["flavor_id"]
            if margs.has_key("confirm"):
                confirm = margs["confirm"]
            if margs.has_key("console_type"):
                console_type = margs["console_type"]
            if margs.has_key("name"):
                name = margs["name"]
            if margs.has_key("snapshot_name"):
                snapshot_name = margs["snapshot_name"]
            if margs.has_key("image_id"):
                image_id = margs["image_id"]
            if margs.has_key("preserve"):
                preserve = margs["preserve"]
            if margs.has_key("backup_name"):
                backup_name = margs["backup_name"]
            if margs.has_key("backup_type"):
                backup_type = margs["backup_type"]
            if margs.has_key("rotation"):
                rotation = margs["rotation"]
            if margs.has_key("region"):
                region = margs["region"]
            response = os_perform_on_instance(self.tenant, self.user, self.password, self.host, self.version, region, instanceid, method, flavorid=flavor_id, confirm=confirm, console=console, console_type=console_type, snapshot_name=snapshot_name, metadata=metadata, vm_name=name, image_id=image_id, preserve=preserve, backup_name=backup_name, backup_type=backup_type, rotation=rotation)
            resp = json.dumps(response)
        except Exception as error:
            resp = str_remove_specialchars( error )
        return resp


    def perform_on_vnet(self):
        vnetid = None
        region = None
        response = []
        method = None
        routerid = None
        portid = None
        subnetid = None
        cidr = None
        ipversion = None
        dns = None
        subnetname = None
        routername = None
        try:
            if not(is_json(self.args)):
                response='{"message": "failure method and vnet_id are mandatory for this action", "status": "400"}'
                return response
            margs = json.loads(self.args)
            if not(margs.has_key("method")) or not(margs.has_key("vnet_id")):
                response = '{"message": "failure method and vnet_id are mandatory for this action", "status": "400"}'
                return response
            vnetid = margs["vnet_id"]
            method = margs["method"]

            if margs.has_key("region"):
                region = margs["region"]
            if margs.has_key("subnet_id"):
                subnetid = margs["subnet_id"]
            if margs.has_key("router_id"):
                routerid = margs["router_id"]
            if margs.has_key("router_name"):
                routername = margs["router_name"]
            if margs.has_key("dns"):
                dns = margs["dns"]
            if margs.has_key("port_id"):
                portid = margs["port_id"]
            if margs.has_key("ip_version"):
                ipversion = margs["ip_version"]
            if margs.has_key("subnet_name"):
                subnet_name = margs["subnet_name"]
            if margs.has_key("cidr_block"):
                cidr = margs["cidr_block"]

            response = os_perform_on_vnet(self.tenant, self.user, self.password, self.host, self.version, region, vnetid, method, routerid=routerid, routername=routername, portid = portid, subnetname = subnetname, subnetid = subnetid, dns=dns, ipversion=ipversion, cidr=cidr)
            resp = json.dumps(response)
        except Exception as error:
            resp = str_remove_specialchars( error )
        return resp



    OS_FUNCTION = {
            "list_flavors": list_flavors,
            "list_images": list_images,
            "get_quotas" : get_quotas,
            "get_volume_types" : get_volume_types,
            "get_current_billing_items" : get_current_usage,
            "get_invoices" : list_invoices,
            "list_instances": list_instances,
            "list_snapshot_images": list_snapshot_images,
            "list_snapshot_volumes": list_snapshot_volumes,
            "list_backup_images" : list_backup_images,
            "perform_on_snapshot_image": perform_on_snapshot_image,
            "perform_on_snapshot_volume": perform_on_snapshot_volume,
            "perform_on_instance": perform_on_instance,
            "list_keypairs": list_keypairs,
            "list_firewalls": list_firewalls,
            "delete_keypair": delete_keypair,
            "create_keypair": create_keypair,
            "delete_firewall": delete_firewall,
            "list_self_owned_images": list_self_owned_images,
            "list_vnets": list_networks,
            "perform_on_vnet": perform_on_vnet
            }


    def get_generic_function(self):
        resp = self.OS_FUNCTION[self.action](self)
        if "failure" in str(resp):
            response = resp
        else:
            response = "json:" + resp
        return response


def os_perform_action(tenant, user, password, host, version, accountname, action, args):
    try:
        os_obj = OsFunction(tenant, user, password, host, version, accountname, action, args)
        if not( OsFunction.OS_FUNCTION.has_key(action) ):
            return "failure unsupported action"
        return os_obj.get_generic_function()
    except Exception as error:
        response = str_remove_specialchars( error )
    return\
        response

def os_vnet_invoke_action(tenant, user, password, host, version, zone, avzone, accountname, userowner, netid, action, args):
    maction = "perform_on_vnet"
    margs = {"region": zone ,"vnet_id": netid,"method":action}
    if args:
        nargs = json.loads(args)
        margs.update(nargs)
    response = os_perform_action(tenant, user, password, host, version, accountname, maction, margs)
    return response
