#!/usr/bin/env python3

import json
import yaml
import kopf
import kubernetes
import os
import prometheus_client
import re
import subprocess
import time

if os.path.exists('/var/run/secrets/kubernetes.io/serviceaccount/namespace'):
    kubernetes.config.load_incluster_config()
    namespace = open("/var/run/secrets/kubernetes.io/serviceaccount/namespace").read()
else:
    kubernetes.config.load_kube_config()
    namespace = kubernetes.config.list_kube_config_contexts()[1]['context']['namespace']

core_v1_api = kubernetes.client.CoreV1Api()
custom_objects_api = kubernetes.client.CustomObjectsApi()

beui_domain = os.environ.get('BEUI_DOMAIN', 'beui.gpte.redhat.com')
poolboy_domain = os.environ.get('POOLBOY_DOMAIN', 'poolboy.gpte.redhat.com')
poolboy_version = os.environ.get('POOLBOY_VERSION', 'v1')

bookbag_imagestream_name = os.environ.get('BOOKBAG_IMAGESTREAM_NAME')
bookbag_imagestream_namespace = os.environ.get('BOOKBAG_IMAGESTREAM_NAMESPACE', '')
if not bookbag_imagestream_namespace:
    bookbag_imagestream_namespace = namespace

bookbag_template_name = os.environ.get('BOOKBAG_TEMPLATE_NAME', 'bookbag')
bookbag_template_namespace = os.environ.get('BOOKBAG_TEMPLATE_NAMESPACE', '')
if not bookbag_template_namespace:
    bookbag_template_namespace = 'openshift'

def get_latest_image_from_bookbag_imagestream():
    bookbag_imagestream = custom_objects_api.get_namespaced_custom_object(
        'image.openshift.io', 'v1', bookbag_imagestream_namespace, 'imagestreams', bookbag_imagestream_name
    )
    for is_tag in bookbag_imagestream.get('status', {}).get('tags', []):
        if is_tag['tag'] == 'latest':
            return is_tag['items'][0]['dockerImageReference']
    return None

def manage_config_map(name, data, resource_claim_ref):
    '''
    Create or update config map based on config map data
    '''
    data = {
        k: data[k] if isinstance(data[k], str) else json.dumps(data[k]) for k in data
    }
    try:
        config_map = core_v1_api.read_namespaced_config_map(name, namespace)
        config_map.data = data
        core_v1_api.replace_namespaced_config_map(name, namespace, config_map)
    except kubernetes.client.rest.ApiException as e:
        if e.status == 404:
            core_v1_api.create_namespaced_config_map(
                namespace,
                kubernetes.client.V1ConfigMap(
                    data = data,
                    metadata = kubernetes.client.V1ObjectMeta(
                        name = name,
                        labels = {beui_domain + '/session-id': None},
                        owner_references = [resource_claim_ref]
                    )
                )
            )
        else:
            raise

def process_bookbag_template(config_map, image=None):
    '''
    Use `oc` to process bookbag template and produce resource list json.
    '''
    oc_process_cmd = [
        'oc', 'process', bookbag_template_namespace + '//' + bookbag_template_name,
        '-o', 'json',
        '-p', 'NAME=' + config_map['metadata']['name'],
        '-p', 'IMAGE_STREAM_NAME=' + bookbag_imagestream_name,
        '-p', 'IMAGE_STREAM_NAMESPACE=' + bookbag_imagestream_namespace,
        '-p', 'WORKSHOP_VARS=' + json.dumps(config_map['data']),
    ]
    if image:
        oc_process_cmd.extend(['-p', 'IMAGE=' + image])
    oc_process_result = subprocess.run(oc_process_cmd, stdout=subprocess.PIPE, check=True)
    return json.loads(oc_process_result.stdout)

def handle_config_map(config_map, logger):
    '''
    Create or update bookbag interfaces for config map.
    '''
    image = get_latest_image_from_bookbag_imagestream()
    template_output = process_bookbag_template(config_map, image)
    config_map_ref = dict(
        apiVersion = config_map['apiVersion'],
        controller = True,
        blockOwnerDeletion = False,
        kind = config_map['kind'],
        name = config_map['metadata']['name'],
        uid = config_map['metadata']['uid']
    )
    for item in template_output['items']:
        metadata = item['metadata']
        if 'ownerReferences' in metadata:
            if config_map_ref not in metadata['ownerReferences']:
                metadata['ownerReferences'].append(config_map_ref)
        else:
            metadata['ownerReferences'] = [config_map_ref]
    oc_apply_result = subprocess.run(['oc', 'apply', '-f', '-'], input=json.dumps(template_output).encode('utf-8'), stdout=subprocess.PIPE, check=True)
    for line in oc_apply_result.stdout.decode('utf-8').splitlines():
        logger.info(line)

def handle_resource_claim(resource_claim, logger):
    '''
    Create ConfigMaps for user lab environments based on ResourceClaim if provisioning has completed.
    '''
    users = {}
    provision_data = {}
    provision_messages = []
    resource_handle_ref = resource_claim.get('status', {}).get('resourceHandle')
    if not resource_handle_ref:
        return
    guid = resource_handle_ref['name'][5:]
    for resource in resource_claim.get('status', {}).get('resources', []):
        state = resource.get('state')
        if not state:
            return
        if state['apiVersion'] != 'anarchy.gpte.redhat.com/v1' \
        or state['kind'] != 'AnarchySubject':
            continue
        if 'completeTimestamp' not in state.get('status', {}).get('towerJobs', {}).get('provision', {}):
            return

        spec_vars = state.get('spec', {}).get('vars', {})
        if 'provision_data' not in spec_vars:
            # No provision_data means provisioning has not finished
            continue
        provision_data.update(spec_vars.get('provision_data', {}))
        provision_messages.extend(spec_vars.get('provision_messages', []))
        for user, user_data in provision_data.get('users', {}).items():
            if user in users:
                users[user].update(user_data)
            else:
                users[user] = user_data

    resource_claim_ref = dict(
        apiVersion = resource_claim['apiVersion'],
        controller = True,
        blockOwnerDeletion = False,
        kind = resource_claim['kind'],
        name = resource_claim['metadata']['name'],
        uid = resource_claim['metadata']['uid']
    )

    if users:
        for user, user_data in users.items():
            user_data['guid'] = guid
            user_data['user'] = user
            manage_config_map('bookbag-{0}-{1}'.format(guid, user), user_data, resource_claim_ref)
    else:
        if provision_messages:
            provision_data['user_info_messages'] = "\n".join(provision_messages)
        provision_data['guid'] = guid
        manage_config_map('bookbag-{0}'.format(guid), provision_data, resource_claim_ref)

@kopf.on.event(poolboy_domain, poolboy_version, 'resourceclaims')
def watch_resource_claims(event, logger, **_):
    '''
    Watch ResourceClaims and manage ConfigMaps.
    '''
    if event['type'] in ['ADDED', 'MODIFIED', None]:
        resource_claim = event['object']
        logger.debug('ResourceClaim %s', resource_claim)
        handle_resource_claim(resource_claim, logger)
    else:
        logger.warning('Unhandled ResourceClaim event %s', event)

@kopf.on.event('', 'v1', 'configmaps', labels={beui_domain + '/session-id': None})
def watch_config_maps(event, logger, **_):
    '''
    Watch ConfigMaps and manage bookbag interfaces.
    '''
    if not bookbag_imagestream_name:
        return
    if event['type'] in ['ADDED', 'MODIFIED', None]:
        config_map = event['object']
        logger.info('ConfigMap %s', config_map)
        handle_config_map(config_map, logger)
    else:
        logger.warning('Unhandled ConfigMap event %s', event)
