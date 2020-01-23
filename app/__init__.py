"""
This module runs a simple Flask-based front-end to Babylon/Anarchy 
ResourceClaims
"""
import os
import random
import redis
import string
import time
import kubernetes
from kubernetes.client.rest import ApiException
from flask import Flask, render_template, flash, redirect, url_for, request, session
from flask_session import Session
from flask_bootstrap import Bootstrap

if os.path.exists("/var/run/secrets/kubernetes.io/serviceaccount/namespace"):
    console_namespace = open("/var/run/secrets/kubernetes.io/serviceaccount/namespace").read()
    kubernetes.config.load_incluster_config()
else:
    kubernetes.config.load_kube_config()
    console_namespace = kubernetes.config.list_kube_config_contexts()[1]['context']['namespace']

def random_string(length):
    return ''.join([random.choice(string.ascii_letters + string.digits) for n in range(length)])

admin_password = os.getenv('ADMIN_PASSWORD', random_string(32))
poolboy_domain = os.getenv('POOLBOY_DOMAIN', 'poolboy.gpte.redhat.com')
poolboy_version = os.getenv('POOLBOY_VERSION', 'v1')
autoprovision = os.getenv('AUTOPROVISION', '').lower() == 'true'
if autoprovision and '/' not in autoprovision:
    autoprovision = '{0}/{1}'.format(console_namespace, autoprovision)

template_namespaces = os.getenv('TEMPLATE_NAMESPACES', None)
if template_namespaces:
    template_namespaces = template_namespaces.split(',')
else:
    template_namespaces = []

core_v1_api = kubernetes.client.CoreV1Api()
custom_objects_api = kubernetes.client.CustomObjectsApi()

app = Flask(__name__)
bootstrap = Bootstrap(app)

SECRET_KEY = random_string(32)
SESSION_TYPE = 'redis'
SESSION_REDIS = redis.from_url('redis://:{0}@{1}'.format(os.getenv('REDIS_PASSWORD'), os.getenv('REDIS_SERVER')))
app.config.from_object(__name__)
Session(app)

api_groups = {}

def create_resource(resource_definition):
    if '/' in resource_definition['apiVersion']:
        group, version = resource_definition['apiVersion'].split('/')
        namespace = resource_definition['metadata'].get('namespace', console_namespace)
        plural, namespaced = get_api(group, version, resource_definition['kind'])
        if namespaced:
            custom_objects_api.create_namespaced_custom_object(
                group, version, namespace, plural, resource_definition
            )
        else:
            custom_objects_api.create_cluster_custom_object(
                group, version, plural, resource_definition
            )
    else:
        kind = resource_definition['kind']
        namespace = resource_definition['metadata'].get('namespace', console_namespace)
        create_namespaced_method = 'create_namespaced_' + inflection.underscore(kind)
        create_cluster_method = 'create_' + inflection.underscore(kind)
        if hasattr(core_v1_api, create_namespaced_method):
            method = getattr(core_v1_api, create_namespaced_method)
            method(namespace, resource_definition)
        else:
            method = getattr(core_v1_api, create_cluster_method)
            method(resource_definition)

def get_api(group, version, kind):
    if group in api_groups \
    and version in api_groups[group]:
        for resource in api_groups[group][version]['resources']:
            if resource['kind'] == kind:
                return resource['name'], resource['namespaced']

    resp = core_v1_api.api_client.call_api(
        '/apis/{}/{}'.format(group, version), 'GET',
        auth_settings=['BearerToken'], response_type='object'
    )
    group_info = resp[0]
    if group not in api_groups:
        api_groups[group] = {}
    api_groups[group][version] = group_info

    for resource in group_info['resources']:
        if resource['kind'] == kind:
            return resource['name'], resource['namespaced']
    raise Exception('Unable to find kind {} in {}/{}', kind, group, version)

def get_resource_claims(session_id=None):
    if session_id:
        return custom_objects_api.list_namespaced_custom_object(
            poolboy_domain, poolboy_version, console_namespace, 'resourceclaims',
            label_selector='session-id=' + session_id
        ).get('items', [])
    else:
        return custom_objects_api.list_namespaced_custom_object(
            poolboy_domain, poolboy_version, console_namespace, 'resourceclaims'
        ).get('items', [])

def get_available_templates():
    templates = custom_objects_api.list_namespaced_custom_object(
        'template.openshift.io', 'v1', console_namespace, 'templates',
        label_selector='gpte.redhat.com/agnosticv'
    ).get('items', [])
    for template_namespace in template_namespaces:
        templates.extend(custom_objects_api.list_namespaced_custom_object(
            'template.openshift.io', 'v1', template_namespace, 'templates',
            label_selector='gpte.redhat.com/agnosticv'
        ).get('items', []))
    templates.sort(key=lambda t: t['metadata']['name'] + t['metadata']['namespace'])
    return templates

def get_session_id():
    session_id = session.get('id', None)
    if not session_id:
        session_id = random_string(32)
        session['id'] = session_id
    return session_id

def get_template(namespace, name):
    return custom_objects_api.get_namespaced_custom_object(
        'template.openshift.io', 'v1', namespace, 'templates', name
    )

def substitute_parameters(value, parameters):
    if isinstance(value, dict):
        return { k:substitute_parameters(v, parameters) for k, v in value.items() }
    elif isinstance(value, list):
        return [ substitute_parameters(item, parameters) for item in value ]
    elif isinstance(value, str):
        for k, v in parameters.items():
            value = value.replace('${' + k + '}', v)
        return value
    else:
        return value

def handle_request_template(template):
    if template.get('parameters'):
        return render_template('request-template.html', template=template)
    else:
        return handle_instantiate_template(template, {})

def handle_instantiate_template(template, parameters):
    for resource_definition in substitute_parameters(template.get('objects', []), parameters):
        if 'annotations' not in resource_definition['metadata']:
            resource_definition['metadata']['annotations'] = {}
        resource_definition['metadata']['annotations']['template.openshift.io/name'] = template['metadata']['name']
        resource_definition['metadata']['annotations']['template.openshift.io/namespace'] = template['metadata']['namespace']
        if 'labels' not in resource_definition['metadata']:
            resource_definition['metadata']['labels'] = {}
        resource_definition['metadata']['labels']['session-id'] = get_session_id()
        create_resource(resource_definition)
    return redirect(url_for('index'))

@app.route('/', methods=['GET'])
def index():
    session_id = get_session_id()
    resource_claims = get_resource_claims(session_id)
    if autoprovision and not resource_claims:
        return redirect(url_for('_request'))
    return render_template('index.html', autoprovision=autoprovision, resource_claims=resource_claims, session_id=session_id)

@app.route('/admin', methods=['GET'])
def admin():
    if not session.get('admin_authenticated'):
        return render_template('admin-login.html')

    resource_claims = get_resource_claims()
    return render_template('admin.html', resource_claims=resource_claims)

@app.route('/admin/login', methods=['POST'])
def admin_login():
    password = request.form.get('password')
    if password == admin_password:
        session['admin_authenticated'] = True
    else:
        flash('login failed')
    return redirect(url_for('admin'))

@app.route('/admin/logout', methods=['GET'])
def admin_logout():
    session['admin_authenticated'] = False
    return redirect(url_for('index'))

@app.route('/request', methods=['GET'])
def _request():
    selected_template = request.args.get('template', autoprovision)
    if selected_template:
        template_namespace, template_name = selected_template.split('/')
        template = get_template(template_namespace, template_name)
        return handle_request_template(template)

    available_templates = get_available_templates()
    if len(available_templates) == 1:
        return handle_request_template(available_templates[0])
    else:
        return render_template('request-catalog.html', templates=available_templates)

@app.route('/admin/delete/<claim_name>', methods=['POST'])
def admin_delete_resource_claim(claim_name):
    if not session.get('admin_authenticated'):
        flash('authentication required')
        return redirect(url_for('admin'))

    try:
        custom_objects_api.delete_namespaced_custom_object(
            poolboy_domain, poolboy_version, console_namespace, 'resourceclaims', claim_name,
            kubernetes.client.V1DeleteOptions()
        )
    except ApiException as e:
        if e.status != 404:
            raise
    flash('{0} deleted'.format(claim_name))
    return redirect(url_for('admin'))

@app.route('/delete/<claim_name>', methods=['POST'])
def delete_resource_claim(claim_name):
    session_id = get_session_id()
    try:
        resource_claim = custom_objects_api.get_namespaced_custom_object(
            poolboy_domain, poolboy_version, console_namespace, 'resourceclaims', claim_name
        )
        if resource_claim['metadata']['labels']['session-id'] == session_id:
            custom_objects_api.delete_namespaced_custom_object(
                poolboy_domain, poolboy_version, console_namespace, 'resourceclaims', claim_name,
                kubernetes.client.V1DeleteOptions()
            )
        else:
            flash('Not the owner of {0}'.format(claim_name))
    except ApiException as e:
        if e.status == 404:
            flash('{0} not found'.format(claim_name))
        else:
            raise
    flash('{0} deleted'.format(claim_name))
    return redirect(url_for('index'))

#    try:
#        response = api.list_namespaced_custom_object(
#            poolboy_domain, poolboy_version, 'resourceclaims'
#        )
#    except ApiException:
#        return render_template('notfound.html')
#
#    try:
#        cr_name = response['items'][0]['metadata']['name']
#    except IndexError:
#        return render_template('notfound.html')
#
#
#    cr_status = api.get_namespaced_custom_object(
#        cr_group, cr_version,
#        cr_namespace, cr_plural,
#        cr_name
#    )
#
#    if (cr_status['spec']['template']['spec']['desiredState'] == 'stopped' and
#            len(btn_classes['stop']) < 3):
#        btn_classes['stop'].append('disabled')
#
#    if (cr_status['spec']['template']['spec']['desiredState'] == 'started' and
#            len(btn_classes['start']) < 3):
#        btn_classes['start'].append('disabled')
#
#    try:
#        curr_state = cr_status['status']['resource']['status']['state']
#    except KeyError:
#        return render_template('starting.html')
#    if (cr_status['status']['resource']['status']['state'] == 'stopped' and
#        cr_status['spec']['template']['spec']['desiredState'] == 'stopped' and
#        len(btn_classes['start']) >= 3):
#        btn_classes['start'].pop(-1)
#
#    if (cr_status['status']['resource']['status']['state'] == 'started' and
#        cr_status['spec']['template']['spec']['desiredState'] == 'started' and
#        len(btn_classes['stop']) >= 3):
#        btn_classes['stop'].pop(-1)
#
#
#    return render_template('index.html',
#                           btn_classes=btn_classes,
#                           cr_status=cr_status)
#
#    @app.route('/version')
#def version():
#    return os.getenv("VERSION", "0.0")
#
#@app.route('/start')
#def start():
#    cr_status = api.get_namespaced_custom_object(cr_group, cr_version,
#                                                 cr_namespace, cr_plural,
#                                                 cr_name)
## Disable Start and enable Stop buttons
#    if len(btn_classes['start']) < 3:
#        btn_classes['start'].append('disabled')
#    if len(btn_classes['stop']) >= 3:
#        btn_classes['stop'].pop(-1)
#    try:
#        response = api.patch_namespaced_custom_object(
#            group=cr_group,
#            version=cr_version,
#            plural=cr_plural,
#            name=cr_name,
#            namespace=cr_namespace,
#            body=body_start)
#    except ApiException as e:
#        print("Exception when calling \
#              CustomObjectsApi->patch_namespaced_custom_object: %s\n" % e)
#    return redirect(url_for('index'))
#
#@app.route('/stop')
#def stop():
#    cr_status = api.get_namespaced_custom_object(
#        cr_group, cr_version,
#        cr_namespace, cr_plural,
#        cr_name
#    )
#    # Disable Stop and enable Start buttons
#    if len(btn_classes['stop']) < 3:
#        btn_classes['stop'].append('disabled')
#    if len(btn_classes['start']) >= 3:
#        btn_classes['start'].pop(-1)
#    try:
#        response = api.patch_namespaced_custom_object(
#            group=cr_group,
#            version=cr_version,
#            plural=cr_plural,
#            name=cr_name,
#            namespace=cr_namespace,
#            body=body_stop
#        )
#    except ApiException as e:
#        print("Exception when calling \
#              CustomObjectsApi->patch_namespaced_custom_object: %s\n" % e)
#    return redirect(url_for('index'))
#
#@app.route('/delete')
#def delete():
#    cr_status = api.get_namespaced_custom_object(
#        cr_group, cr_version,
#        cr_namespace, cr_plural,
#        cr_name
#    )
#    body = client.V1DeleteOptions()
#    try:
#        response = api.delete_namespaced_custom_object(
#            group=cr_group,
#            version=cr_version,
#            plural=cr_plural,
#            name=cr_name,
#            namespace=cr_namespace,
#            body=body)
#    except ApiException as e:
#        print("Exception when calling \
#              CustomObjectsApi->patch_namespaced_custom_object: %s\n" % e)
#    return redirect(url_for('index'))
