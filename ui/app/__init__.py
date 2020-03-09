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
import yaml
from base64 import b32encode, b32decode
from kubernetes.client.rest import ApiException
from flask import Flask, render_template, flash, redirect, url_for, request, session
from flask_session import Session
from flask_bootstrap import Bootstrap
from werkzeug.middleware.proxy_fix import ProxyFix


if os.path.exists("/var/run/secrets/kubernetes.io/serviceaccount/namespace"):
    console_namespace = open("/var/run/secrets/kubernetes.io/serviceaccount/namespace").read()
    kubernetes.config.load_incluster_config()
else:
    kubernetes.config.load_kube_config()
    console_namespace = kubernetes.config.list_kube_config_contexts()[1]['context']['namespace']

def random_string(length):
    return ''.join([random.choice(string.ascii_letters + string.digits) for n in range(length)])

access_password = os.getenv('ACCESS_PASSWORD', '')
admin_password = os.getenv('ADMIN_PASSWORD', random_string(32))
poolboy_domain = os.getenv('POOLBOY_DOMAIN', 'poolboy.gpte.redhat.com')
poolboy_version = os.getenv('POOLBOY_VERSION', 'v1')
poolboy_api_version = poolboy_domain + '/' + poolboy_version

core_v1_api = kubernetes.client.CoreV1Api()
custom_objects_api = kubernetes.client.CustomObjectsApi()

template_name = os.getenv('TEMPLATE_NAME', '')
if template_name == '':
    raise Exception('TEMPLATE_NAME environment variable not set!')
template_namespace = os.getenv('TEMPLATE_NAMESPACE', 'openshift')
template_parameters = yaml.safe_load(os.getenv('TEMPLATE_PARAMETERS', '{}'))

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)

bootstrap = Bootstrap(app)

SECRET_KEY = random_string(32)
SESSION_TYPE = 'redis'
SESSION_REDIS = redis.from_url('redis://:{0}@{1}'.format(os.getenv('REDIS_PASSWORD'), os.getenv('REDIS_SERVER')))
app.config.from_object(__name__)
Session(app)

api_groups = {}

def encode_session_id(session_id):
    return b32encode(session_id.encode('utf-8')).decode('ascii').replace('=','z')

@app.template_filter()
def decode_session_id(session_id):
    return b32decode(session_id.replace('z','=')).decode('utf-8')

def create_resource(resource_definition):
    if '/' in resource_definition['apiVersion']:
        group, version = resource_definition['apiVersion'].split('/')
        namespace = resource_definition['metadata'].get('namespace', console_namespace)
        plural, namespaced = get_api(group, version, resource_definition['kind'])
        if namespaced:
            return custom_objects_api.create_namespaced_custom_object(
                group, version, namespace, plural, resource_definition
            )
        else:
            return custom_objects_api.create_cluster_custom_object(
                group, version, plural, resource_definition
            )
    else:
        kind = resource_definition['kind']
        namespace = resource_definition['metadata'].get('namespace', console_namespace)
        create_namespaced_method = 'create_namespaced_' + inflection.underscore(kind)
        create_cluster_method = 'create_' + inflection.underscore(kind)
        if hasattr(core_v1_api, create_namespaced_method):
            method = getattr(core_v1_api, create_namespaced_method)
            return method(namespace, resource_definition).to_dict()
        else:
            method = getattr(core_v1_api, create_cluster_method)
            return method(resource_definition).to_dict()

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
    raise Exception('Unable to find kind {} in {}/{}'.format(kind, group, version))

def get_lab_url(resource_claim):
    routes = custom_objects_api.list_namespaced_custom_object(
        'route.openshift.io', 'v1', console_namespace, 'routes',
        label_selector="{}/resource-claim={}".format(poolboy_domain, resource_claim['metadata']['name'])
    ).get('items', [])
    if routes:
        return '{}://{}/'.format(
            'https' if 'tls' in routes[0]['spec'] else 'http',
            routes[0]['spec']['host']
        )
    else:
        return None

def get_resource_claims(session_id=None):
    if session_id == 'unowned':
        return custom_objects_api.list_namespaced_custom_object(
            poolboy_domain, poolboy_version, console_namespace, 'resourceclaims',
            label_selector='!session-id'
        ).get('items', [])
    elif session_id:
        return custom_objects_api.list_namespaced_custom_object(
            poolboy_domain, poolboy_version, console_namespace, 'resourceclaims',
            label_selector='session-id=' + encode_session_id(session_id)
        ).get('items', [])
    else:
        return custom_objects_api.list_namespaced_custom_object(
            poolboy_domain, poolboy_version, console_namespace, 'resourceclaims'
        ).get('items', [])

def get_session_id():
    session_id = session.get('id', None)
    if not session_id:
        session_id = random_string(32)
        session['id'] = session_id
    return session_id

def assign_unowned_claim(session_id):
    '''
    Assigned an unowned resource claim to this session.
    '''
    resource_claims = get_resource_claims('unowned')
    for resource_claim in resource_claims:
        claim_resources = resource_claim.get('status',{}).get('resources', None)
        if not claim_resources:
            continue
        subject_vars = claim_resources[0].get('state', {}).get('spec', {}).get('vars', {})
        try:
            if 'labels' not in resource_claim['metadata']:
                resource_claim['metadata']['labels'] = {}
            resource_claim['metadata']['labels']['session-id'] = encode_session_id(session_id)
            return custom_objects_api.replace_namespaced_custom_object(
                poolboy_domain, poolboy_version, console_namespace, 'resourceclaims',
                resource_claim['metadata']['name'], resource_claim
            )
        except ApiException as e:
            # 409 means the resource changed, most likely because another user claimed it first
            if e.status != 409:
                raise

    return None

def provision_from_template(session_id=None):
    template = custom_objects_api.get_namespaced_custom_object(
        'template.openshift.io', 'v1', template_namespace, 'templates', template_name
    )

    resource_claims = []
    for resource_definition in substitute_template_parameters(template.get('objects', []), template_parameters):
        if 'annotations' not in resource_definition['metadata']:
            resource_definition['metadata']['annotations'] = {}
        resource_definition['metadata']['annotations']['template.openshift.io/name'] = template['metadata']['name']
        resource_definition['metadata']['annotations']['template.openshift.io/namespace'] = template['metadata']['namespace']
        if 'labels' not in resource_definition['metadata']:
            resource_definition['metadata']['labels'] = {}
        if session_id:
            resource_definition['metadata']['labels']['session-id'] = encode_session_id(session_id)
        resource = create_resource(resource_definition)
        if resource['apiVersion'] == poolboy_api_version \
        and resource['kind'] == 'ResourceClaim':
            resource_claims.append(resource)
    return resource_claims

def reset_session():
    session['access_authenticated'] = False
    session['id'] = None
    session['resource_claim_assigned'] = False

def substitute_template_parameters(value, parameters):
    if isinstance(value, dict):
        return { k: substitute_template_parameters(v, parameters) for k, v in value.items() }
    elif isinstance(value, list):
        return [ substitute_template_parameters(item, parameters) for item in value ]
    elif isinstance(value, str):
        for k, v in parameters.items():
            value = value.replace('${' + k + '}', v)
        return value
    else:
        return value

@app.route('/', methods=['GET'])
def index():
    # User authentication if required
    if access_password \
    and not session.get('access_authenticated') \
    and not session.get('admin_authenticated'):
        reset_session()
        return render_template('login.html', password_required=(access_password != ''))

    # Session initialization
    session_id = request.args.get('session_id')
    if not session_id:
        session_id = session.get('id', None)
        if session_id:
            return redirect(url_for('index', session_id=session_id))
        else:
            reset_session()
            return render_template('login.html', password_required=(access_password != ''))

    # Get lab environment settings
    resource_claims = get_resource_claims(session_id)
    meta_refresh = 30
    if not resource_claims:
        if session.get('resource_claim_assigned', False):
            # Resource claim is missing, access reset
            reset_session()
            return redirect(url_for('index'))

        meta_refresh = 2
        resource_claim = assign_unowned_claim(session_id)
        if resource_claim:
            resource_claims = [resource_claim]
        else:
            resource_claims = provision_from_template(session_id)

    session['resource_claim_assigned'] = True

    lab_urls = [
        get_lab_url(resource_claim) for resource_claim in resource_claims
    ]

    return render_template('index.html', resource_claims=resource_claims, lab_urls=lab_urls, session_id=session_id, meta_refresh=meta_refresh)

@app.route('/admin', methods=['GET'])
def admin():
    if not session.get('admin_authenticated'):
        return render_template('admin-login.html')

    resource_claims = get_resource_claims()
    return render_template('admin.html', resource_claims=resource_claims)

@app.route('/admin/create', methods=['POST'])
def admin_create():
    if not session.get('admin_authenticated'):
        return render_template('admin-login.html')

    number = int(request.form.get('number', 1))
    for i in range(number):
        provision_from_template()

    flash('{0} environment{1} created'.format(number, 's' if number > 1 else ''))
    return redirect(url_for('admin'))

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

@app.route('/admin/login', methods=['POST'])
def admin_login():
    password = request.form.get('password')
    if password == admin_password:
        session['admin_authenticated'] = True
        return redirect(url_for('admin'))
    return render_template('admin-login.html', login_failed=True)

@app.route('/admin/logout', methods=['GET'])
def admin_logout():
    session['admin_authenticated'] = False
    return redirect(url_for('index'))

@app.route('/login', methods=['POST'])
def login():
    session_id = request.form.get('id')

    if len(session_id) < 6:
        return render_template('login.html', session_id=session_id, invalid_session_id=True)

    if access_password:
        if access_password == request.form.get('password'):
            session['access_authenticated'] = True
        else:
            return render_template('login.html', login_failed=True)

    session['id'] = session.get('id', session_id)
    return redirect(url_for('index', session_id=session_id))

@app.route('/logout', methods=['POST'])
def logout():
    session['access_authenticated'] = False
    session['session_id'] = None
    return redirect(url_for('index'))
