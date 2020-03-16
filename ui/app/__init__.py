"""
This module runs a simple Flask-based front-end to Babylon/Anarchy
"""
import json
import kubernetes
import os
import random
import redis
import string
import subprocess
import time
import yaml
from base64 import b32encode, b32decode
from kubernetes.client.rest import ApiException
from flask import Flask, render_template, flash, redirect, url_for, request, session
from flask_session import Session
from flask_bootstrap import Bootstrap
from werkzeug.middleware.proxy_fix import ProxyFix

if os.path.exists("/var/run/secrets/kubernetes.io/serviceaccount/namespace"):
    namespace = open("/var/run/secrets/kubernetes.io/serviceaccount/namespace").read()
    kubernetes.config.load_incluster_config()
else:
    kubernetes.config.load_kube_config()
    namespace = kubernetes.config.list_kube_config_contexts()[1]['context']['namespace']

def random_string(length):
    return ''.join([random.choice(string.ascii_letters + string.digits) for n in range(length)])

access_password = os.getenv('ACCESS_PASSWORD', '')
admin_password = os.getenv('ADMIN_PASSWORD', random_string(32))

core_v1_api = kubernetes.client.CoreV1Api()
custom_objects_api = kubernetes.client.CustomObjectsApi()

beui_domain = os.environ.get('BEUI_DOMAIN', 'beui.gpte.redhat.com')
catalog_template_name = os.getenv('CATALOG_TEMPLATE_NAME', '')
catalog_template_namespace = os.getenv('CATALOG_TEMPLATE_NAMESPACE', 'openshift')
catalog_template_parameters = yaml.safe_load(os.getenv('CATALOG_TEMPLATE_PARAMETERS', '{}'))
catalog_template_quota = int(os.getenv('CATALOG_TEMPLATE_QUOTA', 5))
poolboy_domain = os.getenv('POOLBOY_DOMAIN', 'poolboy.gpte.redhat.com')
poolboy_version = os.getenv('POOLBOY_VERSION', 'v1')

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

#def create_resource(resource_definition):
#    if '/' in resource_definition['apiVersion']:
#        group, version = resource_definition['apiVersion'].split('/')
#        namespace = resource_definition['metadata'].get('namespace', namespace)
#        plural, namespaced = get_api(group, version, resource_definition['kind'])
#        if namespaced:
#            return custom_objects_api.create_namespaced_custom_object(
#                group, version, namespace, plural, resource_definition
#            )
#        else:
#            return custom_objects_api.create_cluster_custom_object(
#                group, version, plural, resource_definition
#            )
#    else:
#        kind = resource_definition['kind']
#        namespace = resource_definition['metadata'].get('namespace', namespace)
#        create_namespaced_method = 'create_namespaced_' + inflection.underscore(kind)
#        create_cluster_method = 'create_' + inflection.underscore(kind)
#        if hasattr(core_v1_api, create_namespaced_method):
#            method = getattr(core_v1_api, create_namespaced_method)
#            return method(namespace, resource_definition).to_dict()
#        else:
#            method = getattr(core_v1_api, create_cluster_method)
#            return method(resource_definition).to_dict()

#def get_api(group, version, kind):
#    if group in api_groups \
#    and version in api_groups[group]:
#        for resource in api_groups[group][version]['resources']:
#            if resource['kind'] == kind:
#                return resource['name'], resource['namespaced']
#
#    resp = core_v1_api.api_client.call_api(
#        '/apis/{}/{}'.format(group, version), 'GET',
#        auth_settings=['BearerToken'], response_type='object'
#    )
#    group_info = resp[0]
#    if group not in api_groups:
#        api_groups[group] = {}
#    api_groups[group][version] = group_info
#
#    for resource in group_info['resources']:
#        if resource['kind'] == kind:
#            return resource['name'], resource['namespaced']
#    raise Exception('Unable to find kind {} in {}/{}'.format(kind, group, version))

def get_lab_url(config_map):
    try:
        route = custom_objects_api.get_namespaced_custom_object(
            'route.openshift.io', 'v1', namespace, 'routes', config_map.metadata.name
        )
        if 'tls' in route['spec']:
            return 'https://{0}/'.format(route['spec']['host'])
        else:
            return 'http://{0}/'.format(route['spec']['host'])
    except ApiException as e:
        if e.status != 404:
            raise

def get_all_lab_config_maps():
    return core_v1_api.list_namespaced_config_map(
        namespace, label_selector=beui_domain + '/session-id'
    ).items

def get_unowned_lab_config_maps():
    return core_v1_api.list_namespaced_config_map(
        namespace, label_selector=beui_domain + '/session-id='
    ).items

def get_session_lab_config_map(session_id):
    config_maps = core_v1_api.list_namespaced_config_map(
        namespace, label_selector=beui_domain + '/session-id={0}'.format(encode_session_id(session_id))
    ).items
    if config_maps:
        return config_maps[0]
    else:
        return None

def get_resource_claims():
    return custom_objects_api.list_namespaced_custom_object(
        poolboy_domain, poolboy_version, namespace, 'resourceclaims'
    ).get('items', [])

def get_session_id():
    session_id = session.get('id', None)
    if not session_id:
        session_id = random_string(32)
        session['id'] = session_id
    return session_id

def assign_unowned_lab_config_map(session_id):
    '''
    Assigned an unowned config map to this session.
    '''
    config_maps = get_unowned_lab_config_maps()
    for config_map in config_maps:
        try:
            config_map.metadata.labels[beui_domain + '/session-id'] = encode_session_id(session_id)
            return core_v1_api.replace_namespaced_config_map(config_map.metadata.name, namespace, config_map)
        except ApiException as e:
            # 409 means the resource changed, most likely because another user claimed it first
            if e.status != 409:
                raise
    # No free lab config map available
    return None

def process_catalog_template():
    '''
    Use `oc` to process bookbag template and produce resource list json.
    '''
    oc_process_cmd = [
        'oc', 'process', catalog_template_namespace + '//' + catalog_template_name,
        '-o', 'json'
    ]
    for k, v in catalog_template_parameters.items():
        oc_process_cmd.extend(['-p', '{0}={1}'.format(k, v)])
    oc_process_result = subprocess.run(oc_process_cmd, stdout=subprocess.PIPE, check=True)
    return json.loads(oc_process_result.stdout)

def provision_catalog_item():
    template_output = process_catalog_template()
    oc_create_result = subprocess.run(['oc', 'create', '-f', '-'], input=json.dumps(template_output).encode('utf-8'), check=True)

def reset_session():
    session['access_authenticated'] = False
    session['id'] = None
    session['config_map_assigned'] = False

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
    config_map = get_session_lab_config_map(session_id)

    if not config_map:
        if session.get('config_map_assigned', False):
            # Config map is missing, access reset
            reset_session()
            return redirect(url_for('index'))
        config_map = assign_unowned_lab_config_map(session_id)

    if config_map:
        session['config_map_assigned'] = True
        lab_url = get_lab_url(config_map)
    else:
        lab_url = None

    return render_template('index.html', lab_data=config_map.data, lab_url=lab_url, session_id=session_id)

@app.route('/admin', methods=['GET'])
def admin():
    if not session.get('admin_authenticated'):
        return render_template('admin-login.html')

    lab_environments = [{
        "config_map": config_map,
        "lab_url": get_lab_url(config_map)
    } for config_map in get_all_lab_config_maps() ]

    resource_claims = get_resource_claims()
    return render_template('admin.html',
        lab_environments=lab_environments,
        resource_claims=resource_claims,
        catalog_template_name=catalog_template_name,
        catalog_template_namespace=catalog_template_namespace,
        catalog_template_quota=catalog_template_quota
    )

@app.route('/admin/create', methods=['POST'])
def admin_create():
    if not session.get('admin_authenticated'):
        return render_template('admin-login.html')

    resource_claims = get_resource_claims()

    if len(resource_claims) >= catalog_template_quota:
        flash('Quota restriction, refusing to create environment')
        return redirect(url_for('admin'))

    provision_catalog_item()

    flash('Lab environment created')
    return redirect(url_for('admin'))

@app.route('/admin/delete/<claim_name>', methods=['POST'])
def admin_delete_resource_claim(claim_name):
    if not session.get('admin_authenticated'):
        flash('authentication required')
        return redirect(url_for('admin'))

    try:
        custom_objects_api.delete_namespaced_custom_object(
            poolboy_domain, poolboy_version, namespace, 'resourceclaims', claim_name,
            kubernetes.client.V1DeleteOptions()
        )
    except ApiException as e:
        if e.status != 404:
            raise
    flash('{0} deleted'.format(claim_name))
    return redirect(url_for('admin'))

@app.route('/admin/unbind/<name>', methods=['POST'])
def admin_unbind_config_map(name):
    if not session.get('admin_authenticated'):
        flash('authentication required')
        return redirect(url_for('admin'))

    try:
        config_map = core_v1_api.read_namespaced_config_map(
            name, namespace
        )
        config_map.metadata.labels[beui_domain + '/session-id'] = ''
        core_v1_api.replace_namespaced_config_map(name, namespace, config_map)
    except ApiException as e:
        if e.status == 404:
            flash('{0} not found'.format(name))
        else:
            raise
    flash('{0} unbound'.format(name))
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
