
# Copyright 2013 OpenStack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
/PDP endpoint for Sios v1 API
"""

import copy
import eventlet
from oslo.config import cfg
from webob.exc import (HTTPError,
                       HTTPNotFound,
                       HTTPConflict,
                       HTTPBadRequest,
                       HTTPForbidden,
                       HTTPRequestEntityTooLarge,
                       HTTPInternalServerError,
                       HTTPServiceUnavailable)
from webob import Response
from sios.policy.glance import glance
from sios.policy.nova import nova
import sios.api.v1
from sios.common import exception   
from sios.common import utils
from sios.common import wsgi
from sios.openstack.common import strutils
import sios.openstack.common.log as logging
import json
import httplib

from sios.openstack.common import jsonutils
from sios.openstack.common import timeutils


CONF = cfg.CONF
LOG = logging.getLogger(__name__)

opts = [
    cfg.StrOpt('auth_admin_prefix', default=''),
    cfg.StrOpt('keystone_auth_host', default='127.0.0.1'),
    cfg.IntOpt('keystone_auth_port', default=35357),
    cfg.StrOpt('sios_auth_host', default='127.0.0.1'),
    cfg.IntOpt('sios_auth_port', default=5253),
    cfg.StrOpt('auth_protocol', default='http'),
    cfg.StrOpt('auth_version', default=None),
    cfg.BoolOpt('delay_auth_decision', default=False),
    cfg.BoolOpt('http_connect_timeout', default=None),
    cfg.StrOpt('http_handler', default=None),
    cfg.StrOpt('admin_token', secret=True),
    cfg.StrOpt('admin_user'),
    cfg.StrOpt('admin_password', secret=True),
    cfg.StrOpt('admin_tenant_name', default='admin'),
    cfg.StrOpt('certfile'),
    cfg.StrOpt('keyfile'),
    cfg.IntOpt('token_cache_time', default=300),
    cfg.StrOpt('memcache_security_strategy', default=None),
    cfg.StrOpt('memcache_secret_key', default=None, secret=True)
]
CONF = cfg.CONF
CONF.register_opts(opts, group='authtoken')

_POLICY_PATH = None
_POLICY_CACHE = {}

sios_auth_host = CONF.authtoken['sios_auth_host']
sios_auth_port = CONF.authtoken['sios_auth_port']

def reset():
    global _POLICY_PATH
    global _POLICY_CACHE
    _POLICY_PATH = None
    _POLICY_CACHE = {}
    policy.reset()


class RESTConnect(object):
    def __init__(self):
            # where to find the auth service (we use this to validate tokens)
            self.keystone_auth_host = self._conf_get('keystone_auth_host')
            self.keystone_auth_port = int(self._conf_get('keystone_auth_port'))
            self.sios_auth_host = self._conf_get('sios_auth_host')
            self.sios_auth_port = int(self._conf_get('sios_auth_port'))
            self.auth_protocol = self._conf_get('auth_protocol')
            if not self._conf_get('http_handler'):
                if self.auth_protocol == 'http':
                    self.http_client_class = httplib.HTTPConnection
                else:
                    self.http_client_class = httplib.HTTPSConnection
            else:
                # Really only used for unit testing, since we need to
                # have a fake handler set up before we issue an http
                # request to get the list of versions supported by the
                # server at the end of this initialization
                self.http_client_class = self._conf_get('http_handler')
    
            self.auth_admin_prefix = self._conf_get('auth_admin_prefix')
    
            # SSL
            self.cert_file = self._conf_get('certfile')
            self.key_file = self._conf_get('keyfile')
    
            # Credentials used to verify this component with the Auth service since
            # validating tokens is a privileged call
            self.admin_token = self._conf_get('admin_token')
            self.admin_token_expiry = None
            self.admin_user = self._conf_get('admin_user')
            self.admin_password = self._conf_get('admin_password')
            self.admin_tenant_name = self._conf_get('admin_tenant_name')
    
            http_connect_timeout_cfg = self._conf_get('http_connect_timeout')
            self.http_connect_timeout = (http_connect_timeout_cfg and
                                         int(http_connect_timeout_cfg))
            self.auth_version = None
    
    
            self.admin_token=None
            self.admin_user='admin'
            self.admin_password='admin'
            self.admin_tenant_name='admin'
            self.admin_token_expiry = None
            self.key_file = None
            self.cert_file = None
    
            if self.auth_protocol == 'http':
                self.http_client_class = httplib.HTTPConnection
            else:
                self.http_client_class = httplib.HTTPSConnection
    
    def _conf_get(self, name):
            return CONF.authtoken[name]
    
    def _request_admin_token(self):
            """Retrieve new token as admin user from keystone.
    
            :return token id upon success
            :raises ServerError when unable to communicate with keystone
    
            Irrespective of the auth version we are going to use for the
            user token, for simplicity we always use a v2 admin token to
            validate the user token.
    
            """
            params = {
            'auth': {
                'passwordCredentials': {
                    'username': self.admin_user,
                    'password': self.admin_password,
                    },
                'tenantName': self.admin_tenant_name,
                }
            }
    
            response, data = self._json_request(self.keystone_auth_host,
                            self.keystone_auth_port,
                            'POST',
                                                '/v2.0/tokens',
                                                body=params)
            try:
                token = data['access']['token']['id']
                expiry = data['access']['token']['expires']
                assert token
                assert expiry
                datetime_expiry = timeutils.parse_isotime(expiry)
                return (token, timeutils.normalize_time(datetime_expiry))
            except (AssertionError, KeyError):
                LOG.warn(
                #self.LOG.warn(
                    "Unexpected response from keystone service: %s", data)
                raise ServiceError('invalid json response')
            except (ValueError):
                LOG.warn(
                #self.LOG.warn(
                    "Unable to parse expiration time from token: %s", data)
                raise ServiceError('invalid json response')
    
    def get_admin_token(self):
            """Return admin token, possibly fetching a new one.
    
            if self.admin_token_expiry is set from fetching an admin token, check
            it for expiration, and request a new token is the existing token
            is about to expire.
    
            :return admin token id
            :raise ServiceError when unable to retrieve token from keystone
    
            """
            if self.admin_token_expiry:
                if will_expire_soon(self.admin_token_expiry):
                    self.admin_token = None
    
            if not self.admin_token:
                (self.admin_token,
                 self.admin_token_expiry) = self._request_admin_token()
    
            return self.admin_token
    
    def _get_http_connection(self, auth_host, auth_port):
            if self.auth_protocol == 'http':
                return self.http_client_class(auth_host, auth_port,
                                              timeout=self.http_connect_timeout)
            else:
                return self.http_client_class(auth_host,
                                              auth_port,
                                              self.key_file,
                                              self.cert_file,
                                              timeout=self.http_connect_timeout)
    
    
    def _http_request(self, auth_host, auth_port, method, path, **kwargs):
            """HTTP request helper used to make unspecified content type requests.
    
            :param method: http method
            :param path: relative request url
            :return (http response object, response body)
            :raise ServerError when unable to communicate with keystone
    
            """
            conn = self._get_http_connection(auth_host, auth_port)
            RETRIES = 3
            retry = 0
    
            while True:
                try:
                    conn.request(method, path, **kwargs)
                    response = conn.getresponse()
                    body = response.read()
                    break
                except Exception as e:
                    if retry == RETRIES:
                        LOG.error('HTTP connection exception: %s' % e)
                        #self.LOG.error('HTTP connection exception: %s' % e)
                        raise ServiceError('Unable to communicate with keystone')
                    # NOTE(vish): sleep 0.5, 1, 2
                    #self.LOG.warn('Retrying on HTTP connection exception: %s' % e)
                    LOG.warn('Retrying on HTTP connection exception: %s' % e)
                    time.sleep(2.0 ** retry / 2)
                    retry += 1
                finally:
                    conn.close()
    
            return response, body
    
    def _json_request(self, auth_host, auth_port, method, path, body=None, additional_headers=None):
            """HTTP request helper used to make json requests.
    
            :param method: http method
            :param path: relative request url
            :param body: dict to encode to json as request body. Optional.
            :param additional_headers: dict of additional headers to send with
                                       http request. Optional.
            :return (http response object, response body parsed as json)
            :raise ServerError when unable to communicate with keystone
    
            """
            kwargs = {
                'headers': {
                    'Content-type': 'application/json',
                    'Accept': 'application/json',
                },
            }
    
            if additional_headers:
                kwargs['headers'].update(additional_headers)
    
            if body:
                kwargs['body'] = jsonutils.dumps(body)
    
            path = self.auth_admin_prefix + path
    
            response, body = self._http_request(auth_host, auth_port, method, path, **kwargs)
            try:
                data = jsonutils.loads(body)
            except ValueError:
                LOG.debug('Keystone did not return json-encoded body')
                #self.LOG.debug('Keystone did not return json-encoded body')
                data = {}
    
            return response, data


class Controller(object):
    """
    WSGI controller for Policy Decision Point in Sios v1 API

    The PDP resource API is a RESTful web service for Policy Decisions. The API
    is as follows::

        POST /check -- check the Policy Decision
        POST /enforce -- check the Policy Decision to be enforced
    """

    def __init__(self):
        self.policy_glance = glance.Enforcer()
        self.policy_nova = nova
        self.pool = eventlet.GreenPool(size=1024)
        self.policy_pbac = PBAC_PDP()
   
    """
    PDP for glance OpenStack Service
    """
    def enforce_glance(self, req):
        """Authorize an action against our policies"""
        try:
	    LOG.debug(_('Evaluating Policy decision for action [%s]') % req.context.action)
            pdp_decision = self.policy_glance.enforce(req.context, req.context.action, req.context.target)
	    LOG.debug(_('The Policy decision for action [%s] is [%s]') % (req.context.action, pdp_decision))
   	    return pdp_decision
        except:
	    LOG.debug(_('Exception Raised for action [%s]') % req.context.action)
	    LOG.debug(_('The Policy decision for action [%s] is [False]') % req.context.action)
            return False

    def check_glance(self, req):
        """Authorize an action against our policies"""
        try:
	    LOG.debug(_('Evaluating Policy decision for action [%s]') % req.context.action)
            pdp_decision = self.policy_glance.check(req.context, req.context.action, req.context.target)
	    LOG.debug(_('The Policy decision for action [%s] is [%s]') % (req.context.action, pdp_decision))
   	    return pdp_decision
        except exception:
	    LOG.debug(_('Exception Raised for action [%s]') % req.context.action)
	    LOG.debug(_('The Policy decision for action [%s] is [False]') % req.context.action)
            return False

    """
    PDP for nova OpenStack Service
    """
    def enforce_nova(self, req):
        """Authorize an action against our policies"""
        try:
	    LOG.debug(_('Evaluating Policy decision for action CONTEXT [%s]') % req.context)
	    LOG.debug(_('Evaluating Policy decision for action [%s]') % req.context.action)
            pdp_decision =  self.policy_nova.enforce(req.context, req.context.action, req.context.target)
            self.policy_pbac.test_request(req)
	    LOG.debug(_('The Policy decision for action [%s] is [%s]') % (req.context.action, pdp_decision))
	    return pdp_decision
        except:
	    LOG.debug(_('Exception Raised for action [%s]') % req.context.action)
	    LOG.debug(_('The Policy decision for action [%s] is [False]') % req.context.action)
            return False

    """
    Checking request against PBAC policy
    """
    def check_pbac(self, req):
        """Evaluate an action against our policies"""
        try:
	    LOG.debug(_('Evaluating Policy decision for action [%s]') % req.context.action)
#            pdp_decision =  self.policy_nova.enforce(req.context, req.context.action, req.context.target)
            pdp_results = self.policy_pbac.evaluate_request(req)
	    LOG.debug(_('The Policy decision for action [%s] is [%s]') % (req.context.action, pdp_decision))
	    return pdp_results
        except:
	    LOG.debug(_('Exception Raised for action [%s]') % req.context.action)
	    LOG.debug(_('The Policy decision for action [%s] is [False]') % req.context.action)
            return False

	
class PBAC_PIP():

    def __init__(self):
        self.provService_auth_host = '127.0.0.1'
        self.provService_auth_port = 6060
        self.connect = RESTConnect()

    def generate_prov_query(self, context, startingNode, dependencyPath):
        if (context.auth_tok == None):
            return False
        LOG.debug(_('Exception Raised for action in GENERATE_PROV_QUERY [%s]') % context.auth_tok)
        headers = {'X-Auth-Token': context.auth_tok, 'X-Action': context.action, 'X-Target': context.target, 'X-startingNode': startingNode, 'X-dependencyPath': dependencyPath}
        qbody = {'Prov-startingNode': startingNode, 'Prov-dependencyPath': dependencyPath}
        #response, data = self.connect._json_request(self.provService_auth_host, self.provService_auth_port, 'POST',
        #                                    '/v1/rdf/enforce_provquery', additional_headers=headers, body=qbody)
        LOG.debug(_('2nd Exception Raised for action in GENERATE_PROV_QUERY [%s]') % context.target)
        try:
            response, data = self.connect._json_request(self.provService_auth_host, 6060, 'POST',
                                                '/v1/rdf/enforce_provquery', additional_headers=headers, body=qbody)
        except Exception as e:
            LOG.debug(_('Exception Raised for JSONREQ [%s]') %e)
        data = ""
        #LOG.debug(_('Evaluating Policy decision for action [%s]') % self.provService_auth_port)
        return data
	
class PBAC_PDP():

    def __init__(self):
        self.dependencyList = {}
#        self.policySet = self._load_policy()

        """ get connected to ProvService """
#        self.pbac_pap = PBAC_PAP()
        self.pbac_pip = PBAC_PIP()

    def _load_policy(self):
        print "************PBAC***********"
        print "performing policy load"
        LOG.debug(_('Evaluating Policy decision for action [%s]') % self.dependencyList)
        fileName = "/opt/stack/sios/sios/api/v1/pbac_policy.json"
        return readJSONfile(fileName)

    def test_request(self,req):
        LOG.debug(_('TEST_REQUEST DEBUG[%s]') % self.dependencyList)
        startingNode = ""
        dependencyPath = ""
        #self.pbac_pip().generate_prov_query(req.context, startingNode, dependencyPath)
        #self._generate_prov_query(req.context, startingNode, dependencyPath)
        self.pbac_pip.generate_prov_query(req.context, startingNode, dependencyPath)
        return None

	""" evaluate a request """
    def evaluate_request(self, req):
        """ match req to according rules"""
        self.matched_rules = self.policySet['req.context.action'][Rules]

        """ assure that rules match """
        if self.matched_rules == []:
            return False


        for rule_index in range(len(matched_rules)):
            self.conditions = jsondata['Action']['Rules'][rule_index]['Conditions']

        for cond_index in range(len(self.conditions)):
            startingNode = self.conditions[cond_index]["exp"][0]["provquery"][0]
            dependencyPath = self.conditions[cond_index]["exp"][0]["provquery"][1]
        
        self._generate_prov_query(self, startingNode, dependencyPath)
    
        return False
    		
    def _generate_prov_query(self, context, startingNode="",dependencyPath=""):
        LOG.debug(_('Evaluating starting Node for action [%s]') % startingNode)

        LOG.debug(_('Evaluating auth token for action [%s]') % context.target)

        #self.pbac_pip.generate_prov_query(context, startingNode, dependencyPath)

    def _match_action_rules(self, action):
        return None

class Deserializer(wsgi.JSONRequestDeserializer):
    """Handles deserialization of specific controller method requests."""

    def _deserialize(self, request):
        result = {}
        return result

    def create(self, request):
        return self._deserialize(request)

    def update(self, request):
        return self._deserialize(request)


class Serializer(wsgi.JSONResponseSerializer):
    """Handles serialization of specific controller method responses."""

    def __init__(self):
        self.notifier = None

    def meta(self, response, result):
       return response

    def show(self, response, result):
        return response

    def update(self, response, result):
       return response

    def create(self, response, result):
       return response


def create_resource():
    """Resource factory method"""
    deserializer = Deserializer()
    serializer = Serializer()
    return wsgi.Resource(Controller(), deserializer, serializer)

def readJSONfile(file_name):
    data = readfile(file_name)
    json_data = json.loads(data)
    return json_data
	
def readfile(file_name):
    with open (file_name, "r") as myfile:
        data=myfile.read()
        return data
