
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

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


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
	    LOG.debug(_('Evaluating Policy decision for action [%s]') % req.context.action)
            pdp_decision =  self.policy_nova.enforce(req.context, req.context.action, req.context.target)
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
            pdp_decision = self.policy_pbac.evaluate_request(req)
	    LOG.debug(_('The Policy decision for action [%s] is [%s]') % (req.context.action, pdp_decision))
	    return pdp_decision
        except:
	    LOG.debug(_('Exception Raised for action [%s]') % req.context.action)
	    LOG.debug(_('The Policy decision for action [%s] is [False]') % req.context.action)
            return False


#class PBAC_PAP():
	
#	def __init__(self):

	
class PBAC_PIP():

    def __init__(self):
        self.provService_auth_host = '127.0.0.1'
        self.provService_auth_port = 6060

    def generate_prov_query(self, req, startingNode, dependencyPath):
        if (context.auth_tok == None):
            return False

        headers = {'X-Auth-Token': context.auth_tok, 'X-Action': action, 'X-Target': target}
        qbody = {'Prov-startingNode': startingNode, 'Prov-dependencyPath': dependencyPath}
        response, data = self._json_request(self.provService_auth_host, self.provService_auth_port, 'POST',
                                            '/v1/provenance/prov_query', additional_headers=headers, body=qbody)
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
    		
    def _generate_prov_query(self, startingNode, dependencyPath):
        return self.pbac_pip.generate_prov_query(self, startingNode, dependencyPath)
        #return None

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
