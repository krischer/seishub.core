# -*- coding: utf-8 -*-

from StringIO import StringIO
from seishub.core import Component, implements
from seishub.exceptions import SeisHubError
from seishub.packages.builtins import IResourceType, IPackage
from seishub.processor import MAX_URI_LENGTH, ALLOWED_HTTP_METHODS, \
    NOT_IMPLEMENTED_HTTP_METHODS, PUT, POST, DELETE, GET, MOVE, Processor
from seishub.test import SeisHubEnvironmentTestCase
from twisted.web import http
import unittest


XML_DOC = """<?xml version="1.0" encoding="utf-8"?>

<testml>
  <blah1 id="3">
    <blahblah1>üöäß</blahblah1>
  </blah1>
</testml>"""

XML_DOC2 = """<?xml version="1.0" encoding="utf-8"?>

<testml>
  <blah1 id="3">
    <blahblah1>üöäß</blahblah1>
  </blah1>
  <hallowelt />
</testml>"""

XML_VC_DOC = """<?xml version="1.0" encoding="utf-8"?>

<testml>%d</testml>"""


class AResourceType(Component):
    """A non versioned test resource type."""
    implements(IResourceType, IPackage)
    
    package_id = 'processor-test'
    resourcetype_id = 'notvc'
    version_control = False


class AVersionControlledResourceType(Component):
    """A version controlled test resource type."""
    implements(IResourceType, IPackage)
    
    package_id = 'processor-test'
    resourcetype_id = 'vc'
    version_control = True


class ProcessorTest(SeisHubEnvironmentTestCase):
    """Processor test case."""
    def setUp(self):
        self.env.enableComponent(AVersionControlledResourceType)
        self.env.enableComponent(AResourceType)
    
    def tearDown(self):
        self.env.disableComponent(AVersionControlledResourceType)
        self.env.disableComponent(AResourceType)
    
    def test_orderOfAddingResourcesMatters(self):
        """This test in this specific order failed in a previous revision.""" 
        proc = Processor(self.env)
        proc.run(PUT, '/xml/processor-test/vc/test.xml', StringIO(XML_DOC))
        proc.run(POST, '/xml/processor-test/vc/test.xml', StringIO(XML_DOC))
        proc.run(POST, '/xml/processor-test/vc/test.xml', StringIO(XML_DOC))
        proc.run(PUT, '/xml/processor-test/notvc/test.xml', StringIO(XML_DOC))
        proc.run(DELETE, '/xml/processor-test/vc/test.xml')
        proc.run(DELETE, '/xml/processor-test/notvc/test.xml')
    
    def test_oversizedURI(self):
        """Request URI ist restricted by MAX_URI_LENGTH."""
        proc = Processor(self.env)
        for method in ALLOWED_HTTP_METHODS:
            try:
                proc.run(method, 'a' * MAX_URI_LENGTH, '')
                self.fail("Expected SeisHubError")
            except SeisHubError, e:
                self.assertEqual(e.code, http.REQUEST_URI_TOO_LONG)
    
    def test_notImplementedMethods(self):
        proc = Processor(self.env)
        for method in NOT_IMPLEMENTED_HTTP_METHODS:
            try:
                proc.run(method, '/')
                self.fail("Expected SeisHubError")
            except SeisHubError, e:
                self.assertEqual(e.code, http.NOT_IMPLEMENTED)
    
    def test_invalidMethods(self):
        proc = Processor(self.env)
        for method in ['MUH', 'XXX', 'GETPUT']:
            try:
                proc.run(method, '/')
                self.fail("Expected SeisHubError")
            except SeisHubError, e:
                self.assertEqual(e.code, http.NOT_ALLOWED)
    
    def test_forbiddenMethodsOnRoot(self):
        proc = Processor(self.env)
        for method in [POST, PUT, DELETE, MOVE]:
            # without slash
            try:
                proc.run(method, '')
                self.fail("Expected SeisHubError")
            except SeisHubError, e:
                self.assertEqual(e.code, http.FORBIDDEN)
            # with slash
            try:
                proc.run(method, '/')
                self.fail("Expected SeisHubError")
            except SeisHubError, e:
                self.assertEqual(e.code, http.FORBIDDEN)
    
    def test_forbiddenMethodsOnPackage(self):
        proc = Processor(self.env)
        for method in [POST, PUT, DELETE, MOVE]:
            # without trailing slash
            try:
                proc.run(method, '/xml/processor-test')
                self.fail("Expected SeisHubError")
            except SeisHubError, e:
                self.assertEqual(e.code, http.FORBIDDEN)
            # with trailing slash
            try:
                proc.run(method, '/xml/processor-test/')
                self.fail("Expected SeisHubError")
            except SeisHubError, e:
                self.assertEqual(e.code, http.FORBIDDEN)
    
    def test_forbiddenMethodsOnResourceTypes(self):
        proc = Processor(self.env)
        for method in [POST, PUT, DELETE, MOVE]:
            # without trailing slash
            try:
                proc.run(method, '/xml/processor-test')
                self.fail("Expected SeisHubError")
            except SeisHubError, e:
                self.assertEqual(e.code, http.FORBIDDEN)
            # with trailing slash
            try:
                proc.run(method, '/xml/processor-test/')
                self.fail("Expected SeisHubError")
            except SeisHubError, e:
                self.assertEqual(e.code, http.FORBIDDEN)
    
    def test_forbiddenMethodsOnResourceType(self):
        proc = Processor(self.env)
        for method in [POST, DELETE, MOVE]:
            # without trailing slash
            try:
                proc.run(method, '/xml/processor-test/vc')
                self.fail("Expected SeisHubError")
            except SeisHubError, e:
                self.assertEqual(e.code, http.FORBIDDEN)
            # with trailing slash
            try:
                proc.run(method, '/xml/processor-test/vc/')
                self.fail("Expected SeisHubError")
            except SeisHubError, e:
                self.assertEqual(e.code, http.FORBIDDEN)
    
    def test_processResourceType(self):
        proc = Processor(self.env)
        proc.path = '/xml/processor-test/notvc'
        # test valid GET method
        data = proc.run(GET, '/xml/processor-test/notvc')
        # data must be a dict
        self.assertTrue(isinstance(data, dict))
        # test valid PUT method
        data = proc.run(PUT, '/xml/processor-test/notvc', StringIO(XML_DOC))
        # check response; data should be empty; we look into request
        self.assertFalse(data)
        self.assertEqual(proc.response_code, http.CREATED)
        self.assertTrue(isinstance(proc.response_header, dict))
        response_header = proc.response_header
        self.assertTrue(response_header.has_key('Location'))
        location = response_header.get('Location')
        self.assertTrue(location.startswith(self.env.getRestUrl() + proc.path))
        # strip REST url from location
        location = location[len(self.env.getRestUrl()):]
        # fetch resource and compare it with original
        data = proc.run(GET, location)
        self.assertTrue(data, XML_DOC)
        # delete uploaded resource
        data = proc.run(DELETE, location)
        # check response; data should be empty; we look into request
        self.assertFalse(data)
        self.assertEqual(proc.response_code, http.NO_CONTENT)
    
    def test_processResource(self):
        proc = Processor(self.env)
        # upload a resource via PUT
        data = proc.run(PUT, '/xml/processor-test/notvc', StringIO(XML_DOC))
        # check response; data should be empty; we look into request
        self.assertFalse(data)
        self.assertEqual(proc.response_code, http.CREATED)
        self.assertTrue(isinstance(proc.response_header, dict))
        response_header = proc.response_header
        self.assertTrue(response_header.has_key('Location'))
        location = response_header.get('Location')
        self.assertTrue(location.startswith(self.env.getRestUrl() + proc.path))
        # GET resource
        location = location[len(self.env.getRestUrl()):]
        data = proc.run(GET, location)
        self.assertEquals(data, XML_DOC)
        # overwrite this resource via POST request
        proc.run(POST, location, StringIO(XML_DOC2))
        # GET resource
        data = proc.run(GET, location)
        self.assertNotEquals(data, XML_DOC)
        self.assertEquals(data, XML_DOC2)
        # DELETE resource
        proc.run(DELETE, location)
        # GET deleted revision
        try:
            proc.run(GET, location)
            self.fail("Expected SeisHubError")
        except SeisHubError, e:
            self.assertEqual(e.code, http.NOT_FOUND)
    
    def test_processVCResource(self):
        """Test for a version controlled resource."""
        proc = Processor(self.env)
        # upload a resource via PUT
        data = proc.run(PUT, '/xml/processor-test/vc', StringIO(XML_DOC))
        # check response; data should be empty; we look into request
        self.assertFalse(data)
        self.assertEqual(proc.response_code, http.CREATED)
        self.assertTrue(isinstance(proc.response_header, dict))
        response_header = proc.response_header
        self.assertTrue(response_header.has_key('Location'))
        location = response_header.get('Location')
        self.assertTrue(location.startswith(self.env.getRestUrl() + proc.path))
        # overwrite this resource via POST request
        location = location[len(self.env.getRestUrl()):]
        data = proc.run(POST, location, StringIO(XML_DOC2))
        # check response; data should be empty; we look into request
        self.assertFalse(data)
        self.assertEqual(proc.response_code, http.NO_CONTENT)
        self.assertTrue(isinstance(proc.response_header, dict))
        response_header = proc.response_header
        self.assertTrue(response_header.has_key('Location'))
        location = response_header.get('Location')
        self.assertTrue(location.startswith(self.env.getRestUrl() + proc.path))
        # GET latest revision
        location = location[len(self.env.getRestUrl()):]
        data = proc.run(GET, location)
        self.assertEquals(data, XML_DOC2)
        # GET revision #1
        data = proc.run(GET, location + '/1')
        self.assertEquals(data, XML_DOC)
        # GET revision #2
        data = proc.run(GET, location + '/2')
        self.assertEquals(data, XML_DOC2)
        # GET not existing revision #3
        try:
            data = proc.run(GET, location + '/3')
            self.fail("Expected SeisHubError")
        except SeisHubError, e:
            self.assertEqual(e.code, http.NOT_FOUND)
        # DELETE resource
        proc.run(DELETE, location)
        # try to GET deleted revision
        try:
            proc.run(GET, location)
            self.fail("Expected SeisHubError")
        except SeisHubError, e:
            self.assertEqual(e.code, http.NOT_FOUND)


def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(ProcessorTest, 'test'))
    return suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')