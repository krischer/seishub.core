# -*- coding: utf-8 -*-
import unittest

from seishub.test import SeisHubEnvironmentTestCase
from seishub.core import Component, implements
from seishub.packages.builtins import IResourceType, IPackage


XML_DOC = """<?xml version="1.0" encoding="UTF-8"?>

<testml>
  <blah1 id="3">
    <blahblah1>üöäß</blahblah1>
  </blah1>
</testml>"""


class AResourceType(Component):
    """A non versioned test resource type."""
    implements(IResourceType, IPackage)
    
    package_id = 'put-test'
    resourcetype_id = 'notvc'
    version_control = False


class AVersionControlledResourceType(Component):
    """A version controlled test resource type."""
    implements(IResourceType, IPackage)
    
    package_id = 'put-test'
    resourcetype_id = 'vc'
    version_control = True


class ProcessorPUTTest(SeisHubEnvironmentTestCase):
    """Processor test case."""
    def setUp(self):
        self.env.enableComponent(AVersionControlledResourceType)
        self.env.enableComponent(AResourceType)
        
    def tearDown(self):
        self.env.disableComponent(AVersionControlledResourceType)
        self.env.disableComponent(AResourceType)
    
    def test_processRoot(self):
        pass


def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(ProcessorPUTTest, 'test'))
    return suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')