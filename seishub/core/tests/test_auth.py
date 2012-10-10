#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Test suite for seishub.core.auth.

:copyright:
    Lion Krischer (krischer@geophysik.uni-muenchen.de), 2012
:license:
    GNU Lesser General Public License, Version 3
    (http://www.gnu.org/copyleft/lesser.html)
"""
from seishub.core.auth import Authorization
from seishub.core.exceptions import SeisHubError

import unittest


class AuthorizationTestCase(unittest.TestCase):
    """
    Some tests to check that the Authorization object works as intended.
    """
    def setUp(self):
        pass

    def test_default_constructor(self):
        """
        The empty constructor only gives rights to admins. This is only a dummy
        authorization object as admins have all rights anyways.
        """
        auth = Authorization()
        self.assertEqual(auth.owner, "admin")
        self.assertEqual(auth.group, "admin")
        self.assertEqual(auth.public, False)
        self.assertEqual(auth.permissions, "660")

    def test_constructor(self):
        """
        Test some more advanced constructors.
        """
        auth = Authorization(owner="test", public=True)
        self.assertEqual(auth.owner, "test")
        self.assertEqual(auth.group, "admin")
        self.assertEqual(auth.public, True)
        self.assertEqual(auth.permissions, "660")
        auth = Authorization(owner="test", group="blub", public=True,
            permissions="000")
        self.assertEqual(auth.owner, "test")
        self.assertEqual(auth.group, "blub")
        self.assertEqual(auth.public, True)
        self.assertEqual(auth.permissions, "000")

    def test_permission_property(self):
        """
        Test the permissions property.
        """
        auth = Authorization()
        # Internal checks!
        self.assertEqual(auth._owner_rights, 6)
        self.assertEqual(auth._group_rights, 6)
        self.assertEqual(auth._other_rights, 0)
        self.assertEqual(auth.permissions, "660")
        auth.permissions = "212"
        self.assertEqual(auth._owner_rights, 2)
        self.assertEqual(auth._group_rights, 1)
        self.assertEqual(auth._other_rights, 2)
        self.assertEqual(auth.permissions, "212")
        auth.permissions = "070"
        self.assertEqual(auth._owner_rights, 0)
        self.assertEqual(auth._group_rights, 7)
        self.assertEqual(auth._other_rights, 0)
        self.assertEqual(auth.permissions, "070")
        # Only for testing! Should never be done!
        auth._owner_rights = 1
        auth._group_rights = 1
        auth._other_rights = 5
        self.assertEqual(auth.permissions, "115")

    def test_permission_exceptions(self):
        """
        Only valid permissions should be allowed to be set.
        """
        self.assertRaises(SeisHubError, Authorization, permissions=123)
        auth = Authorization()
        self.assertRaises(SeisHubError, auth.__setattr__, "permissions", 123)
        self.assertRaises(SeisHubError, auth.__setattr__, "permissions", "-12")
        self.assertRaises(SeisHubError, auth.__setattr__, "permissions", "10")
        self.assertRaises(SeisHubError, auth.__setattr__, "permissions",
            "1200")
        self.assertRaises(SeisHubError, auth.__setattr__, "permissions",
            "-100")

    def test_authentication(self):
        """
        Test the is_authorized() method.
        """
        auth = Authorization(owner="test", group="test", permissions="640",
            public=False)
        self.assertFalse(auth.is_authorized(action="write"))
        self.assertFalse(auth.is_authorized(action="read"))
        self.assertFalse(auth.is_authorized(action="write", user="blub"))
        self.assertFalse(auth.is_authorized(action="read", user_groups="blub"))
        self.assertFalse(auth.is_authorized(action="write", user="blub",
            user_groups="blub"))
        # If either the group or owner is correct, the chosen permission should
        # be granted. In this case, the owner can do everything, the group can
        # read and the rest has no permissions.
        self.assertTrue(auth.is_authorized(action="r", user="test"))
        self.assertTrue(auth.is_authorized(action="w", user="test"))
        self.assertTrue(auth.is_authorized(action="r", user_groups="test"))
        self.assertTrue(auth.is_authorized(action="r", user_groups=["test"]))
        self.assertTrue(auth.is_authorized(action="r", user_groups=["test",
            "yay"]))
        self.assertFalse(auth.is_authorized(action="w", user_groups="test"))
        # Correct owner or group is enough, if given.
        self.assertTrue(auth.is_authorized(action="w", user="test",
            user_groups="blub"))
        self.assertTrue(auth.is_authorized(action="w", user="test",
            user_groups="test"))
        self.assertFalse(auth.is_authorized(action="w", user="blub",
            user_groups="test"))
        # Giving access to other, means that all logged in users have read
        # and/or write rights. Anonymous access is still not allowed.
        auth.permissions = "644"
        self.assertFalse(auth.is_authorized(action="r"))
        self.assertFalse(auth.is_authorized(action="r", user_groups=None))
        self.assertTrue(auth.is_authorized(action="r", user="blub"))
        self.assertTrue(auth.is_authorized(action="r", user_groups="blub"))
        self.assertFalse(auth.is_authorized(action="w", user="blub"))
        # Setting the public attribute to True should enable anonymous read
        # access. But no write access.
        auth.public = True
        self.assertTrue(auth.is_authorized(action="read"))
        self.assertFalse(auth.is_authorized(action="write"))
        self.assertTrue(auth.is_authorized(action="read", user="blub",
            user_groups="blub"))
        self.assertFalse(auth.is_authorized(action="write", user="blub",
            user_groups="blub"))


def suite():
    return unittest.makeSuite(AuthorizationTestCase, 'test')


if __name__ == '__main__':
    unittest.main()
