# -*- coding: utf-8 -*-

from seishub.core.config import IntOption, Option
from seishub.core.defaults import MIN_PASSWORD_LENGTH
from seishub.core.exceptions import DuplicateObjectError, SeisHubError, \
    InvalidParameterError
from seishub.core.util.text import hash
from sqlalchemy import Column, String, create_engine, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from twisted.cred import checkers, credentials, error
from twisted.internet import defer
from zope.interface import implements
import os


class PasswordDictChecker:
    """
    A simple Twisted password checker using a dictionary as input.
    """
    implements(checkers.ICredentialsChecker)
    credentialInterfaces = (credentials.IUsernamePassword,)

    def __init__(self, env):
        self.env = env

    def requestAvatarId(self, credentials):
        """
        @param credentials: something which implements one of the interfaces in
        self.credentialInterfaces.

        @return: a Deferred which will fire a string which identifies an
        avatar, an empty tuple to specify an authenticated anonymous user
        (provided as checkers.ANONYMOUS) or fire a Failure(UnauthorizedLogin).
        Alternatively, return the result itself.
        """
        username = credentials.username
        if username in self.env.auth.passwords:
            if hash(credentials.password) == self.env.auth.passwords[username]:
                return defer.succeed(username)
        err = error.UnauthorizedLogin("No such user or bad password")
        return defer.fail(err)


Base = declarative_base()


class User(Base):
    """
    A user object.

    Every user has the following attributes:
        id:            Unique id number. Can never be changed.
        user_name:     The user's name used inside SeisHub. Can be changed.
        password_hash: Password hash.
        real_name:     The user's true name.
        groups:        A list of all groups the user is a member of.
        institution:   The user's institution.
        email:         The user's email.
    """
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    user_name = Column(String)
    password_hash = Column(String)
    real_name = Column(String)
    groups = Column(String)
    institution = Column(String)
    email = Column(String)

    def __init__(self, user_name, password_hash, real_name, groups,
        institution='', email=''):
        self.user_name = user_name
        self.password_hash = password_hash
        self.real_name = real_name
        self.groups = ", ".join(groups)
        self.institution = institution
        self.email = email

    def __repr__(self):
        return "<User %s(%s), member of groups: %s>" % (self.user_name,
            self.real_name, self.groups)


class Group(Base):
    """
    A group object.

    Every group has the following attributes:
        id:          Unique id number. Can never be changed.
        group_name:  The group name.
        group_owner: The group owner. Only the owner can add new members.
        description: Extended description.
    """
    __tablename__ = 'groups'

    id = Column(Integer, primary_key=True)
    group_name = Column(String)
    group_owner = Column(String)
    description = Column(String)

    def __init__(self, group_name, group_owner, description=""):
        self.group_name = group_name
        self.group_owner = group_owner
        self.description = description

    def __repr__(self):
        return "<Group %s (owner: %s): %s)>" % (self.group_name,
            self.group_owner, self.description)


class AuthenticationManager(object):
    """
    The Authentication Manager.
    """
    IntOption('seishub', 'min_password_length', MIN_PASSWORD_LENGTH,
        "Minimum password length.")
    Option('seishub', 'auth_uri', '', "Authentication database string.")

    passwords = {}
    users = []

    def __init__(self, env):
        self.env = env
        # fetch db uri - this is an option primary for the test cases
        uri = self.env.config.get('seishub', 'auth_uri') or \
            'sqlite:///' + os.path.join(self.env.getInstancePath(), 'db',
                                        'auth.db')
        engine = create_engine(uri, encoding='utf-8', convert_unicode=True)
        # Define and create user table
        Base.metadata.create_all(engine, checkfirst=True)
        self.Session = sessionmaker(bind=engine)
        self.refresh()
        # Groups 'admin' and 'users' should always exist.
        if not "admin" in self.groups:
            self.addGroup(group_name="admin", group_owner="admin",
                description="Users in this group have admin rights.")
        if not "users" in self.groups:
            self.addGroup(group_name="users", group_owner="admin",
                description="Default group for all users.")
        # add admin if no account exists and check for the default password
        if "admin" not in self.users.keys():
            self.env.log.warn("An administrative account with both username "
                              "and passwort 'admin' has been automatically "
                              "created. You should change the password as "
                              "soon as possible.")
            self.addUser(user_name='admin', password="admin",
                         groups=["admin", "users"], real_name='Administrator',
                         checkPassword=False)
        elif self.checkPassword('admin', 'admin'):
            self.env.log.warn("The administrative account is accessible via "
                              "the standard password! Please change this as "
                              "soon as possible!")
        self.refresh()

    def _validatePassword(self, password):
        """
        All kind of password checks.
        """
        min_length = self.env.config.getint('seishub', 'min_password_length')
        if len(password) < min_length:
            raise SeisHubError("Password is way too short!")

    def addUser(self, user_name, password, real_name, groups, institution='',
                email='', checkPassword=True):
        """
        Adds an user.
        """
        if user_name in self.users.keys():
            raise DuplicateObjectError("User already exists!")
        if checkPassword:
            self._validatePassword(password)
        # Check if all groups exists.
        for group in groups:
            if not group in self.groups.keys():
                msg = "Group '%s' does not exists." % group
                raise SeisHubError(msg)
        user = User(user_name=user_name, password_hash=hash(password),
                    real_name=real_name, groups=groups,
                    institution=institution, email=email)
        session = self.Session()
        session.add(user)
        try:
            session.commit()
        except Exception, e:
            session.rollback()
            raise SeisHubError(str(e))
        print "Added user!"
        session.close()
        self.refresh()

    def addGroup(self, group_name, group_owner, description=""):
        """
        Adds a new group. Should be self-explanatory.
        """
        if group_name in self.groups.keys():
            raise DuplicateObjectError("Group already exists!")
        # Do not check if the group owner exists! This is necessary because
        # groups can be created before any users exist!
        group = Group(group_name=group_name, group_owner=group_owner,
                      description=description)
        session = self.Session()
        session.add(group)
        try:
            session.commit()
        except Exception, e:
            session.rollback()
            raise SeisHubError(str(e))
        session.close()
        self.refresh()

    def updateGroup(self, group_name, new_group_name=None, group_owner=None,
                    description=None):
        """
        Updates an already existing group.
        """
        if new_group_name and group_name != new_group_name and \
           new_group_name in self.groups.keys():
            raise DuplicateObjectError("Group %s already exists!" %
                                       new_group_name)
        # Only allow existing users to be group owners.
        if group_owner and group_owner not in self.users.keys():
            raise SeisHubError("User %s does not exists." % group_owner)
        # Get the group, update it and write it to the database.
        group = self.getGroup(group_name)
        if new_group_name:
            group.group_name = new_group_name
        if group_owner:
            group.group_owner = group_owner
        if description:
            group.description = description
        session = self.Session()
        session.add(group)
        try:
            session.commit()
        except Exception, e:
            session.rollback()
            raise SeisHubError(str(e))
        session.close()
        self.refresh()

    def deleteGroup(self, group_name):
        """
        Deletes a group. Should be self-explanatory.
        """
        group = self.getGroup(group_name)
        session = self.Session()
        session.delete(group)
        try:
            session.commit()
        except Exception, e:
            session.rollback()
            raise SeisHubError(str(e))
        session.close()
        self.refresh()

    def getGroup(self, group_name):
        """
        Returns the Group instance of one user.
        """
        if group_name not in self.groups.keys():
            raise SeisHubError("Group %s does not exists!" % group_name)
        return self.groups[group_name]

    def checkPassword(self, user_name, password):
        """
        Check a user's password.
        """
        return self.checkPasswordHash(user_name, hash(password))

    def checkPasswordHash(self, user_name, password_hash):
        """
        Check a user's password hash.
        """
        user = self.getUser(user_name)
        return user.password_hash == password_hash

    def changePassword(self, user_name, password):
        """
        Change a user's password.
        """
        self.updateUser(user_name, password=password)

    def getUser(self, user_name):
        """
        Returns the User instance of one user.
        """
        if user_name not in self.users.keys():
            raise SeisHubError("User %s does not exists!" % user_name)
        return self.users[user_name]

    def updateUser(self, user_name, new_user_name=None, password=None,
        real_name=None, groups=None, institution=None, email=None):
        """
        Modifies user information. Should be self-explanatory.
        """
        if password:
            self._validatePassword(password)
        user = self.getUser(user_name)
        if new_user_name:
            user.user_name = new_user_name
        if password:
            user.password_hash = hash(password)
        if real_name:
            user.real_name = real_name
        if institution:
            user.institution = institution
        if email:
            user.email = email
        if groups:
            for group in groups:
                if not group in self.groups.keys():
                    msg = "Group '%s' does not exists." % group
                    raise SeisHubError(msg)
            user.groups = ", ".join(groups)
        # Add the updated user to the session.
        session = self.Session()
        session.add(user)
        try:
            session.commit()
        except Exception, e:
            session.rollback()
            raise SeisHubError(str(e))
        session.close()
        self.refresh()

    def deleteUser(self, user_name):
        """
        Deletes a user with a given user name.
        """
        user = self.getUser(user_name)
        session = self.Session()
        session.delete(user)
        try:
            session.commit()
        except Exception, e:
            session.rollback()
            raise SeisHubError(str(e))
        session.close()
        self.refresh()

    def refresh(self):
        """
        Refreshes the internal list of users and groups.
        """
        session = self.Session()
        self.users = {}
        for user in session.query(User).all():
            self.users[user.user_name] = user
        self.groups = {}
        for group in session.query(Group).all():
            self.groups[group.group_name] = group
        session.close()

    def getCheckers(self):
        """
        Returns a tuple of checkers used by Twisted portal objects.
        """
        return (PasswordDictChecker(self.env),)
