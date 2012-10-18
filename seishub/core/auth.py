# -*- coding: utf-8 -*-

from obspy.core import UTCDateTime
import os
from seishub.core.config import IntOption, Option
from seishub.core.defaults import MIN_PASSWORD_LENGTH
from seishub.core.exceptions import DuplicateObjectError, SeisHubError
from seishub.core.util.text import hash
from sqlalchemy import Column, String, create_engine, Integer, DateTime, \
    Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from twisted.cred import checkers, credentials, error
from twisted.internet import defer
from zope.interface import implements


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
        date_joined:   Datetime at account creation time.
        last_login:    Datetime of the user's last login.
        is_active:     Boolean flag whether or not the user is considered to be
                       active.
    """
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    user_name = Column(String)
    password_hash = Column(String)
    real_name = Column(String)
    groups = Column(String)
    institution = Column(String)
    email = Column(String)
    date_joined = Column(DateTime)
    last_login = Column(DateTime)
    is_active = Column(Boolean)

    def __init__(self, user_name, password_hash, real_name, groups,
        institution='', email=''):
        self.user_name = user_name
        self.password_hash = password_hash
        self.real_name = real_name
        self.groups = ", ".join(groups)
        self.institution = institution
        self.email = email
        self.date_joined = UTCDateTime().datetime
        self.last_login = None
        self.is_active = True

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

    def checkIsUserInGroup(self, user_name, group_name):
        user = self.getUser(user_name)
        if group_name in user.groups:
            return True
        return False

    def getUserAndGroupIds(self, user_name):
        """
        Convenience method to return the id of the user and the first item in
        the group list.
        """
        try:
            user = self.getUser(user_name)
        # Return two empty strings if the user does not exist.
        except SeisHubError:
            return "", ""
        # Return the user id and the id of the first group.
        return user.id, self.getGroup(user.groups.split(",")[0]).id

    def getGroup(self, group_name):
        """
        Returns the Group instance of one user.
        """
        if group_name not in self.groups.keys():
            raise SeisHubError("Group %s does not exists!" % group_name)
        return self.groups[group_name]

    def checkPassword(self, user_name, password):
        """
        Check a user's password. Will also set the last login flag of the user
        to the current time.
        Will return False for inactive users!
        """
        return self.checkPasswordHash(user_name, hash(password))

    def checkPasswordHash(self, user_name, password_hash):
        """
        Check a user's password hash. Will also set the last login flag of the
        user to the current time.
        Will return False for inactive users!
        """
        try:
            user = self.getUser(user_name)
        except SeisHubError:
            return False
        if not user.is_active:
            return False
        password_valid = password_hash == user.password_hash
        if password_valid is True:
            # Update the users last login time.
            user.last_login = UTCDateTime().datetime
            session = self.Session()
            session.add(user)
            try:
                session.commit()
            except Exception, e:
                session.rollback()
                raise SeisHubError(str(e))
            session.close()
            self.refresh()
        return password_valid

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
        real_name=None, groups=None, institution=None, email=None,
        is_active=None):
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
        if is_active is not None:
            user.is_active = bool(is_active)
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

        Currently used by the manhole, sftp and ssh services.
        """
        return (PasswordDictChecker(self.env),)


class Authorization(object):
    """
    Object dealing with the authorization of resources. It is meant to be
    attached to a resource object and stores the owner, the group and the
    permissions for owner/group/other for the parent object.

    The permission model is modelled after the Unix file system and is a three
    digit octal code with the same meaning.
    """
    def __init__(self, owner="admin", group="admin", permissions="660",
        public=False):
        """
        The empty constructor only gives rights to admins. This is only a dummy
        authorization object as admins have all rights anyways. At the same
        time this is the safe solution in case someone forgets to set
        permissions somewhere.
        """
        self._read_actions = ("r", "read")
        self._write_actions = ("w", "write")
        self._read_write_actions = ("rw", "read-write", "read write",
            "read-write")
        self.owner = owner
        self.group = group
        self.permissions = permissions
        self.public = public

    def is_authorized(self, action, user=None, user_groups=None):
        """
        Determine whether the given user with his groups is authorized to
        access this resource.

        :param action: "r", "read", "w" or "write"
        """
        action = action.lower()
        # If public read access is True, return True.
        if self.public is True and action in self._read_actions:
            return True
        # User or the groups of the user needs to be given.
        if user is None and user_groups is None:
            return False
        if isinstance(user_groups, basestring):
            user_groups = [user_groups]
        # Determine owner and group membership.
        if user and user == self.owner:
            user_is_owner = True
        else:
            user_is_owner = False
        if user_groups and self.group in user_groups:
            user_in_group = True
        else:
            user_in_group = False
        # Check read actions. Bitwise and with 4 has to not be 0!
        if action in self._read_actions:
            if user_is_owner and self._owner_rights & 4:
                return True
            if user_in_group and self._group_rights & 4:
                return True
            if user_is_owner is False and user_in_group is False and \
                self._other_rights & 4:
                return True
        # Check write actions. Bitwise and with 2 has to not be 0!
        elif action in self._write_actions:
            if user_is_owner and self._owner_rights & 2:
                return True
            if user_in_group and self._group_rights & 2:
                return True
            if user_is_owner is False and user_in_group is False and \
                self._other_rights & 2:
                return True
        return False

    @property
    def permissions(self):
        """
        Permissions of a resource in UNIX like octal notation.

        The read bit adds 4 to the total value.
        The write bit adds 2 to the total value.
        The execute bit adds 1 to the total value (Currently has no meaning!).

        Examples:
            600: Read and write permission only for the resource owner.
            644: Read permissions for everyone + write permissions for the
                 owner.
            640: Read permissions for the group and owner + write permissions
                 for the owner.
            666: Read and write permissions for everyone.
            400: Read access only for the owner. Useful to prevent accidental
                 changes.

        Other combinations are possible but likely do not make much sense.
        """
        return "%i%i%i" % (self._owner_rights, self._group_rights,
            self._other_rights)

    @permissions.setter
    def permissions(self, value):
        if not isinstance(value, basestring) or len(value) != 3 or \
            not value.isdigit() or int(value) < 0:
            msg = "Permission needs to be a three digit string."
            raise SeisHubError(msg)
        self._owner_rights = int(value[0])
        self._group_rights = int(value[1])
        self._other_rights = int(value[2])

    def __str__(self):
        ret_val = ("Authorization object - owner: '{owner}', Group: '{group}',"
            " Permissions: '{permissions}', Public Read Access: {public}")
        return ret_val.format(
            owner=self.owner,
            group=self.group,
            permissions="%s%s%s%s%s%s" % (
                "r" if self._owner_rights & 4 else "-",
                "w" if self._owner_rights & 2 else "-",
                "r" if self._group_rights & 4 else "-",
                "w" if self._group_rights & 2 else "-",
                "r" if self._other_rights & 4 else "-",
                "w" if self._other_rights & 2 else "-",),
            public=str(self.public))
