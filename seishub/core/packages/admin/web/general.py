# -*- coding: utf-8 -*-
"""
General configuration panels for the web-based administration service.
"""

from seishub.core.core import Component, implements
from seishub.core.db import DEFAULT_POOL_SIZE, DEFAULT_MAX_OVERFLOW
from seishub.core.defaults import DEFAULT_COMPONENTS, ADMIN_THEME, ADMIN_TITLE
from seishub.core.exceptions import SeisHubError
from seishub.core.log import LOG_LEVELS, ERROR
from seishub.core.packages.interfaces import IAdminPanel
from seishub.core.util.text import getFirstSentence
from sqlalchemy import create_engine
from twisted.application import service
from twisted.internet import reactor
import inspect
import os
import sys


class BasicPanel(Component):
    """
    Basic configuration.
    """
    implements(IAdminPanel)

    template = 'templates' + os.sep + 'general_basic.tmpl'
    panel_ids = ('admin', 'General', 'basic', 'Basic Settings')
    has_roles = ['SEISHUB_ADMIN']

    def render(self, request):
        data = {
            'log_levels': dict([(v, k) for k, v in LOG_LEVELS.iteritems()]),
            'themes': self.root.themes
        }
        if request.method == 'POST':
            host = request.args0.get('host', 'localhost')
            description = request.args0.get('description', '')
            log_level = request.args0.get('log_level', 'ERROR').upper()
            clearlogs = request.args0.get('clear_logs_on_startup', False)
            theme = request.args0.get('theme', ADMIN_THEME)
            title = request.args0.get('title', ADMIN_TITLE)
            self.config.set('seishub', 'host', host)
            self.config.set('seishub', 'description', description)
            self.config.set('seishub', 'log_level', log_level)
            self.config.set('seishub', 'clear_logs_on_startup', clearlogs)
            self.config.set('web', 'admin_theme', theme)
            self.config.set('web', 'admin_title', title)
            self.config.save()
            if self.env.log.log_level != LOG_LEVELS.get(log_level, ERROR):
                self.env.log.log("Setting log level to %s" % log_level)
                self.env.log.log_level = LOG_LEVELS.get(log_level, ERROR)
            data['info'] = "Options have been saved."
        data.update({
          'instance': self.config.path,
          'host': self.config.get('seishub', 'host'),
          'description': self.config.get('seishub', 'description'),
          'theme': self.config.get('web', 'admin_theme'),
          'title': self.config.get('web', 'admin_title'),
          'log_level': self.config.get('seishub', 'log_level'),
          'clear_logs_on_startup':
                self.config.getbool('seishub', 'clear_logs_on_startup')
        })
        return data


class DatabasePanel(Component):
    """
    Database configuration.
    """
    implements(IAdminPanel)

    template = 'templates' + os.sep + 'general_database.tmpl'
    panel_ids = ('admin', 'General', 'database', 'Database')
    has_roles = ['SEISHUB_ADMIN']

    def render(self, request):
        db = self.db
        data = {
          'db': db,
          'uri': self.config.get('db', 'uri'),
          'pool_size': self.config.getint('db', 'pool_size'),
          'max_overflow': self.config.getint('db', 'max_overflow'),
        }
        if db.engine.name == 'sqlite':
            data['info'] = ("SQLite Database enabled!", "A SQLite database "
                            "should never be used in a productive "
                            "environment!<br />Instead try to use any "
                            "supported database listed at "
                            "<a href='http://www.sqlalchemy.org/trac/wiki/"
                            "DatabaseNotes'>http://www.sqlalchemy.org/trac/"
                            "wiki/DatabaseNotes</a>.")
        if request.method == 'POST':
            uri = request.args0.get('uri', '')
            pool_size = request.args0.get('pool_size', DEFAULT_POOL_SIZE)
            max_overflow = request.args0.get('max_overflow',
                                             DEFAULT_MAX_OVERFLOW)
            verbose = request.args0.get('verbose', False)
            self.config.set('db', 'verbose', verbose)
            self.config.set('db', 'pool_size', pool_size)
            self.config.set('db', 'max_overflow', max_overflow)
            data['uri'] = uri
            try:
                engine = create_engine(uri)
                engine.connect()
            except:
                data['error'] = ("Could not connect to database %s" % uri,
                                 "Please make sure the database URI has " +
                                 "the correct syntax: dialect://user:" +
                                 "password@host:port/dbname.")
            else:
                self.config.set('db', 'uri', uri)
                data['info'] = ("Connection to database was successful",
                                "You have to restart SeisHub in order to " +
                                "see any changes at the database settings.")
            self.config.save()
        data['verbose'] = self.config.getbool('db', 'verbose')
        data['pool_size'] = self.config.getint('db', 'pool_size')
        data['max_overflow'] = self.config.getint('db', 'max_overflow')
        return data


class ConfigPanel(Component):
    """
    General configuration.
    """
    implements(IAdminPanel)

    template = 'templates' + os.sep + 'general_config.tmpl'
    panel_ids = ('admin', 'General', 'ini', 'seishub.ini')
    has_roles = ['SEISHUB_ADMIN']

    def render(self, request):  # @UnusedVariable
        data = {}
        sections = self.config.sections()
        data['sections'] = sections
        data['options'] = {}
        for s in sections:
            options = self.config.options(s)
            data['options'][s] = options
        return data


class LogsPanel(Component):
    """
    Web based log file viewer.
    """
    implements(IAdminPanel)

    template = 'templates' + os.sep + 'general_logs.tmpl'
    panel_ids = ('admin', 'General', 'logs', 'Logs')
    has_roles = ['SEISHUB_ADMIN']

    def render(self, request):  # @UnusedVariable
        log_file = os.path.join(self.env.getInstancePath(), 'logs',
                                'seishub.log')
        try:
            fh = open(log_file, 'r')
            logs = fh.readlines()
            fh.close()
        except:
            logs = ["Can't open log file."]
        error_logs = logs[-500:]
        data = {
          'errorlog': error_logs,
        }
        return data


class GroupsPanel(Component):
    """
    Administration of groups.
    """
    implements(IAdminPanel)

    template = 'templates' + os.sep + 'general_groups.tmpl'
    panel_ids = ('admin', 'General', 'groups', 'Groups')
    has_roles = ['SEISHUB_ADMIN']

    def render(self, request):
        data = {}

        # process POST request
        if request.method == 'POST':
            args = request.args
            # Clicking the Add button opens a new site for entering the new
            # group's information.
            if 'add-group' in args.keys():
                data['action'] = 'add'
            # This function is called from within the Add new group form and
            # will actually create a new group.
            elif 'add' in args.keys():
                data.update(self._addGroup(args))
                # Upon error, show the same screen again.
                if "error" in data:
                    data["action"] = "add"
            elif 'delete' in args.keys():
                data.update(self._deleteGroup(args))
            elif 'edit-group' in args.keys():
                group_name = args.get("group_name", [""])[0]
                # admin and users groups cannot be edited.
                if not group_name:
                    data["error"] = "No group name given."
                elif group_name in ["admin", "users"]:
                    data["error"] = ("Group '%s' is " % group_name) + \
                        "protected and cannot be changed!"
                else:
                    data = self._getGroup(args)
                    data["action"] = "edit"
            elif "edit" in args.keys():
                data = self._editGroup(args)
                # Upon error, show the same screen again.
                if "error" in data:
                    data["action"] = "edit"
        # Default vales
        result = {
            "group_name": "",
            # The old group name is needed in case one wants to edit the name
            # of a group.
            "old_group_name": "",
            "group_owner": "",
            "description": "",
            # Sort groups by id.
            "groups": sorted(self.auth.groups.values(), key=lambda x: x.id),
            # By default, do nothing.
            "action": ""
        }
        result.update(data)
        return result

    def _addGroup(self, args):
        """
        Panel to add a new group.
        """
        data = {}
        data["group_name"] = args.get("group_name", [""])[0]
        data["group_owner"] = args.get("group_owner", [""])[0]
        data["description"] = args.get("description", [""])[0]
        if not data["group_name"]:
            data["error"] = "Group name must be given."
            return data
        elif not data["group_owner"]:
            data["error"] = "Group owner must be given."
            return data
        elif data["group_owner"] not in self.auth.users.keys():
            data["error"] = "Group owner '%s' does not exists" % \
                data["group_owner"]
            return data
        elif data["group_name"] in self.auth.groups.keys():
            data["error"] = "Group '%s' already exists" % \
                data["group_name"]
            return data
        try:
            self.auth.addGroup(data["group_name"], data["group_owner"],
                               data["description"])
        except Exception, e:
            self.log.error("Error adding new group '%s'" % data["group_name"],
                           e)
            data["error"] = "Error adding new group '%s' - %s" % \
                (data["group_name"], str(e))
            return data
        data["info"] = "Added group '%s'." % data["group_name"]
        return data

    def _getGroup(self, args):
        """
        Retrieves a group and fills the data dictionary.
        """
        data = {}
        data["group_name"] = args.get("group_name", [""])[0]
        if not data["group_name"]:
            data["error"] = "No group selected!"
            return data
        if not data["group_name"] in self.auth.groups.keys():
            data["error"] = "Group '%s' does no exists." % data["group_name"]
            return data
        # Get the group.
        group = self.auth.groups[data["group_name"]]
        data["old_group_name"] = data["group_name"]
        data["group_owner"] = group.group_owner
        data["description"] = group.description
        return data

    def _editGroup(self, args):
        """
        Panel to edit an existing group.
        """
        data = {}
        data["group_name"] = args.get("group_name", [""])[0]
        data["old_group_name"] = args.get("old_group_name", [""])[0]
        data["group_owner"] = args.get("group_owner", [""])[0]
        data["description"] = args.get("description", [""])[0]
        if data["old_group_name"] in ["admin", "users"]:
            data["error"] = "Group '%s' is protected and cannot be changed." \
                % data["old_group_name"]
            return data
        if not data["group_name"]:
            data["error"] = "Group name needs to be given!"
            return data
        elif not data["group_owner"]:
            data["error"] = "Group owner needs to be given!"
            return data
        elif data["group_owner"] not in self.auth.users.keys():
            data["error"] = "Group owner '%s' does not exist!" % \
                data["group_owner"]
            return data
        try:
            self.auth.updateGroup(data["old_group_name"],
                new_group_name=data["group_name"],
                group_owner=data["group_owner"],
                description=data["description"])
        except Exception, e:
            self.log.error("Error editing group %s" % data["old_group_name"],
                           e)
            data["error"] = "Error editing group '%s' - %s" % \
                (data["old_group_name"], str(e))
            return data
        data["info"] = "Edited group '%s'" % data["old_group_name"]
        return data

    def _deleteGroup(self, args):
        """
        Panel to delete a selected group.
        """
        data = {}
        data["group_name"] = args.get("group_name", [""])[0]
        if not data["group_name"]:
            data["error"] = "No group selected"
            return data
        # Groups 'admin' and 'users' are protected and essential.
        elif data["group_name"] in ["admin", "users"]:
            data["error"] = "Group '%s' is essential and cannot be deleted!" \
                % data["group_name"]
            return data
        try:
            self.auth.deleteGroup(group_name=data["group_name"])
        except Exception, e:
            self.log.error("Error deleting group '%s'" % data["group_name"], e)
            data["error"] = "Error deleting group '%s' - %s" % \
                    (data["group_name"], str(e))
            return data
        data["info"] = "Deleted group '%s'" % data["group_name"]
        return data


class UsersPanel(Component):
    """
    Administration of users.
    """
    implements(IAdminPanel)

    template = 'templates' + os.sep + 'general_users.tmpl'
    panel_ids = ('admin', 'General', 'users', 'Users')
    has_roles = ['SEISHUB_ADMIN']

    def render(self, request):
        data = {}
        # process POST request
        if request.method == 'POST':
            args = request.args
            if 'add-user' in args.keys():
                data['action'] = 'add'
            elif 'edit-user' in args.keys():
                data = self._getUser(args)
                data["action"] = "edit"
            elif 'delete' in args.keys():
                data = self._deleteUser(args)
            elif 'add' in args.keys():
                data['action'] = 'add'
                data.update(self._addUser(args))
            elif 'edit' in args.keys():
                data['action'] = 'edit'
                data.update(self._editUser(args))
        # default values
        result = {
            'id': '',
            'user_name': '',
            # The old user name enables the edit-user panel to show the old
            # user when editing the name.
            'old_user_name': '',
            'real_name': '',
            'email': '',
            'institution': '',
            # By default, all users will be added to the 'users' group.
            'groups': 'users',
            # Sort users by id.
            'users': sorted(self.auth.users.values(), key=lambda x: x.id),
            # No action will simply render a list of all users.
            'action': ''
        }
        result.update(data)
        return result

    def _getUser(self, args):
        """
        Get user data.
        """
        data = {}
        user_name = args.get("user_name", [""])[0]
        if not user_name:
            return {"error": "No user selected"}
        else:
            user = self.auth.getUser(user_name)
            data["id"] = user.id
            data["user_name"] = user.user_name
            data["old_user_name"] = user.user_name
            data["real_name"] = user.real_name
            data["email"] = user.email
            data["institution"] = user.institution
            data["groups"] = user.groups
        return data

    def _addUser(self, args):
        """
        Add a new user.
        """
        password = args.get("password", [""])[0]
        password_confirmation = args.get("password_confirmation", [""])[0]

        # Just fill them in so they will show up again if some wrong
        # information was entered.
        data = {}
        data["user_name"] = args.get("user_name", [""])[0]
        data["real_name"] = args.get("real_name", [""])[0]
        data["email"] = args.get("email", [""])[0]
        data["institution"] = args.get("institution", [""])[0]
        data["groups"] = args.get("groups", [""])[0]

        # Some error checks.
        if not data["user_name"]:
            data["error"] = "No user name given."
            return data
        elif not data["real_name"]:
            data["error"] = "No real name given."
            return data
        elif not password or not password_confirmation:
            data["error"] = "Password or password confirmation missing."
            return data
        elif password != password_confirmation:
            data["error"] = "Password and password confirmation are not equal!"
            return data
        try:
            groups = [_i.strip() for _i in data["groups"].split(",") if
                      _i.strip()]
        except:
            data["error"] = ("Groups needs to be a comma seperated list with "
                             "at least one entry")
            return data
        if not data["groups"]:
            data["error"] = ("Groups needs to be a comma separated list with "
                             "at least one entry")
            return data

        # Actually add the user. Some further checks are performed in there.
        try:
            self.auth.addUser(user_name=data["user_name"],
                              real_name=data["real_name"],
                              groups=groups, password=password,
                              email=data["email"],
                              institution=data["institution"])
        except Exception, e:
            self.log.error("Error adding new user", e)
            data["error"] = "Error adding new user - %s" % str(e)
            return data

        data["info"] = "User '%s' has been added." % data["user_name"]
        data["action"] = None

        return data

    def _editUser(self, args):
        """
        Modify user information.
        """
        password = args.get("password", [""])[0]
        password_confirmation = args.get("password_confirmation", [""])[0]

        # Just fill them in so they will show up again if some wrong
        # information was entered.
        data = {}
        data["user_name"] = args.get("user_name", [""])[0]
        data["old_user_name"] = args.get("old_user_name", [""])[0]
        data["real_name"] = args.get("real_name", [""])[0]
        data["email"] = args.get("email", [""])[0]
        data["institution"] = args.get("institution", [""])[0]
        data["groups"] = args.get("groups", [""])[0]

        # Some error checks.
        if not data["user_name"]:
            data["error"] = "No user name given."
            return data
        elif not data["real_name"]:
            data["error"] = "No real name given."
            return data
        elif password != password_confirmation:
            data["error"] = "Password and password confirmation are not equal!"
            return data
        try:
            groups = [_i.strip() for _i in data["groups"].split(",") if
                      _i.strip()]
        except:
            data["error"] = ("Groups needs to be a comma seperated list with "
                             "at least one entry")
            return data
        if not data["groups"]:
            data["error"] = ("Groups needs to be a comma separated list with "
                             "at least one entry")
            return data

        # Actually add the user. Some further checks are performed in there.
        try:
            self.auth.updateUser(data["old_user_name"],
                                 new_user_name=data["user_name"],
                                 real_name=data["real_name"], groups=groups,
                                 password=password, email=data["email"],
                                 institution=data["institution"])
        except Exception, e:
            self.log.error("Error updating user '%s'" % data["old_user_name"],
                e)
            data["error"] = "Error updating user '%s' - %s" % \
                (data["old_user_name"], str(e))
            return data

        data["info"] = "User '%s' has been updated." % data["old_user_name"]
        data["action"] = None

        return data

    def _deleteUser(self, args):
        """
        Delete one user.
        """
        user_name = args.get("user_name", [""])[0]
        if not user_name:
            return {"error": "No user selected"}
        try:
            self.auth.deleteUser(user_name=user_name)
        except SeisHubError(), e:
            # checks are made in self.auth.deleteUser method
            return {'error': str(e)}
        except Exception, e:
            self.log.error("Error deleting user", e)
            return {"error": "Error deleting user. %s" % str(e)}
        return {'info': "User '%s' has been deleted." % user_name}


class PluginsPanel(Component):
    """
    Administration of plug-ins.
    """
    implements(IAdminPanel)

    template = 'templates' + os.sep + 'general_plugins.tmpl'
    panel_ids = ('admin', 'General', 'plug-ins', 'Plug-ins')
    has_roles = ['SEISHUB_ADMIN']

    def render(self, request):
        error = None
        if request.method == 'POST':
            if 'update' in request.args:
                error = self._updatePlugins(request)
                if not error:
                    request.redirect(request.uri)
                    request.finish()
                    return ""
            if 'reload' in request.args:
                self._refreshPlugins()
        return self._viewPlugins(request, error)

    def _refreshPlugins(self):
        from seishub.core.util.loader import ComponentLoader
        ComponentLoader(self.env)

    def _updatePlugins(self, request):
        """
        Update components.
        """
        enabled = request.args.get('enabled', [])
        error = []

        from seishub.core.core import ComponentMeta
        for component in ComponentMeta._components:
            module = sys.modules[component.__module__]
            modulename = module.__name__
            classname = modulename + '.' + component.__name__
            if classname in enabled or classname in DEFAULT_COMPONENTS or \
                modulename in DEFAULT_COMPONENTS:
                if not self.env.isComponentEnabled(classname):
                    msg = self.env.enableComponent(component, update=False)
                    if msg and msg not in error:
                        error.append(msg)
            elif self.env.isComponentEnabled(classname):
                msg = self.env.disableComponent(component, update=False)
                if msg and msg not in error:
                    error.append(msg)
        # call update on the end
        self.env.update()
        return error

    def _viewPlugins(self, request, error=None):  # @UnusedVariable
        plugins = {}
        from seishub.core.core import ComponentMeta
        for component in ComponentMeta._components:
            try:
                module = sys.modules[component.__module__]
            except:
                continue
            description = getFirstSentence(inspect.getdoc(module))
            modulename = module.__name__
            classname = modulename + '.' + component.__name__
            plugin = {
              'name': component.__name__,
              'module': module.__name__,
              'file': module.__file__,
              'classname': classname,
              'description': getFirstSentence(inspect.getdoc(component)),
              'enabled': self.env.isComponentEnabled(classname),
              'required': classname in DEFAULT_COMPONENTS or
                          modulename in DEFAULT_COMPONENTS,
            }
            packagename = '.'.join(modulename.split('.')[0:3])
            plugins.setdefault(packagename, {})
            plugins[packagename].setdefault(modulename, {})
            plugins[packagename][modulename].setdefault('plugins',
                                                        []).append(plugin)
            plugins[packagename][modulename]['description'] = description
        data = {
          'sorted_plugins': sorted(plugins),
          'plugins': plugins,
          'error': error,
        }
        return data


class ServicesPanel(Component):
    """
    Administration of services.
    """
    implements(IAdminPanel)

    template = 'templates' + os.sep + 'general_services.tmpl'
    panel_ids = ('admin', 'General', 'services', 'Services')
    has_roles = ['SEISHUB_ADMIN']

    def render(self, request):
        if request.method == 'POST':
            if 'shutdown' in request.args:
                self._shutdownSeisHub()
            elif 'reload' in request.args:
                self._changeServices(request)
            elif 'restart' in request.args:
                self._restartSeisHub()
        data = {
          'services': service.IServiceCollection(self.env.app),
        }
        return data

    def _shutdownSeisHub(self):
        reactor.stop()  # @UndefinedVariable

    def _restartSeisHub(self):
        raise NotImplemented

    def _changeServices(self, request):
        serviceList = request.args.get('service', [])
        for srv in service.IServiceCollection(self.env.app):
            if srv.running and not srv.service_id in serviceList:
                self.env.disableService(srv.service_id)
            elif not srv.running and srv.service_id in serviceList:
                self.env.enableService(srv.service_id)
