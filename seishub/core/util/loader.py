#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Simple class to automatically discover and load all SeisHub plugins.
"""

import copy
import pkg_resources
import os
import sys


__all__ = ['ComponentLoader']


class ComponentLoader(object):
    """
    Upon construction, this class will automatically load all SeisHub plugins
    it finds.

    Every Python module that registers a "seishub.plugin" entry_point will be
    considered a SeisHub plugin and consequently loaded.

    Three places are searched for plugins:
        * seishub.plugins_dir as specified in the SeisHub config file.
        * The 'plugins' subdirectory of the current SeisHub instance.
        * Any path in sys.path.
    """
    def __init__(self, env):
        self.env = env
        extra_path = env.config.get('seishub', 'plugins_dir')
        # add plug-in directory
        plugins_dir = os.path.join(env.config.path, 'plugins')
        search_path = [plugins_dir, ]
        # add user defined paths
        if extra_path:
            search_path += list((extra_path,))
        self._loadPlugins(search_path)

    def _loadPlugins(self, extra_search_paths):
        """
        Loader that loads SeisHub plugins from the specified search paths and
        L{sys.path}.
        """
        # Modify sys.path to find any additional modules.
        unmodified_system_path = copy.deepcopy(sys.path)
        sys.path += extra_search_paths

        # Loop over all modules
        plugin_count = 0
        for entry in pkg_resources.iter_entry_points("seishub.plugins"):
            self.env.log.debug("Loading plugin '%s v%s' from %s ..." %
                (entry.module_name, entry.dist.version, entry.dist.location))
            try:
                entry.load()
            except Exception, e:
                self.env.log.warn("Could not load plugin '%s': %s" %
                                  (entry.name, e))
            plugin_count += 1

        self.env.log.info("Initialized %i plug-in(s)." % plugin_count)

        # Restore sys.path.
        sys.path = unmodified_system_path
