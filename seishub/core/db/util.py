# -*- coding: utf-8 -*-
"""
Database related utilities.
"""

from decimal import Decimal
from lxml.etree import Element, SubElement, tostring
from seishub.core.util.xmlwrapper import toString
import sqlalchemy
from sqlalchemy import sql, Table
import datetime
import json


def compileStatement(stmt, bind=None, params={}, **kwargs):
    """
    Compiles a statement with inlines bindparams and additional arguments.

    WARNING: This doesn't do any escaping!

    @see L{http://www.sqlalchemy.org/trac/wiki/DebugInlineParams}

    XXX: Creating views currently relies on this - you should never use it
    within mapped functions due to security reasons!
    """
    if not bind:
        bind = stmt.bind
    compiler = bind.dialect.statement_compiler(bind.dialect, stmt)
    compiler.bindtemplate = "[[[%(name)s]]]"
    compiler.compile()
    d = compiler.params
    d.update(params)
    d.update(kwargs)
    s = compiler.string
    for id, value in d.iteritems():
        s = s.replace('[[[' + id + ']]]', repr(value))
    # this omits an annoying warning
    if bind.engine.name.startswith('postgres'):
        s = s.replace('%%', '%')
    return s


def querySingleColumn(request, table, column, **kwargs):
    """
    """
    tab = Table(table, request.env.db.metadata, autoload=True)
    # fetch arguments
    order = request.args0.get('order', 'ASC').upper()
    if order == 'ASC':
        order_by = [sql.asc(tab.c[column])]
    else:
        order_by = [sql.desc(tab.c[column])]
    try:
        limit = int(request.args0.get('limit'))
        offset = int(request.args0.get('offset', 0))
    except:
        limit = None
        offset = 0
    oncl = None
    if kwargs:
        for key, value in kwargs.iteritems():
            if value:
                oncl = sql.and_(oncl, tab.c[key] == value)
    # build up query
    query = sql.select([tab.c[column].distinct()], oncl, limit=limit,
                       offset=offset, order_by=order_by)
    # execute query
    try:
        results = request.env.db.query(query)
    except:
        results = []
    # format results
    if not limit:
        return formatResults(request, results)
    # ok count all distinct values
    query = sql.select([sql.func.count(tab.c[column].distinct())])
    # execute query
    try:
        count = request.env.db.query(query).fetchone()[0]
    except:
        count = 0
    return formatResults(request, results, limit=limit, offset=offset,
                         count=count)


class CustomJSONEncoder(json.JSONEncoder):
    """
    Custom JSOn Encoder which also takes care of datetime and Decimal objects.
    """
    def default(self, obj):
        if isinstance(obj, datetime.date):
            return obj.strftime('%Y-%m-%d')
        elif isinstance(obj, datetime.time):
            return obj.strftime('%H:%M:%S')
        elif isinstance(obj, datetime.datetime):
            return obj.strftime('%Y-%m-%dT%H:%M:%SZ')
        elif isinstance(obj, datetime.timedelta):
            return str(obj)
        elif isinstance(obj, Decimal):
            return float(obj)
        else:
            return json.JSONEncoder.default(self, obj)


def formatORMResults(request, query, build_url=False):
    """
    """
    base_url = request.env.getRestUrl()
    # create stats
    stats = {}
    stats['totalResultsAvailable'] = query.count()
    # limits or offset
    try:
        limit = int(request.args0.get('limit'))
        query = query.limit(limit)
    except:
        pass
    offset = int(request.args0.get('offset', 0))
    query = query.offset(offset)
    stats['firstResultPosition'] = offset
    stats['totalResultsReturned'] = query.count()
    # get format
    formats = request.args.get('format', []) or request.args.get('output', [])
    if 'json' in formats:
        # build up JSON string
        data = stats
        data['Result'] = []
        for result in query:
            temp = {}
            for key in result.keys():
                value = getattr(result, key, '')
                temp[key] = str(value)
            data['Result'].append(temp)
        # add attributes to root node
        for key, value in stats.iteritems():
            if not isinstance(value, list):
                data[key] = str(value)
            else:
                data[key] = value
        # generate correct header
        request.setHeader('content-type', 'application/json; charset=UTF-8')
        # create output
        return json.dumps({'ResultSet': data}, cls=CustomJSONEncoder, indent=4)
    elif 'xhtml' in formats:
        # build up a XHTML table
        html = Element("html")
        body = SubElement(html, "body")
        table = SubElement(body, "table", border="1")
        sub = SubElement(table, "tr")
        for key in query._entities:
            SubElement(sub, "th").text = str(key._label_name)
        # build URL
        if build_url:
            SubElement(sub, "th").text = "URL"
        for result in query:
            sub = SubElement(table, "tr")
            for key in result.keys():
                value = getattr(result, key, '')
                if value == None:
                    value = ''
                SubElement(sub, "td").text = str(value)
            # build URL
            if not build_url:
                continue
            url = '/'.join([base_url, 'xml', result['package_id'],
                            result['resourcetype_id'],
                            result['resource_name']])
            td = SubElement(sub, 'td')
            SubElement(td, 'a', href=url).text = url
        # generate correct header
        request.setHeader('content-type', 'text/html; charset=UTF-8')
        return tostring(html, method='html', encoding='utf-8')
    else:
        # build up XML document
        xml = Element("ResultSet")
        for result in query:
            sub = SubElement(xml, "Item")
            for key in result.keys():
                value = getattr(result, key, '')
                SubElement(sub, key).text = str(value)
            # build URL
            if not build_url:
                continue
            SubElement(sub, 'url').text = '/'.join([base_url, 'xml',
                                                    result['package_id'],
                                                    result['resourcetype_id'],
                                                    result['resource_name']])
        # add attributes to root node
        for key, value in stats.iteritems():
            xml.set(key, str(value))
        return toString(xml)


def formatResults(request, results, count=None, limit=None, offset=0,
                  build_url=False):
    """
    Takes a list of (potentially nested) dictionaries and produces output in
    XML, JSON or XHTML. The limit and offset kwargs have to be provided by the
    user.
    Also sets the correct HTML headers.
    """
    base_url = request.env.getRestUrl()
    # create stats
    stats = {}
    stats['firstResultPosition'] = offset
    # get format
    formats = request.args.get('format', []) or request.args.get('output', [])
    if 'json' in formats:
        # build up JSON string
        data = stats
        data['Result'] = [dict(r) for r in results]
        data['totalResultsReturned'] = limit or len(data['Result'])
        data['totalResultsAvailable'] = count or len(data['Result'])
        # generate correct header
        request.setHeader('content-type', 'application/json; charset=UTF-8')
        # create output
        return json.dumps({'ResultSet': data}, cls=CustomJSONEncoder, indent=4)
    elif 'xhtml' in formats:
        # build up a XHTML table
        html = Element("html")
        body = SubElement(html, "body")
        table = SubElement(body, "table", border="1")
        sub = SubElement(table, "tr")
        # In xhtml the order of keys matters as we want to build a table.
        # If the result object is a sqlalchemy.engine.base.ResultProxy object,
        # use the key order stored there, otherwise just sort the keys
        # alphabetically.
        if hasattr(results, "keys"):
            keys = [str(_i) for _i in results.keys()]
        else:
            keys = sorted([str(_i) for _i in results[0].keys()])
        for key in keys:
            SubElement(sub, "th").text = key
        # build URL
        if build_url:
            SubElement(sub, "th").text = "URL"
        for result in results:
            sub = SubElement(table, "tr")
            for key in keys:
                try:
                    value = result[key]
                except:
                    value = ""
                if value is None:
                    value = ""
                SubElement(sub, "td").text = str(value)
            # build URL
            if not build_url:
                continue
            url = '/'.join([base_url, 'xml', result['package_id'],
                            result['resourcetype_id'],
                            result['resource_name']])
            td = SubElement(sub, 'td')
            SubElement(td, 'a', href=url).text = url
        # generate correct header
        request.setHeader('content-type', 'text/html; charset=UTF-8')
        return tostring(html, method='html', encoding='utf-8',
            pretty_print=True)
    else:
        def toXML(root, item):
            """
            Recursively translate a dict of dicts/lists to a SubElement
            structure.

            Can deal with nested dicts and lists of dictionaries, e.g.

            item = {"root":
                {"item1": "a", "list_of_a": [{"a": "2"}, {"a": "3"}]}}

            would results in

            <root>
                <item1>a</item1>
                <list_of_a>
                    <a>2</a>
                    <a>3</a>
                </list_of_a>
            </root>
            """
            try:
                item = dict(item)
            except:
                pass
            if isinstance(item, dict):
                for (key, value) in item.iteritems():
                    new_root = SubElement(root, key)
                    toXML(new_root, value)
            elif hasattr(item, "__iter__"):
                for sub_item in item:
                    toXML(root, sub_item)
            else:
                root.text = str(item)

        # build up XML document
        xml = Element("ResultSet")
        for i, result in enumerate(results):
            i = i + 1
            sub = SubElement(xml, "Item")
            toXML(sub, result)
            # build URL
            if not build_url:
                continue
            SubElement(sub, 'url').text = '/'.join([base_url, 'xml',
                                                    result['package_id'],
                                                    result['resourcetype_id'],
                                                    result['resource_name']])
        # add attributes to root node
        stats['totalResultsReturned'] = limit or i
        stats['totalResultsAvailable'] = count or i
        for key, value in stats.iteritems():
            xml.set(key, str(value))
        request.setHeader('content-type', 'text/xml; charset=UTF-8')
        return toString(xml)
