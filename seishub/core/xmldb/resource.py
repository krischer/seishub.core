# -*- coding: utf-8 -*-

from seishub.core.core import implements
from seishub.core.db.orm import Serializable, Relation, db_property, \
    LazyAttribute
from seishub.core.exceptions import InvalidParameterError
from seishub.core.registry.package import ResourceTypeWrapper
from seishub.core.util.text import hash, validate_id
from seishub.core.util.xml import toUnicode, parseXMLDeclaration, \
    addXMLDeclaration
from seishub.core.util.xmlwrapper import IXmlDoc, XmlTreeDoc
from seishub.core.xmldb.defaults import resource_tab, document_tab, \
    document_meta_tab
from seishub.core.xmldb.interfaces import IResource, IXmlDocument, \
    IDocumentMeta


XML_DECLARATION_LENGTH = len(addXMLDeclaration(""))


class DocumentMeta(Serializable):
    """
    Every XML resource, here called XMLDocument, has an associated entry in the
    `document_meta_tab` table. It stores the metadata for the resource, that is
    all information that is not directly related to the file itself. Currently
    it stores the following fields (some optional) for every resource:

        * id: Unique id of the document in the `document` table.
        * size: Size of the resource in bytes.
        * last_modified: Time of creation/last modification.
        * hash: Hash of the actual resource.
        * owner_id: Unique id of the owner of the resource.
        * group_id: Unique id of the group of the resource.
        * permissions: Permissions of the file.
        * public: Boolean flag whether or not the resource is public.
    """
    implements(IDocumentMeta)

    db_table = document_meta_tab

    db_mapping = {
        "_id": "id",
        "size": "size",
        "last_modified": "last_modified",
        "hash": "hash",
        "owner_id": "owner_id",
        "group_id": "group_id",
        "permissions": "permissions",
        "public": "public"}

    def __init__(self, size=None, last_modified=None, hash=None, owner_id=None,
        group_id=None, permissions=None, public=None):
        """
        Very simple init just setting the attributes. The object relational
        mapping from SQLAlchemy takes care of the rest.
        """
        self.size = size
        self.last_modified = last_modified
        self.hash = hash
        self.owner_id = owner_id
        self.group_id = group_id
        # Set default permissions and public flag.
        if permissions is None:
            self.permissions = "600"
        else:
            self.permissions = permissions
        if public is None:
            self.public = False
        else:
            self.public = bool(public)


class XmlDocument(Serializable):
    """
    Auto-parsing XML resource.

    Given xml data gets validated and parsed on resource creation.

    Per Default, permissions will be set to "600", meaning the owner can read
    and write, group and others can do nothing. This is a safe default - if it
    turns out inconvenient, it should be changed.
    """
    implements(IXmlDocument)

    db_table = document_tab
    db_mapping = {"_id": "id",
                  "revision": "revision",
                  "data": LazyAttribute("data"),
                  "meta": Relation(DocumentMeta, "id", cascading_delete=True,
                                  lazy=False)}

    def __init__(self, data=None, revision=None, owner_id=None, group_id=None):
        self._xml_doc = None
        self.meta = DocumentMeta(owner_id=owner_id, group_id=group_id)
        self.data = data
        # self.datetime = None
        Serializable.__init__(self)

    def setData(self, data):
        """
        set data, convert to unicode and remove XML declaration
        """
        if not data or data == "":
            self._data = None
            return
        if not isinstance(data, unicode):
            raise TypeError("Data has to be unicode!")
        # encode "utf-8" to determine hash and size
        raw_data = data.encode("utf-8")
        self._data = data
        self.meta.size = len(raw_data) + XML_DECLARATION_LENGTH
        self.meta.hash = hash(raw_data)

    def getData(self):
        """Returns data as unicode object."""
        data = self._data
        assert not data or isinstance(data, unicode)
        return data

    data = db_property(getData, setData, 'Raw xml data as a string',
                       attr='_data')

    def getXml_doc(self):
        if not self._xml_doc:
            self._xml_doc = self._validateXml_data(self.data)
        return self._xml_doc

    def setXml_doc(self, xml_doc):
        if not IXmlDoc.providedBy(xml_doc):
            raise TypeError("%s is not an IXmlDoc" % str(xml_doc))
        self._xml_doc = xml_doc

    xml_doc = property(getXml_doc, setXml_doc, 'Parsed xml document (IXmlDoc)')

    def getMeta(self):
        return self._meta

    def setMeta(self, meta):
        if meta and not IDocumentMeta.providedBy(meta):
            raise TypeError("%s is not an IDocumentMeta" % str(meta))
        self._meta = meta

    meta = db_property(getMeta, setMeta, "Document metadata", attr='_meta')

    def getRevision(self):
        return self._revision

    def setRevision(self, revision):
        self._revision = revision

    revision = property(getRevision, setRevision, "Document revision")

    def _validateXml_data(self, value):
        return self._parseXml_data(value)

    def _parseXml_data(self, xml_data):
        # encode before handing it to parser:
        # xml_data = xml_data.encode("utf-8")
        return XmlTreeDoc(xml_data=xml_data, blocking=True)


class Resource(Serializable):

    implements(IResource)

    db_table = resource_tab
    db_mapping = {'_id':'id', # external id
                  'resourcetype':Relation(ResourceTypeWrapper,
                                          'resourcetype_id',
                                          lazy=False),
                  'name':'name',
                  'document':Relation(XmlDocument, 'resource_id',
                                      lazy=False, relation_type='to-many',
                                      cascading_delete=True),
                  }

    def __init__(self, resourcetype=ResourceTypeWrapper(), id=None,
                 document=None, name=None):
        self.document = document
        self._id = id
        self.resourcetype = resourcetype
        self.name = name

    def __str__(self):
        return "/%s/%s/%s" % (self.package.package_id,
                              self.resourcetype.resourcetype_id,
                              str(self.name))

    def getId(self):
        return self._getId()

    def setId(self, id):
        return self._setId(id)

    id = property(getId, setId, "Unique resource id (integer)")

    def getResourceType(self):
        return self._resourcetype

    def setResourceType(self, data):
        self._resourcetype = data

    resourcetype = db_property(getResourceType, setResourceType,
                               "Resource type", attr='_resourcetype')

    def getPackage(self):
        return self.resourcetype.package

    def setPackage(self, data):
        pass

    package = property(getPackage, setPackage, "Package")

    def getDocument(self):
        # return document as a list only if multiple revisions are present
        if len(self._document) == 1:
            return self._document[0]
        else:
            return self._document

    def setDocument(self, data):
        if not isinstance(data, list):
            data = [data]
        self._document = data

    document = db_property(getDocument, setDocument, "xml document",
                           attr='_document')

    def getName(self):
        if not self._name:
            return self.id
        return self._name

    def setName(self, data):
        try:
            data = validate_id(data)
        except ValueError:
            msg = "Invalid resource name: %s"
            raise InvalidParameterError(msg % str(data))
        self._name = data

    name = property(getName, setName, "Alphanumeric name (optional)")


def newXMLDocument(data, id=None, owner_id=None, group_id=None):
    """
    Returns a new XmlDocument object.

    Data will be converted to unicode and a possible XML declaration will be
    removed. Use this method whenever you wish to create a XmlDocument
    manually!

    :param owner_id: User id of the resource owner.
    :param group_id: Group id of the resource.
    """
    # check for data
    if len(data) == 0:
        raise InvalidParameterError("XML document is empty.")
    # convert data to unicode and remove XML declaration
    if isinstance(data, unicode):
        data, _ = parseXMLDeclaration(data, remove_decl=True)
    else:
        data, _ = toUnicode(data, remove_decl=True)
    return XmlDocument(data, id, owner_id=owner_id, group_id=group_id)
