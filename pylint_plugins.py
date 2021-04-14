#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

from __future__ import print_function

import copy
import os.path
import sys
import textwrap

from astroid import MANAGER, parse, register_module_extender
from astroid import scoped_nodes
from pylint.checkers import BaseChecker
from pylint.checkers.utils import check_messages
from pylint.interfaces import IAstroidChecker
from astroid.builder import AstroidBuilder


def register(linter):
    linter.register_checker(IPAChecker(linter))


def _warning_already_exists(cls, member):
    print(
        "WARNING: member '{member}' in '{cls}' already exists".format(
            cls="{}.{}".format(cls.root().name, cls.name), member=member),
        file=sys.stderr
    )


def fake_class(name_or_class_obj, members=()):
    if isinstance(name_or_class_obj, scoped_nodes.ClassDef):
        cl = name_or_class_obj
    else:
        cl = scoped_nodes.ClassDef(name_or_class_obj, None)

    for m in members:
        if isinstance(m, str):
            if m in cl.locals:
                _warning_already_exists(cl, m)
            else:
                cl.locals[m] = [scoped_nodes.ClassDef(m, None)]
        elif isinstance(m, dict):
            for key, val in m.items():
                assert isinstance(key, str), "key must be string"
                if key in cl.locals:
                    _warning_already_exists(cl, key)
                    fake_class(cl.locals[key], val)
                else:
                    cl.locals[key] = [fake_class(key, val)]
        else:
            # here can be used any astroid type
            if m.name in cl.locals:
                _warning_already_exists(cl, m.name)
            else:
                cl.locals[m.name] = [copy.copy(m)]
    return cl


# 'class': ['generated', 'properties']
ipa_class_members = {
    # Python standard library & 3rd party classes
    'socket._socketobject': ['sendall'],

    # IPA classes
    'ipalib.base.NameSpace': [
        'add',
        'mod',
        'del',
        'show',
        'find'
    ],
    'ipalib.cli.Collector': ['__options'],
    'ipalib.config.Env': [  # somehow needed for pylint on Python 2
        'debug',
        'startup_traceback',
        'server',
        'validate_api',
        'verbose',
    ],
    'ipalib.errors.ACIError': [
        'info',
    ],
    'ipalib.errors.ConversionError': [
        'error',
    ],
    'ipalib.errors.DatabaseError': [
        'desc',
    ],
    'ipalib.errors.NetworkError': [
        'error',
    ],
    'ipalib.errors.NotFound': [
        'reason',
    ],
    'ipalib.errors.PublicError': [
        'msg',
        'strerror',
        'kw',
    ],
    'ipalib.errors.SingleMatchExpected': [
        'found',
    ],
    'ipalib.errors.SkipPluginModule': [
        'reason',
    ],
    'ipalib.errors.ValidationError': [
        'error',
    ],
    'ipalib.errors.SchemaUpToDate': [
        'fingerprint',
        'ttl',
    ],
    'ipalib.messages.PublicMessage': [
        'msg',
        'strerror',
        'type',
        'kw',
    ],
    'ipalib.parameters.Param': [
        'cli_name',
        'cli_short_name',
        'label',
        'default',
        'doc',
        'required',
        'multivalue',
        'primary_key',
        'normalizer',
        'default_from',
        'autofill',
        'query',
        'attribute',
        'include',
        'exclude',
        'flags',
        'hint',
        'alwaysask',
        'sortorder',
        'option_group',
        'no_convert',
        'deprecated',
     ],
    'ipalib.parameters.Bool': [
        'truths',
        'falsehoods'],
    'ipalib.parameters.Data': [
        'minlength',
        'maxlength',
        'length',
        'pattern',
        'pattern_errmsg',
    ],
    'ipalib.parameters.Str': ['noextrawhitespace'],
    'ipalib.parameters.Password': ['confirm'],
    'ipalib.parameters.File': ['stdin_if_missing'],
    'ipalib.parameters.Enum': ['values'],
    'ipalib.parameters.Number': [
        'minvalue',
        'maxvalue',
    ],
    'ipalib.parameters.Decimal': [
        'precision',
        'exponential',
        'numberclass',
    ],
    'ipalib.parameters.DNSNameParam': [
        'only_absolute',
        'only_relative',
    ],
    'ipalib.parameters.Principal': [
        'require_service',
    ],
    'ipalib.plugable.API': [
        'Advice',
    ],
    'ipalib.util.ForwarderValidationError': [
        'msg',
    ],
    'ipaserver.plugins.dns.DNSRecord': [
        'validatedns',
        'normalizedns',
    ],
}


def transform_ipa_classes(node):
    fake_class(node, ipa_class_members[node.qname()])


MANAGER.register_transform(
    scoped_nodes.ClassDef,
    transform_ipa_classes,
    lambda node: node.qname() in ipa_class_members,
)


def transform_integrationtest(node):
    module = parse(
        """
    from ipatests.pytest_ipa.integration.host import Host, WinHost
    from ipatests.pytest_ipa.integration.config import Config, Domain

    class PylintIPAHosts:
        def __getitem__(self, key):
            return Host()

    class PylintWinHosts:
        def __getitem__(self, key):
            return WinHost()

    class PylintADDomains:
        def __getitem__(self, key):
            return Domain()

    domain = Domain()
    master = Host()
    replicas = PylintIPAHosts()
    clients = PylintIPAHosts()
    ads = PylintWinHosts()
    ad_treedomains = PylintWinHosts()
    ad_subdomains = PylintWinHosts()
    ad_domains = PylintADDomains()
    """
    )
    node.locals["domain"] = module.locals["domain"]
    node.locals["master"] = module.locals["master"]
    node.locals["replicas"] = module.locals["replicas"]
    node.locals["clients"] = module.locals["clients"]
    node.locals["ads"] = module.locals["ads"]
    node.locals["ad_treedomains"] = module.locals["ad_treedomains"]
    node.locals["ad_subdomains"] = module.locals["ad_subdomains"]
    node.locals["ad_domains"] = module.locals["ad_domains"]


MANAGER.register_transform(
    scoped_nodes.ClassDef,
    transform_integrationtest,
    lambda node: node.qname() == (
        "ipatests.test_integration.base.IntegrationTest"
    ),
)


def ipaplatform_constants_transform():
    return AstroidBuilder(MANAGER).string_build(textwrap.dedent('''
    from ipaplatform.base.constants import constants, User, Group
    __all__ = ('constants', 'User', 'Group')
    '''))


def ipaplatform_paths_transform():
    return AstroidBuilder(MANAGER).string_build(textwrap.dedent('''
    from ipaplatform.base.paths import paths
    __all__ = ('paths',)
    '''))


def ipaplatform_services_transform():
    return AstroidBuilder(MANAGER).string_build(textwrap.dedent('''
    from ipaplatform.base.services import knownservices
    from ipaplatform.base.services import timedate_services
    from ipaplatform.base.services import service
    from ipaplatform.base.services import wellknownservices
    from ipaplatform.base.services import wellknownports
    __all__ = ('knownservices', 'timedate_services', 'service',
               'wellknownservices', 'wellknownports')
    '''))


def ipaplatform_tasks_transform():
    return AstroidBuilder(MANAGER).string_build(textwrap.dedent('''
    from ipaplatform.base.tasks import tasks
    __all__ = ('tasks',)
    '''))


register_module_extender(MANAGER, 'ipaplatform.constants',
                         ipaplatform_constants_transform)
register_module_extender(MANAGER, 'ipaplatform.paths',
                         ipaplatform_paths_transform)
register_module_extender(MANAGER, 'ipaplatform.services',
                         ipaplatform_services_transform)
register_module_extender(MANAGER, 'ipaplatform.tasks',
                         ipaplatform_tasks_transform)


def ipalib_request_transform():
    """ipalib.request.context attribute
    """
    return AstroidBuilder(MANAGER).string_build(textwrap.dedent('''
    from ipalib.request import context
    context._pylint_attr = Connection("_pylint", lambda: None)
    '''))


register_module_extender(MANAGER, 'ipalib.request', ipalib_request_transform)


class IPAChecker(BaseChecker):
    __implements__ = IAstroidChecker

    name = 'ipa'
    msgs = {
        'W9901': (
            'Forbidden import %s (can\'t import from %s in %s)',
            'ipa-forbidden-import',
            'Used when an forbidden import is detected.',
        ),
    }
    options = (
        (
            'forbidden-imports',
            {
                'default': '',
                'type': 'csv',
                'metavar': '<path>[:<module>[:<module>...]][,<path>...]',
                'help': 'Modules which are forbidden to be imported in the '
                        'given paths',
            },
        ),
    )
    priority = -1

    def open(self):
        self._dir = os.path.abspath(os.path.dirname(__file__))

        self._forbidden_imports = {self._dir: []}
        for forbidden_import in self.config.forbidden_imports:
            forbidden_import = forbidden_import.split(':')
            path = os.path.join(self._dir, forbidden_import[0])
            path = os.path.abspath(path)
            modules = forbidden_import[1:]
            self._forbidden_imports[path] = modules

        self._forbidden_imports_stack = []

    def _get_forbidden_import_rule(self, node):
        path = node.path
        if path and isinstance(path, list):
            # In pylint 2.0, path is a list with one element. Namespace
            # packages may contain more than one element, but we can safely
            # ignore them, as they don't contain code.
            path = path[0]
        if path:
            path = os.path.abspath(path)
            while path.startswith(self._dir):
                if path in self._forbidden_imports:
                    return path
                path = os.path.dirname(path)
        return self._dir

    def visit_module(self, node):
        self._forbidden_imports_stack.append(
            self._get_forbidden_import_rule(node))

    def leave_module(self, node):
        self._forbidden_imports_stack.pop()

    def _check_forbidden_imports(self, node, names):
        path = self._forbidden_imports_stack[-1]
        relpath = os.path.relpath(path, self._dir)
        modules = self._forbidden_imports[path]
        for module in modules:
            module_prefix = module + '.'
            for name in names:
                if name == module or name.startswith(module_prefix):
                    self.add_message('ipa-forbidden-import',
                                     args=(name, module, relpath), node=node)

    @check_messages('ipa-forbidden-import')
    def visit_import(self, node):
        names = [n[0] for n in node.names]
        self._check_forbidden_imports(node, names)

    @check_messages('ipa-forbidden-import')
    def visit_importfrom(self, node):
        names = ['{}.{}'.format(node.modname, n[0]) for n in node.names]
        self._check_forbidden_imports(node, names)


#
# Teach pylint how api object works
#
# ipalib uses some tricks to create api.env members and api objects. pylint
# is not able to infer member names and types from code. The explict
# assignments inside the string builder templates are good enough to show
# pylint, how the api is created. Additional transformations are not
# required.
#

AstroidBuilder(MANAGER).string_build(textwrap.dedent(
    """
    from ipalib import api
    from ipalib import cli, plugable, rpc
    from ipalib.base import NameSpace
    from ipaclient.plugins import rpcclient
    try:
        from ipaserver.plugins import dogtag, ldap2, serverroles
    except ImportError:
        HAS_SERVER = False
    else:
        HAS_SERVER = True

    def wildcard(*args, **kwargs):
        return None

    # ipalib.api members
    api.Backend = plugable.APINameSpace(api, None)
    api.Command = plugable.APINameSpace(api, None)
    api.Method = plugable.APINameSpace(api, None)
    api.Object = plugable.APINameSpace(api, None)
    api.Updater = plugable.APINameSpace(api, None)
    # ipalib.api.Backend members
    api.Backend.cli = cli.cli(api)
    api.Backend.textui = cli.textui(api)
    api.Backend.jsonclient = rpc.jsonclient(api)
    api.Backend.rpcclient = rpcclient.rpcclient(api)
    api.Backend.xmlclient = rpc.xmlclient(api)

    if HAS_SERVER:
        api.Backend.kra = dogtag.kra(api)
        api.Backend.ldap2 = ldap2.ldap2(api)
        api.Backend.ra = dogtag.ra(api)
        api.Backend.ra_certprofile = dogtag.ra_certprofile(api)
        api.Backend.ra_lightweight_ca = dogtag.ra_lightweight_ca(api)
        api.Backend.serverroles = serverroles.serverroles(api)

    # ipalib.base.NameSpace
    NameSpace.find = wildcard
    """
))


AstroidBuilder(MANAGER).string_build(textwrap.dedent(
    """
    from ipalib import api
    from ipapython.dn import DN

    api.env.api_version = ''
    api.env.bin = ''  # object
    api.env.ca_agent_port = 0
    api.env.ca_host = ''
    api.env.ca_install_port = None
    api.env.ca_port = 0
    api.env.certmonger_wait_timeout = 0
    api.env.conf = ''  # object
    api.env.conf_default = ''  # object
    api.env.confdir = ''  # object
    api.env.container_accounts = DN()
    api.env.container_adtrusts = DN()
    api.env.container_applications = DN()
    api.env.container_automember = DN()
    api.env.container_automount = DN()
    api.env.container_ca = DN()
    api.env.container_ca_renewal = DN()
    api.env.container_caacl = DN()
    api.env.container_certmap = DN()
    api.env.container_certmaprules = DN()
    api.env.container_certprofile = DN()
    api.env.container_cifsdomains = DN()
    api.env.container_configs = DN()
    api.env.container_custodia = DN()
    api.env.container_deleteuser = DN()
    api.env.container_dna = DN()
    api.env.container_dna_posix_ids = DN()
    api.env.container_dns = DN()
    api.env.container_dnsservers = DN()
    api.env.container_group = DN()
    api.env.container_hbac = DN()
    api.env.container_hbacservice = DN()
    api.env.container_hbacservicegroup = DN()
    api.env.container_host = DN()
    api.env.container_hostgroup = DN()
    api.env.container_locations = DN()
    api.env.container_masters = DN()
    api.env.container_netgroup = DN()
    api.env.container_otp = DN()
    api.env.container_permission = DN()
    api.env.container_policies = DN()
    api.env.container_policygroups = DN()
    api.env.container_policylinks = DN()
    api.env.container_privilege = DN()
    api.env.container_radiusproxy = DN()
    api.env.container_ranges = DN()
    api.env.container_realm_domains = DN()
    api.env.container_rolegroup = DN()
    api.env.container_roles = DN()
    api.env.container_s4u2proxy = DN()
    api.env.container_selinux = DN()
    api.env.container_service = DN()
    api.env.container_stageuser = DN()
    api.env.container_sudocmd = DN()
    api.env.container_sudocmdgroup = DN()
    api.env.container_sudorule = DN()
    api.env.container_sysaccounts = DN()
    api.env.container_topology = DN()
    api.env.container_trusts = DN()
    api.env.container_user = DN()
    api.env.container_vault = DN()
    api.env.container_views = DN()
    api.env.container_virtual = DN()
    api.env.context = ''  # object
    api.env.debug = False
    api.env.delegate = False
    api.env.dogtag_version = 0
    api.env.dot_ipa = ''  # object
    api.env.enable_ra = False
    api.env.env_confdir = None
    api.env.fallback = True
    api.env.force_schema_check = False
    api.env.home = ''  # object
    api.env.host = ''
    api.env.host_princ = ''
    api.env.http_timeout = 0
    api.env.in_server = False  # object
    api.env.in_tree = False  # object
    api.env.interactive = True
    api.env.ipalib = ''  # object
    api.env.kinit_lifetime = None
    api.env.lite_pem = ''
    api.env.lite_profiler = ''
    api.env.lite_host = ''
    api.env.lite_port = 0
    api.env.log = ''  # object
    api.env.logdir = ''  # object
    api.env.mode = ''
    api.env.mount_ipa = ''
    api.env.nss_dir = ''  # object
    api.env.plugins_on_demand = False  # object
    api.env.prompt_all = False
    api.env.ra_plugin = ''
    api.env.recommended_max_agmts = 0
    api.env.replication_wait_timeout = 0
    api.env.rpc_protocol = ''
    api.env.server = ''
    api.env.script = ''  # object
    api.env.site_packages = ''  # object
    api.env.skip_version_check = False
    api.env.smb_princ = ''
    api.env.startup_timeout = 0
    api.env.startup_traceback = False
    api.env.tls_ca_cert = ''  # object
    api.env.tls_version_max = ''
    api.env.tls_version_min = ''
    api.env.validate_api = False
    api.env.verbose = 0
    api.env.version = ''
    api.env.wait_for_dns = 0
    api.env.webui_prod = True
    """
))

# dnspython 2.x introduces enums and creates module level globals from them
# pylint does not understand the trick
AstroidBuilder(MANAGER).string_build(textwrap.dedent(
    """
    import dns.flags
    import dns.rdataclass
    import dns.rdatatype

    dns.flags.AD = 0
    dns.flags.CD = 0
    dns.flags.DO = 0
    dns.flags.RD = 0

    dns.rdataclass.IN = 0

    dns.rdatatype.A = 0
    dns.rdatatype.AAAA = 0
    dns.rdatatype.CNAME = 0
    dns.rdatatype.DNSKEY = 0
    dns.rdatatype.MX = 0
    dns.rdatatype.NS = 0
    dns.rdatatype.PTR = 0
    dns.rdatatype.RRSIG = 0
    dns.rdatatype.SOA = 0
    dns.rdatatype.SRV = 0
    dns.rdatatype.TXT = 0
    dns.rdatatype.URI = 0
    """
))

AstroidBuilder(MANAGER).string_build(
    textwrap.dedent(
        """\
    from ipatests.pytest_ipa.integration.host_namespaces import (
        HostPlatformPaths
    )

    HostPlatformPaths.BIN_CURL=""
    HostPlatformPaths.CA_CRT=""
    HostPlatformPaths.CA_CS_CFG_PATH=""
    HostPlatformPaths.CERTMONGER_REQUESTS_DIR=""
    HostPlatformPaths.CERTUTIL=""
    HostPlatformPaths.CHRONY_CONF=""
    HostPlatformPaths.CRYPTO_POLICY_OPENSSLCNF_FILE=""
    HostPlatformPaths.DNSSEC_TRUSTED_KEY=""
    HostPlatformPaths.DOGTAG_ADMIN_P12=""
    HostPlatformPaths.DOGTAG_IPA_CA_RENEW_AGENT_SUBMIT=""
    HostPlatformPaths.DSCTL=""
    HostPlatformPaths.ETC_DIRSRV_SLAPD_INSTANCE_TEMPLATE=""
    HostPlatformPaths.GETENFORCE=""
    HostPlatformPaths.HOSTS=""
    HostPlatformPaths.HTTP_KEYTAB=""
    HostPlatformPaths.HTTPD_CERT_FILE=""
    HostPlatformPaths.HTTPD_IPA_CONF=""
    HostPlatformPaths.HTTPD_KEY_FILE=""
    HostPlatformPaths.HTTPD_PASSWD_FILE_FMT=""
    HostPlatformPaths.HTTPD_SSL_CONF=""
    HostPlatformPaths.IPA_CA_CRT=""
    HostPlatformPaths.IPA_CA_CSR=""
    HostPlatformPaths.IPA_CACERT_MANAGE=""
    HostPlatformPaths.IPA_CCACHES=""
    HostPlatformPaths.IPA_CERTUPDATE=""
    HostPlatformPaths.IPA_CLIENT_SYSRESTORE=""
    HostPlatformPaths.IPA_CUSTODIA_CHECK=""
    HostPlatformPaths.IPA_CUSTODIA_CONF=""
    HostPlatformPaths.IPA_CUSTODIA_KEYS=""
    HostPlatformPaths.IPA_GETCERT=""
    HostPlatformPaths.IPA_NSSDB_PWDFILE_TXT=""
    HostPlatformPaths.IPA_NSSDB_DIR=""
    HostPlatformPaths.IPACLIENT_INSTALL_LOG=""
    HostPlatformPaths.IPACLIENT_UNINSTALL_LOG=""
    HostPlatformPaths.IPASERVER_INSTALL_LOG=""
    HostPlatformPaths.KDC_CERT=""
    HostPlatformPaths.KDCPROXY_CONFIG=""
    HostPlatformPaths.KRB5_CONF=""
    HostPlatformPaths.KRB5_KEYTAB=""
    HostPlatformPaths.LDAPPASSWD=""
    HostPlatformPaths.LIBEXEC_IPA_DIR=""
    HostPlatformPaths.NAMED_CONF=""
    HostPlatformPaths.NAMED_CUSTOM_CONF=""
    HostPlatformPaths.NAMED_CUSTOM_OPTIONS_CONF=""
    HostPlatformPaths.NAMED_CRYPTO_POLICY_FILE=""
    HostPlatformPaths.NAMED_LOGGING_OPTIONS_CONF=""
    HostPlatformPaths.NSS_DB_DIR=""
    HostPlatformPaths.OPENLDAP_LDAP_CONF=""
    HostPlatformPaths.OPENSSL=""
    HostPlatformPaths.OPENSSL_CERTS_DIR=""
    HostPlatformPaths.OPENSSL_DIR=""
    HostPlatformPaths.OPENSSL_PRIVATE_DIR=""
    HostPlatformPaths.PKI_CA_PUBLISH_DIR=""
    HostPlatformPaths.PKI_TOMCAT_ALIAS_DIR=""
    HostPlatformPaths.PKI_TOMCAT_ALIAS_PWDFILE_TXT=""
    HostPlatformPaths.RA_AGENT_PEM=""
    HostPlatformPaths.RESOLV_CONF=""
    HostPlatformPaths.ROOT_IPA_CSR=""
    HostPlatformPaths.SAMBA_KEYTAB=""
    HostPlatformPaths.SELINUXENABLED=""
    HostPlatformPaths.SEMODULE=""
    HostPlatformPaths.SMB_CONF=""
    HostPlatformPaths.SSS_SSH_AUTHORIZEDKEYS=""
    HostPlatformPaths.SSSD_CONF=""
    HostPlatformPaths.SYSRESTORE=""
    HostPlatformPaths.SYSUPGRADE_STATEFILE_DIR=""
    HostPlatformPaths.SYSUPGRADE_STATEFILE_FILE=""
    HostPlatformPaths.TMP=""
    HostPlatformPaths.VAR_LIB_PKI_TOMCAT_DIR=""
    HostPlatformPaths.VAR_LIB_SLAPD_INSTANCE_DIR_TEMPLATE=""
    HostPlatformPaths.VAR_LOG_HTTPD_ERROR=""
    HostPlatformPaths.VAR_LOG_DIRSRV_INSTANCE_TEMPLATE=""
    HostPlatformPaths.VAR_LOG_SSSD_DIR=""
    """
    )
)

AstroidBuilder(MANAGER).string_build(
    textwrap.dedent(
        """\
    from ipatests.pytest_ipa.integration.host_namespaces import (
        HostPlatformOSInfo
    )
    HostPlatformOSInfo.name = ""
    HostPlatformOSInfo.platform = ""
    HostPlatformOSInfo.id = ""
    HostPlatformOSInfo.id_like = list()
    HostPlatformOSInfo.version = ""
    HostPlatformOSInfo.version_number = list()
    HostPlatformOSInfo.platform_ids = list()
    HostPlatformOSInfo.container = ""
    """
    )
)

AstroidBuilder(MANAGER).string_build(
    textwrap.dedent(
        """\
    from ipatests.pytest_ipa.integration.host_namespaces import (
        HostPlatformConstants
    )
    HostPlatformConstants.HTTPD_USER = ""
    HostPlatformConstants.IPAAPI_USER = ""
    HostPlatformConstants.DEFAULT_SHELL = ""
    HostPlatformConstants.DEFAULT_ADMIN_SHELL = ""
    HostPlatformConstants.WSGI_PROCESSES = 0
    HostPlatformConstants.DS_USER = ""
    HostPlatformConstants.DS_GROUP = ""
    HostPlatformConstants.SELINUX_USERMAP_ORDER = ""
    """
    )
)
