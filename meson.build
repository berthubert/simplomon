project('simplomon', 'cpp', default_options : ['cpp_std=c++20'])

# sqlitedep = dependency('sqlite3', version : '>3')
thread_dep = dependency('threads')
json_dep = dependency('nlohmann_json')
fmt_dep = dependency('fmt', version: '>9', static: true)

curl_dep = dependency(
    'libcurl',
    version: '>=8.5',
    allow_fallback: true,
    default_options: [
        'tests=disabled',
        'bindlocal=disabled',
        'dict=disabled',
        'shuffle-dns=disabled',
        'doh=disabled',
        'file=disabled',
        'form-api=disabled',
        'ftp=disabled',
        'gopher=disabled',
        'imap=disabled',
        'ldap=disabled',
        'ldaps=disabled',
        'mime=disabled',
        'mqtt=disabled',
        'netrc=disabled',
        'pop3=disabled',
        'progress-meter=disabled',
        'psl=disabled',
        'sspi=disabled',
        'rtsp=disabled',
        'rtmp=disabled',
        'smb=disabled',
        'smtp=disabled',
        'socketpair=disabled',
        'telnet=disabled',
        'tftp=disabled',
        'tls-srp=disabled',
        'unixsockets=disabled',
        'openssl=enabled',
        'brotli=disabled',
        'http2=enabled',
        'zstd=disabled',
        'ssl=enabled',
        'ntlm=disabled',
        'kerberos-auth=disabled',
        'aws=disabled',
        'idn=disabled',
        'gss-api=disabled',
        'ssh=disabled',
        'tool=disabled',
        'default_library=static',
    ],
)


lua_dep = dependency('lua-5.3', static: true)

cpphttplib = dependency('cpp-httplib')
# sqlitewriter_dep = dependency('sqlitewriter', static: true)
doctest_dep=dependency('doctest')
simplesockets_dep = dependency('simplesockets', static: true)
# argparse_dep = dependency('argparse', version: '>=3')

executable('simplomon', 'simplomon.cc', 'notifiers.cc', 'minicurl.cc', 'dnsmon.cc', 'record-types.cc', 'dnsmessages.cc', 'dns-storage.cc', 'netmon.cc', 'luabridge.cc',
	dependencies: [json_dep, fmt_dep, cpphttplib, 
	simplesockets_dep, lua_dep, curl_dep])



if host_machine.system() in ['freebsd']
  incdir = include_directories('/usr/local/include/doctest')
  executable('testrunner', 'testrunner.cc', 'notifiers.cc', 'minicurl.cc', 'dnsmon.cc', 'record-types.cc', 'dnsmessages.cc', 'dns-storage.cc', 'netmon.cc', 'luabridge.cc',
        dependencies: [doctest_dep, curl_dep, json_dep, fmt_dep, cpphttplib, simplesockets_dep, lua_dep],
        include_directories: incdir)
else
  executable('testrunner', 'testrunner.cc', 'notifiers.cc', 'minicurl.cc', 'dnsmon.cc', 'record-types.cc', 'dnsmessages.cc', 'dns-storage.cc', 'netmon.cc', 'luabridge.cc',
        dependencies: [doctest_dep, curl_dep, json_dep, fmt_dep, cpphttplib, simplesockets_dep, lua_dep])
endif

