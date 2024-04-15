project('simplomon', 'cpp', default_options : ['cpp_std=c++20'])

sqlite_dep = dependency('sqlite3', version : '>3')
thread_dep = dependency('threads')
json_dep = dependency('nlohmann_json')
fmt_dep = dependency('fmt', version: '>9', static: true)
openssl_dep = dependency('openssl', version : '>=3.0.0')

curl_dep = dependency(
    'libcurl',
    version: '>=8.5',
    allow_fallback: true,
    default_options: [
        'tests=disabled',
        'bindlocal=enabled',
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

foreach name : ['lua-5.3', 'lua53']
    lua_dep = dependency(name, version: '>=5.3', required: false, static: true)
    if lua_dep.found()
        break
    endif
endforeach
if not lua_dep.found()
    error('Lua 5.3 could not be found')
endif

cpphttplib = dependency('cpp-httplib')
sqlitewriter_dep = dependency('sqlitewriter', static: true)
doctest_dep=dependency('doctest')
simplesockets_dep = dependency('simplesockets', static: true)
# argparse_dep = dependency('argparse', version: '>=3')

prog_xxd = find_program('xxd')

index_html_h = custom_target(
    'index_html.h', output : 'index_html.h',  input : 'html/index.html',  
    command : [prog_xxd, '-i', '@INPUT@', '@OUTPUT@'],
)

style_css_h = custom_target(
    'style_css.h', output : 'style_css.h',  input : 'html/style.css',  
    command : [prog_xxd, '-i', '@INPUT@', '@OUTPUT@'],
)

simplomon_ico_h = custom_target(
    'simplomon_ico.h', output : 'simplomon_ico.h',  input : 'html/simplomon.ico',  
    command : [prog_xxd, '-i', '@INPUT@', '@OUTPUT@'],
)

alpine_min_js_h = custom_target(
    'alpine_min_js.h', output : 'alpine_min_js.h',  input : 'html/alpine.min.js',  
    command : [prog_xxd, '-i', '@INPUT@', '@OUTPUT@'],
)

logic_js_h = custom_target(
    'logic_js.h', output : 'logic_js.h',  input : 'html/logic.js',  
    command : [prog_xxd, '-i', '@INPUT@', '@OUTPUT@'],
)


webpages = [logic_js_h, alpine_min_js_h, simplomon_ico_h, style_css_h, index_html_h]

executable('simplomon', 'simplomon.cc', 'notifiers.cc', 'minicurl.cc', 'dnsmon.cc', 'record-types.cc', 'dnsmessages.cc', 'dns-storage.cc', 'netmon.cc', 'luabridge.cc', 'webservice.cc', 'support.cc', 'promon.cc', 'mailmon.cc', 'nonblocker.cc',
webpages,
	dependencies: [json_dep, fmt_dep, cpphttplib, openssl_dep,
	simplesockets_dep, lua_dep, curl_dep, sqlite_dep, sqlitewriter_dep])

executable('testrunner', 'testrunner.cc', 'notifiers.cc', 'minicurl.cc', 'dnsmon.cc', 'record-types.cc', 'dnsmessages.cc', 'dns-storage.cc', 'netmon.cc', 'luabridge.cc', 'webservice.cc', 'support.cc', 'promon.cc', 'mailmon.cc', 'nonblocker.cc', 
	dependencies: [doctest_dep, curl_dep, json_dep, fmt_dep, cpphttplib, sqlite_dep, openssl_dep,
	simplesockets_dep, lua_dep, sqlitewriter_dep])




